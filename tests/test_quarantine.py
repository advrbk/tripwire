"""Safe extraction of hostile archives.

These archives attack the *format* (paths, links, sizes, counts). Their file
contents are harmless filler, so nothing here resembles malware.
"""

import gzip
import hashlib
import base64
import io
import sys
import tarfile
import tracemalloc
import zipfile
from pathlib import Path

import pytest
from helpers import link_member, tar_with, zip_with

from tripwire.quarantine import (ExtractionError, Limits, archive_kind, ensure_not_on_import_path,
                                 new_quarantine_dir, remove_tree, safe_extract, sanitize_member_name, verify_digest)


def write(tmp_path: Path, data: bytes, name: str = "a.tar.gz") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def all_files(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}


# ---------------------------------------------------------------- member names

@pytest.mark.parametrize("name,reason", [
    ("../evil.txt", "path traversal"),
    ("pkg/../../evil.txt", "path traversal"),
    ("pkg\\..\\..\\evil.txt", "path traversal"),
    ("/etc/passwd", "absolute path"),
    ("\\\\server\\share\\x", "absolute path"),
    ("C:/Windows/x.txt", "absolute path"),
    ("c:x.txt", "absolute path"),
    ("pkg/file.txt:stream", "alternate data stream"),
    ("pkg/CON.txt", "reserved"),
    ("pkg/nul", "reserved"),
    ("pkg/lpt1.log", "reserved"),
    ("pkg/CONIN$", "reserved"),
    ("pkg/conout$.txt", "reserved"),
    ("pkg/COM¹", "reserved"),
    ("pkg/trailing. ", "trailing"),
    ("pkg/a<b>.txt", "not allowed"),
    ("pkg/a\x00b", "NUL"),
    ("", "empty"),
    ("./.", "empty path"),
])
def test_refused_names(name, reason):
    rel, why = sanitize_member_name(name, 200)
    assert rel is None and reason in why


@pytest.mark.parametrize("name,expected", [
    ("pkg/mod.py", "pkg/mod.py"), ("./pkg/./mod.py", "pkg/mod.py"), ("pkg\\sub\\m.py", "pkg/sub/m.py"),
    ("pkg//double.py", "pkg/double.py"), ("..data/file", "..data/file"),
])
def test_accepted_names(name, expected):
    assert sanitize_member_name(name, 200) == (expected, None)


def test_long_path_refused():
    rel, why = sanitize_member_name("a/" * 150 + "x.py", 200)
    assert rel is None and "too long" in why


# ---------------------------------------------------------------- tar attacks

def test_tar_traversal_is_blocked_and_nothing_escapes(tmp_path):
    arc = write(tmp_path, tar_with([("pkg/ok.py", b"x = 1\n"), ("../escaped.txt", b"filler"),
                                    ("pkg/../../escaped2.txt", b"filler")]))
    dest = tmp_path / "out"
    rep = safe_extract(arc, dest)
    assert rep.files == ["pkg/ok.py"]
    assert {r for _, r in rep.blocked} == {"path traversal (..)"}
    assert not (tmp_path / "escaped.txt").exists() and not (tmp_path / "escaped2.txt").exists()


def test_tar_absolute_path_is_blocked(tmp_path):
    rep = safe_extract(write(tmp_path, tar_with([("/tmp/abs.txt", b"filler")])), tmp_path / "out")
    assert rep.files == [] and rep.blocked[0][1] == "absolute path"


def test_tar_symlink_is_not_created(tmp_path):
    arc = write(tmp_path, tar_with([link_member("pkg/link", "/etc/passwd"), ("pkg/a.py", b"x=1\n")]))
    rep = safe_extract(arc, tmp_path / "out")
    assert ("pkg/link", "symlink") in rep.blocked
    assert not (tmp_path / "out" / "pkg" / "link").exists()


def test_tar_hardlink_is_not_created(tmp_path):
    arc = write(tmp_path, tar_with([("pkg/a.py", b"x=1\n"), link_member("pkg/hard", "pkg/a.py", hard=True)]))
    rep = safe_extract(arc, tmp_path / "out")
    assert ("pkg/hard", "hard link") in rep.blocked
    assert rep.files == ["pkg/a.py"]


def test_tar_symlink_then_write_through_it_stays_inside(tmp_path):
    # Classic two-step: a link to outside, then a file "through" the link.
    arc = write(tmp_path, tar_with([link_member("pkg/out", ".."), ("pkg/out/escaped.txt", b"filler")]))
    dest = tmp_path / "out"
    safe_extract(arc, dest)
    assert not (tmp_path / "escaped.txt").exists()
    assert all(p.resolve().is_relative_to(dest.resolve()) for p in dest.rglob("*"))


@pytest.mark.parametrize("kind", [tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE])
def test_tar_devices_are_blocked(tmp_path, kind):
    info = tarfile.TarInfo("pkg/dev")
    info.type = kind
    rep = safe_extract(write(tmp_path, tar_with([info])), tmp_path / "out")
    assert rep.blocked == [("pkg/dev", "device, FIFO or other special file")]


def test_tar_member_count_cap(tmp_path):
    arc = write(tmp_path, tar_with([(f"pkg/f{i}.txt", b"x") for i in range(30)]))
    with pytest.raises(ExtractionError, match="members"):
        safe_extract(arc, tmp_path / "out", Limits(max_members=10))


def test_tar_per_file_cap(tmp_path):
    arc = write(tmp_path, tar_with([("pkg/big.txt", b"a" * 5000)]))
    with pytest.raises(ExtractionError, match="file larger"):
        safe_extract(arc, tmp_path / "out", Limits(max_file_bytes=1000))


def test_tar_gzip_bomb_is_stopped_before_writing(tmp_path):
    # 20 MB of zeros compresses to ~20 KB. The declared size is checked up front.
    arc = write(tmp_path, tar_with([("pkg/zeros.bin", bytes(20 * 1024 * 1024))]))
    assert arc.stat().st_size < 100_000
    dest = tmp_path / "out"
    with pytest.raises(ExtractionError, match="declares more than"):
        safe_extract(arc, dest, Limits(max_total_bytes=5 * 1024 * 1024))
    assert all_files(dest) == set()


def test_tar_bomb_hidden_in_a_refused_member(tmp_path):
    # A refused (traversal) member must still count: skipping it means decompressing it.
    arc = write(tmp_path, tar_with([("../zeros.bin", bytes(8 * 1024 * 1024))]))
    with pytest.raises(ExtractionError):
        safe_extract(arc, tmp_path / "out", Limits(max_total_bytes=1024 * 1024))


def test_tar_total_bytes_counted_while_copying(tmp_path):
    arc = write(tmp_path, tar_with([(f"pkg/f{i}.txt", b"a" * 4000) for i in range(5)]))
    with pytest.raises(ExtractionError):
        safe_extract(arc, tmp_path / "out", Limits(max_total_bytes=10_000))


def test_uncompressed_and_bz2_tar(tmp_path):
    for mode, name in (("w", "a.tar"), ("w:bz2", "a.tar.bz2"), ("w:xz", "a.tar.xz")):
        arc = write(tmp_path, tar_with([("pkg/a.py", b"x=1\n")], mode=mode), name)
        assert safe_extract(arc, tmp_path / name.replace(".", "_")).files == ["pkg/a.py"]


def test_names_differing_only_in_case_are_both_kept(tmp_path):
    # On Linux these are two files and pip runs the lower-case one. Keeping only
    # the first would let "Setup.py" (benign) hide "setup.py" (the one that runs).
    arc = write(tmp_path, tar_with([("pkg/Mod.py", b"a=1\n"), ("pkg/mod.py", b"b=2\n")]))
    rep = safe_extract(arc, tmp_path / "out")
    assert rep.files == ["pkg/Mod.py", "pkg/mod.py"] and rep.blocked == []
    assert rep.path_of("pkg/Mod.py").read_bytes() == b"a=1\n"
    assert rep.path_of("pkg/mod.py").read_bytes() == b"b=2\n"
    assert rep.collisions and rep.collisions[0][0] == "pkg/mod.py"
    # the second copy lives outside the extraction folder, never inside it
    assert not rep.path_of("pkg/mod.py").is_relative_to((tmp_path / "out").resolve())


@pytest.mark.filterwarnings("ignore:Duplicate name")  # zipfile warns while building the test archive
@pytest.mark.parametrize("builder,name", [(tar_with, "a.tar.gz"), (zip_with, "a.zip")])
def test_exact_duplicate_keeps_the_later_copy(tmp_path, builder, name):
    # tar, npm and pip all let the later entry overwrite the earlier one, so the
    # later one is what runs and what must be analysed.
    arc = write(tmp_path, builder([("pkg/a.py", b"first\n"), ("pkg/a.py", b"second\n")]), name)
    rep = safe_extract(arc, tmp_path / "out")
    assert rep.files == ["pkg/a.py"] and rep.path_of("pkg/a.py").read_bytes() == b"second\n"
    assert rep.collisions == [("pkg/a.py", "duplicate entry; the later copy replaced the earlier one")]


def _short_names_enabled(folder: Path) -> bool:
    probe = folder / "shortname_probe_file.txt"
    probe.write_bytes(b"")
    try:
        return (folder / "SHORTN~1.TXT").exists()
    finally:
        probe.unlink()


def test_8dot3_short_name_alias_does_not_overwrite(tmp_path):
    # On NTFS with 8.3 names on, "INSTAL~1.JS" opens the file "install_script.js".
    # Writing it used to replace the real file's contents before analysis.
    if not _short_names_enabled(tmp_path):
        pytest.skip("this file system does not generate 8.3 short names")
    arc = write(tmp_path, tar_with([("package/install_script.js", b"real\n"),
                                    ("package/INSTAL~1.JS", b"decoy\n")]))
    rep = safe_extract(arc, tmp_path / "out")
    assert sorted(rep.files) == ["package/INSTAL~1.JS", "package/install_script.js"]
    assert rep.path_of("package/install_script.js").read_bytes() == b"real\n"
    assert rep.path_of("package/INSTAL~1.JS").read_bytes() == b"decoy\n"
    assert rep.collisions


def _gnu_longname_tar(name_bytes: int, count: int = 1) -> bytes:
    """A gzip tar whose GNU long-name header(s) declare ``name_bytes`` of name data."""
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9) as gz:
        for _ in range(count):
            head = tarfile.TarInfo("././@LongLink")
            head.size = name_bytes
            head.type = tarfile.GNUTYPE_LONGNAME
            gz.write(head.tobuf(format=tarfile.GNU_FORMAT))
            left = name_bytes
            while left:
                n = min(left, 1 << 20)
                gz.write(b"a" * n)
                left -= n
            gz.write(b"\0" * (-name_bytes % 512))
            body = tarfile.TarInfo("x.txt")
            gz.write(body.tobuf(format=tarfile.GNU_FORMAT))
        gz.write(b"\0" * 1024)
    return raw.getvalue()


def test_tar_long_name_header_bomb_is_refused_without_reading_it(tmp_path):
    # tarfile reads a GNU long-name header into memory in one call before the
    # member is ever yielded, so the per-member checks never got a say: a 64 KB
    # .tar.gz made it allocate 64 MB (and a 25 MB one, gigabytes).
    arc = write(tmp_path, _gnu_longname_tar(64 * 1024 * 1024))
    assert arc.stat().st_size < 200_000
    tracemalloc.start()
    try:
        with pytest.raises(ExtractionError, match="larger than any real package"):
            safe_extract(arc, tmp_path / "out")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 8 * 1024 * 1024


def test_tar_pax_header_bomb_is_refused(tmp_path):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("pkg/a.txt")
        info.pax_headers = {"comment": "a" * (3 * 1024 * 1024)}
        tf.addfile(info, io.BytesIO(b""))
    with pytest.raises(ExtractionError):
        safe_extract(write(tmp_path, raw.getvalue()), tmp_path / "out")


def test_tar_stream_cap_counts_header_data(tmp_path):
    # Many medium long-name headers: each read is allowed, the stream total is not.
    arc = write(tmp_path, _gnu_longname_tar(900 * 1024, count=4))
    with pytest.raises(ExtractionError, match="tar stream expands past"):
        safe_extract(arc, tmp_path / "out", Limits(max_total_bytes=1024, max_members=10))


def test_ordinary_pax_and_long_names_still_work(tmp_path):
    long_name = "pkg/" + "d" * 120 + "/mod.py"
    for fmt in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz", format=fmt) as tf:
            data = b"x = 1\n"
            info = tarfile.TarInfo(long_name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        rep = safe_extract(write(tmp_path, raw.getvalue(), f"f{fmt}.tar.gz"), tmp_path / f"out{fmt}")
        assert rep.files == [long_name]


def test_corrupt_xz_tar_and_lzma_zip_member_are_extraction_errors(tmp_path):
    # LZMAError is not an OSError; it used to escape from the zip reader uncaught.
    plain = bytes(range(256)) * 2000
    xz = bytearray(tar_with([("pkg/a.bin", plain)], mode="w:xz"))
    for i in range(200, len(xz) - 100, 7):
        xz[i] ^= 0x55
    with pytest.raises(ExtractionError):
        safe_extract(write(tmp_path, bytes(xz), "bad.tar.xz"), tmp_path / "o1")
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w", zipfile.ZIP_LZMA) as zf:
        zf.writestr("pkg/a.txt", plain)
    zdata = bytearray(zb.getvalue())
    start = zdata.find(b"pkg/a.txt") + len("pkg/a.txt") + 20
    for i in range(start, start + 200):
        zdata[i] ^= 0x55
    with pytest.raises(ExtractionError):
        safe_extract(write(tmp_path, bytes(zdata), "bad.zip"), tmp_path / "o2")


def test_file_and_directory_collision(tmp_path):
    arc = write(tmp_path, tar_with([("pkg/a", b"file\n"), ("pkg/a/b.txt", b"x\n")]))
    rep = safe_extract(arc, tmp_path / "out")
    assert ("pkg/a/b.txt", "directory collides with a file") in rep.blocked


# ---------------------------------------------------------------- zip attacks

def test_zip_traversal_and_absolute(tmp_path):
    arc = write(tmp_path, zip_with([("pkg/ok.py", b"x=1\n"), ("../evil.txt", b"f"), ("/abs.txt", b"f"),
                                    ("C:\\Windows\\x.txt", b"f")]), "a.zip")
    rep = safe_extract(arc, tmp_path / "out")
    assert rep.files == ["pkg/ok.py"] and len(rep.blocked) == 3
    assert not (tmp_path / "evil.txt").exists()


def test_zip_symlink_is_blocked(tmp_path):
    info = zipfile.ZipInfo("pkg/link")
    info.external_attr = (0o120777 << 16)
    rep = safe_extract(write(tmp_path, zip_with([(info, b"/etc/passwd")]), "a.zip"), tmp_path / "out")
    assert rep.blocked == [("pkg/link", "symlink")] and rep.files == []


def test_zip_encrypted_member_is_skipped(tmp_path):
    # zipfile clears flag bits when writing, so set the "encrypted" bit in the bytes.
    data = bytearray(zip_with([("pkg/secret.py", b"x"), ("pkg/ok.py", b"y")]))
    data[6] |= 0x1                                  # local header of the first member
    cd = data.find(b"PK")
    data[cd + 8] |= 0x1                             # its central-directory entry
    rep = safe_extract(write(tmp_path, bytes(data), "a.zip"), tmp_path / "out")
    assert ("pkg/secret.py", "encrypted member") in rep.blocked and rep.files == ["pkg/ok.py"]


def test_zip_bomb_is_stopped(tmp_path):
    arc = write(tmp_path, zip_with([("pkg/zeros.bin", bytes(20 * 1024 * 1024))]), "bomb.zip")
    assert arc.stat().st_size < 100_000
    with pytest.raises(ExtractionError, match="decompression bomb"):
        safe_extract(arc, tmp_path / "out", Limits(max_total_bytes=2 * 1024 * 1024, max_file_bytes=50 * 1024 * 1024))


def test_zip_with_lying_size_header_is_not_trusted(tmp_path):
    # Rewrite the central-directory "uncompressed size" of a 3 MB member to 10 bytes.
    data = bytearray(zip_with([("pkg/zeros.bin", bytes(3 * 1024 * 1024))]))
    cd = data.rfind(b"PK\x01\x02")
    data[cd + 24:cd + 28] = (10).to_bytes(4, "little")
    lo = data.find(b"PK\x03\x04")
    data[lo + 22:lo + 26] = (10).to_bytes(4, "little")
    arc = write(tmp_path, bytes(data), "liar.zip")
    dest = tmp_path / "out"
    try:
        rep = safe_extract(arc, dest, Limits(max_total_bytes=1024 * 1024))
    except ExtractionError:
        return  # refused outright: fine
    # If it was accepted, no more than the budget reached the disk.
    assert sum((dest / f).stat().st_size for f in rep.files) <= 1024 * 1024


def test_zip_member_count_cap(tmp_path):
    arc = write(tmp_path, zip_with([(f"f{i}.txt", b"x") for i in range(30)]), "many.zip")
    with pytest.raises(ExtractionError, match="members"):
        safe_extract(arc, tmp_path / "out", Limits(max_members=10))


# ---------------------------------------------------------------- whole-archive checks

def test_archive_size_cap(tmp_path):
    arc = write(tmp_path, tar_with([("pkg/a.txt", b"x" * 1000)]))
    with pytest.raises(ExtractionError, match="limit is"):
        safe_extract(arc, tmp_path / "out", Limits(max_archive_bytes=10))


def test_unknown_format(tmp_path):
    with pytest.raises(ExtractionError, match="unsupported"):
        safe_extract(write(tmp_path, b"just some text, not an archive", "x.tar.gz"), tmp_path / "out")


def test_truncated_gzip(tmp_path):
    data = tar_with([("pkg/a.txt", bytes(range(256)) * 400)])
    with pytest.raises(ExtractionError):
        safe_extract(write(tmp_path, data[: len(data) // 2]), tmp_path / "out")


def test_garbage_after_gzip_magic(tmp_path):
    with pytest.raises(ExtractionError):
        safe_extract(write(tmp_path, b"\x1f\x8b" + b"\x00" * 300), tmp_path / "out")


def test_kind_is_detected_from_content_not_name(tmp_path):
    zip_named_tar = write(tmp_path, zip_with([("a.txt", b"x")]), "looks.tar.gz")
    assert archive_kind(zip_named_tar) == "zip"
    assert archive_kind(write(tmp_path, tar_with([("a", b"x")], mode="w"), "plain.zip")) == "tar"
    assert archive_kind(write(tmp_path, gzip.compress(b"x"), "g.gz")) == "tar"
    assert archive_kind(write(tmp_path, b"hello", "h.whl")) == "unknown"


# ---------------------------------------------------------------- digests and folders

def test_sha256_digest(tmp_path):
    p = write(tmp_path, b"payload", "f")
    good = hashlib.sha256(b"payload").hexdigest()
    assert verify_digest(p, sha256=good) and verify_digest(p, sha256=good.upper())
    assert not verify_digest(p, sha256="0" * 64)


def test_sri_sha512_digest(tmp_path):
    p = write(tmp_path, b"payload", "f")
    sri = "sha512-" + base64.b64encode(hashlib.sha512(b"payload").digest()).decode()
    assert verify_digest(p, integrity=sri)
    assert not verify_digest(p, integrity="sha512-" + base64.b64encode(b"\0" * 64).decode())


def test_no_digest_published_is_accepted(tmp_path):
    assert verify_digest(write(tmp_path, b"x", "f"))


def test_quarantine_dirs_are_fresh_and_removable(tmp_path):
    a, b = new_quarantine_dir(tmp_path), new_quarantine_dir(tmp_path)
    assert a != b and a.is_dir() and not any(a.iterdir())
    (a / "f").write_text("x")
    remove_tree(a)
    assert not a.exists()


def test_quarantine_must_not_be_importable(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "path", [str(tmp_path)] + sys.path)
    with pytest.raises(RuntimeError, match="sys.path"):
        ensure_not_on_import_path(tmp_path)


def test_quarantine_on_pythonpath_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(tmp_path.resolve()))
    with pytest.raises(RuntimeError, match="PYTHONPATH"):
        ensure_not_on_import_path(tmp_path)


def test_ordinary_folder_is_fine(tmp_path):
    ensure_not_on_import_path(tmp_path / "q")


def test_report_counts_bytes(tmp_path):
    rep = safe_extract(write(tmp_path, tar_with([("a.txt", b"12345"), ("b.txt", b"678")])), tmp_path / "o")
    assert rep.total_bytes == 8 and sorted(rep.files) == ["a.txt", "b.txt"]

