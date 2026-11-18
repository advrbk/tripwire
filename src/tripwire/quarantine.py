"""Safe handling of untrusted archives.

Rules this module enforces:

* Archives are only ever *read*. Nothing in here imports, builds, installs or
  runs anything that came out of an archive.
* ``extractall`` is never used. Each member is checked and copied by hand, so
  the extractor decides what reaches the disk, not the archive.
* Blocked: absolute paths, ``..`` segments, drive letters, Windows reserved
  names and alternate data streams, symlinks, hard links, devices and FIFOs.
* Limits: archive size, number of members, bytes per file and total bytes.
  Byte counts are measured while copying, never trusted from headers, so a
  zip bomb that lies about its sizes still gets stopped. For tar, the whole
  decompressed stream is capped too, because tarfile reads GNU long-name and
  pax headers into memory in one piece before we ever see the member.
* Name collisions never hide a file. An exact duplicate replaces the earlier
  copy (that is what tar, npm and pip do, so the last copy is the one that
  runs). A name that only collides on Windows or macOS (``Setup.py`` vs
  ``setup.py``, or an 8.3 short name such as ``INSTAL~1.JS``) is written to a
  side folder and analysed under its own name, so both copies are read.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import io
import lzma
import os
import re
import shutil
import tarfile
import uuid
import zipfile
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from zlib import error as zlibError  # raised for corrupt gzip/deflate streams

CHUNK = 64 * 1024

_WINDOWS_RESERVED = re.compile(
    r"^(con|prn|aux|nul|conin\$|conout\$|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])(\..*)?$",
    re.IGNORECASE)
_BAD_CHARS = re.compile(r'[<>"|?*\x00-\x1f]')


class ExtractionError(Exception):
    """The archive broke a hard limit; nothing from it should be analysed."""


@dataclass(frozen=True)
class Limits:
    max_archive_bytes: int = 25 * 1024 * 1024
    max_members: int = 5_000
    max_file_bytes: int = 20 * 1024 * 1024
    max_total_bytes: int = 150 * 1024 * 1024
    max_path_length: int = 200  # keeps the final path under Windows MAX_PATH


@dataclass
class ExtractReport:
    root: Path
    files: list[str] = field(default_factory=list)  # relative posix paths written
    blocked: list[tuple[str, str]] = field(default_factory=list)  # (member name, reason)
    total_bytes: int = 0
    # Files that could not live at root/<rel> because the name collided on this
    # file system: {relative posix path: where it was actually written}.
    disk_paths: dict[str, Path] = field(default_factory=dict)
    # Names that collided with an earlier member: (member name, what happened).
    collisions: list[tuple[str, str]] = field(default_factory=list)

    def path_of(self, rel: str) -> Path:
        return self.disk_paths.get(rel, self.root / rel)


def new_quarantine_dir(base: Path) -> Path:
    """A fresh, empty directory for one release."""
    d = base / uuid.uuid4().hex[:12]
    d.mkdir(parents=True, exist_ok=False)
    return d


def remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


def sanitize_member_name(name: str, max_len: int) -> tuple[str | None, str | None]:
    """Return (safe relative posix path, None) or (None, reason it was refused)."""
    if not name or "\x00" in name:
        return None, "empty or NUL in name"
    norm = name.replace("\\", "/")
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
        return None, "absolute path"
    parts = []
    for part in PurePosixPath(norm).parts:
        if part in ("", "."):
            continue
        if part == "..":
            return None, "path traversal (..)"
        if ":" in part:
            return None, "drive letter or alternate data stream"
        if _BAD_CHARS.search(part):
            # Windows cannot create these names; refuse the entry, not the archive.
            return None, "character not allowed in file names"
        if _WINDOWS_RESERVED.match(part):
            return None, "Windows reserved device name"
        if part != part.rstrip(" ."):
            return None, "trailing dot or space"
        parts.append(part)
    if not parts:
        return None, "empty path"
    rel = "/".join(parts)
    if len(rel) > max_len:
        return None, "path too long"
    return rel, None


class _Budget:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.total = 0

    def copy(self, src: io.BufferedIOBase, dst_path: Path) -> int:
        written = 0
        with open(dst_path, "wb") as dst:
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                self.total += len(chunk)
                if written > self.limits.max_file_bytes:
                    raise ExtractionError(f"file larger than {self.limits.max_file_bytes} bytes")
                if self.total > self.limits.max_total_bytes:
                    raise ExtractionError(
                        f"archive expands past {self.limits.max_total_bytes} bytes (decompression bomb?)"
                    )
                dst.write(chunk)
        return written


def _target(dest: Path, rel: str) -> Path:
    target = (dest / rel).resolve()
    if not target.is_relative_to(dest.resolve()):
        # Belt and braces: sanitize_member_name should already have caught this.
        raise ExtractionError(f"member escapes the quarantine folder: {rel}")
    return target


class _Writer:
    """Decides where each member goes, so that no member can hide another."""

    def __init__(self, dest: Path, budget: _Budget, report: ExtractReport):
        self.dest = dest
        self.budget = budget
        self.report = report
        self.where: dict[str, Path] = {}  # rel -> file on disk
        self.folded: set[str] = set()  # case-folded rels seen so far
        self.side = 0

    def write(self, rel: str, src) -> None:
        report = self.report
        if rel in self.where:
            # Exact duplicate. Every real extractor lets the later copy win, so
            # that is the one that would run: analyse it, not the earlier one.
            self.budget.copy(src, self.where[rel])
            report.collisions.append((rel, "duplicate entry; the later copy replaced the earlier one"))
            return
        target = _target(self.dest, rel)
        if rel.casefold() in self.folded or target.exists():
            # Same name on a case-insensitive file system, or an 8.3 short-name
            # alias (INSTAL~1.JS) of a file already written. Writing it here
            # would overwrite what is a separate file on Linux. Keep both.
            self._write_aside(rel, src)
            return
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except (FileExistsError, NotADirectoryError, FileNotFoundError):
            report.blocked.append((rel, "directory collides with a file"))
            return
        if target.exists():
            # A parent folder turned out to be an alias of an existing one.
            self._write_aside(rel, src)
            return
        self.folded.add(rel.casefold())
        self.where[rel] = target
        self.budget.copy(src, target)
        report.files.append(rel)

    def _write_aside(self, rel: str, src) -> None:
        self.side += 1
        target = self.dest.parent / f"{self.dest.name}.collisions" / str(self.side) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        self.where[rel] = target
        self.folded.add(rel.casefold())
        self.budget.copy(src, target)
        self.report.files.append(rel)
        self.report.disk_paths[rel] = target
        self.report.collisions.append(
            (rel, "name collides with another member on Windows/macOS; both copies analysed"))


class _CappedStream:
    """Read-only view of a decompressed tar stream that will not go past
    ``cap`` bytes and refuses any single read larger than ``max_read``.

    tarfile reads a GNU long-name or pax header into memory in one call, sized
    by the header itself, before it hands us the member. Without this cap a
    300 KB .tar.gz can make it allocate gigabytes.
    """

    def __init__(self, raw, cap: int, max_read: int):
        self._raw = raw
        self._cap = cap
        self._max_read = max_read

    def tell(self) -> int:
        return self._raw.tell()

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0 or n > self._max_read:
            raise ExtractionError("tar header or block larger than any real package needs")
        if self._raw.tell() + n > self._cap:
            raise ExtractionError(f"tar stream expands past {self._cap} bytes (decompression bomb?)")
        return self._raw.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        if whence != 0:
            raise io.UnsupportedOperation("only absolute seeks")
        if pos > self._cap:
            raise ExtractionError(f"tar stream expands past {self._cap} bytes (decompression bomb?)")
        return self._raw.seek(pos)

    def close(self) -> None:
        self._raw.close()


def _open_tar_stream(archive: Path, limits: Limits) -> _CappedStream:
    with open(archive, "rb") as fh:
        head = fh.read(6)
    if head.startswith(b"\x1f\x8b"):
        raw = gzip.open(archive, "rb")
    elif head.startswith(b"BZh"):
        raw = bz2.open(archive, "rb")
    elif head.startswith(b"\xfd7zXZ"):
        raw = lzma.open(archive, "rb")
    else:
        raw = open(archive, "rb")
    # Room for every allowed byte of file data plus generous header overhead
    # (a header block, padding and a long-name or pax block per member).
    cap = limits.max_total_bytes + limits.max_members * 4 * 512 + 1024 * 1024
    return _CappedStream(raw, cap, max_read=1024 * 1024)


def extract_tar(archive: Path, dest: Path, limits: Limits = Limits()) -> ExtractReport:
    report = ExtractReport(root=dest)
    budget = _Budget(limits)
    writer = _Writer(dest, budget, report)
    stream = _open_tar_stream(archive, limits)
    try:
        tf = tarfile.open(fileobj=stream, mode="r:")
    except ExtractionError:
        stream.close()
        raise
    except (tarfile.TarError, OSError, EOFError, zlibError, lzma.LZMAError) as exc:
        stream.close()
        raise ExtractionError(f"not a readable tar archive: {exc}") from exc
    with closing(stream), tf:
        count = 0
        declared = 0
        try:
            for member in tf:  # streamed, so a huge member list is cut off early
                count += 1
                if count > limits.max_members:
                    raise ExtractionError(f"more than {limits.max_members} archive members")
                # Tar sizes in headers are honest (the reader uses them to find the next
                # header), so they can be checked up front. This also covers members that
                # are refused below: skipping past them still means decompressing them.
                declared += max(member.size, 0)
                if declared > limits.max_total_bytes:
                    raise ExtractionError(
                        f"archive declares more than {limits.max_total_bytes} bytes (decompression bomb?)")
                rel, reason = sanitize_member_name(member.name, limits.max_path_length)
                if rel is None:
                    report.blocked.append((member.name, reason or "refused"))
                    continue
                if member.issym() or member.islnk():
                    report.blocked.append((member.name, "symlink" if member.issym() else "hard link"))
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    report.blocked.append((member.name, "device, FIFO or other special file"))
                    continue
                src = tf.extractfile(member)
                if src is None:
                    continue
                with src:
                    writer.write(rel, src)
        except (tarfile.TarError, EOFError, OSError, zlibError, lzma.LZMAError) as exc:
            raise ExtractionError(f"corrupt tar archive: {exc}") from exc
    report.total_bytes = budget.total
    return report


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    # Unix mode bits live in the high 16 bits of external_attr.
    mode = (info.external_attr >> 16) & 0o170000
    return mode == 0o120000


def extract_zip(archive: Path, dest: Path, limits: Limits = Limits()) -> ExtractReport:
    report = ExtractReport(root=dest)
    budget = _Budget(limits)
    writer = _Writer(dest, budget, report)
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ExtractionError(f"not a readable zip archive: {exc}") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_members:
            raise ExtractionError(f"more than {limits.max_members} archive members")
        try:
            for info in infos:
                rel, reason = sanitize_member_name(info.filename, limits.max_path_length)
                if rel is None:
                    report.blocked.append((info.filename, reason or "refused"))
                    continue
                if _zip_is_symlink(info):
                    report.blocked.append((info.filename, "symlink"))
                    continue
                if info.is_dir():
                    continue
                if info.flag_bits & 0x1:
                    report.blocked.append((info.filename, "encrypted member"))
                    continue
                with zf.open(info) as src:
                    writer.write(rel, src)
        except (zipfile.BadZipFile, zlibError, lzma.LZMAError, EOFError, NotImplementedError, RuntimeError,
                OSError) as exc:
            raise ExtractionError(f"corrupt zip archive: {exc}") from exc
    report.total_bytes = budget.total
    return report


def archive_kind(path: Path) -> str:
    """Detect by content, not by name: 'zip', 'tar' or 'unknown'."""
    with open(path, "rb") as fh:
        head = fh.read(262)
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\x1f\x8b") or head.startswith(b"BZh") or head.startswith(b"\xfd7zXZ"):
        return "tar"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return "unknown"


def safe_extract(archive: Path, dest: Path, limits: Limits = Limits()) -> ExtractReport:
    size = archive.stat().st_size
    if size > limits.max_archive_bytes:
        raise ExtractionError(f"archive is {size} bytes, limit is {limits.max_archive_bytes}")
    dest.mkdir(parents=True, exist_ok=True)
    kind = archive_kind(archive)
    if kind == "zip":
        return extract_zip(archive, dest, limits)
    if kind == "tar":
        return extract_tar(archive, dest, limits)
    raise ExtractionError("unsupported archive format")


def verify_digest(path: Path, sha256: str | None = None, integrity: str | None = None) -> bool:
    """Check a download against the digest the registry published."""
    if sha256:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                h.update(chunk)
        return h.hexdigest() == sha256.lower()
    if integrity and integrity.startswith("sha512-"):
        h = hashlib.sha512()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                h.update(chunk)
        return base64.b64encode(h.digest()).decode() == integrity.split("-", 1)[1]
    return True


def ensure_not_on_import_path(path: Path) -> None:
    """Refuse to work in a folder Python could import from."""
    import sys

    resolved = path.resolve()
    for entry in sys.path:
        try:
            if entry and Path(entry).resolve() == resolved:
                raise RuntimeError(f"quarantine folder {path} is on sys.path")
        except OSError:
            continue
    if os.environ.get("PYTHONPATH") and str(resolved) in os.environ["PYTHONPATH"]:
        raise RuntimeError("quarantine folder is on PYTHONPATH")
