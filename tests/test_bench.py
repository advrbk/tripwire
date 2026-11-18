"""The benchmark corpus must stay inert, labelled and well formed."""

import ast
import ipaddress
import json
import re
from collections import Counter

import pytest

from tripwire.bench.archive import build
from tripwire.bench.corpus import BENIGN, CATEGORIES, FIXTURES, MALICIOUS, by_id
from tripwire.bench.run import Outcome, format_report, metrics, prf, write_corpus, write_labels
from tripwire.models import Evidence, ScanResult
from tripwire.quarantine import safe_extract

HOST = re.compile(r"""(?:https?|ftp|wss?)://([^/\s'"`:)]+)""")
DOMAIN_LIKE = re.compile(r"""\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|site|app|dev|invalid|example|test|cn|me))\b""",
                         re.I)
RESERVED_SUFFIXES = (".invalid", ".example", ".test", "example.com", "example.org", "example.net")
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
# Benign fixtures may name a couple of real, well-known *legitimate* hosts (a prebuilt
# binary on GitHub) because that is exactly the false-positive case being measured.
BENIGN_EXTRA_HOSTS = {"github.com"}


def all_text(fx) -> str:
    return "\n".join(fx.files.values()) + "\n" + "\n".join(fx.scripts.values())


def hosts_in(text: str) -> set[str]:
    return {h.lower() for h in HOST.findall(text)} | {d.lower() for d in DOMAIN_LIKE.findall(text)}


def is_allowed_host(host: str, label: str) -> bool:
    if host.endswith(RESERVED_SUFFIXES) or host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private and not ip.is_global or any(ip in n for n in DOC_NETS)
    except ValueError:
        pass
    return label == BENIGN and host in BENIGN_EXTRA_HOSTS


# ------------------------------------------------------------------ corpus shape

def test_corpus_size():
    counts = Counter(f.label for f in FIXTURES)
    assert 40 <= counts[MALICIOUS] <= 60 and 40 <= counts[BENIGN] <= 60


def test_ids_and_names_are_unique():
    assert len({f.id for f in FIXTURES}) == len(FIXTURES)
    assert len({(f.ecosystem, f.name) for f in FIXTURES}) == len(FIXTURES)


def test_labels_are_consistent():
    for f in FIXTURES:
        assert f.label in (MALICIOUS, BENIGN)
        assert f.signals <= set(CATEGORIES), f.id
        assert bool(f.signals) == (f.label == MALICIOUS), f.id


def test_every_category_is_represented():
    covered = Counter(s for f in FIXTURES for s in f.signals)
    assert all(covered[c] >= 5 for c in CATEGORIES), covered


def test_by_id():
    assert by_id("setup-env-post").label == MALICIOUS
    with pytest.raises(KeyError):
        by_id("no-such-fixture")


# ------------------------------------------------------------------ inertness

@pytest.mark.parametrize("fx", FIXTURES, ids=lambda f: f.id)
def test_fixture_hosts_are_reserved_or_documentation(fx):
    bad = {h for h in hosts_in(all_text(fx)) if not is_allowed_host(h, fx.label)}
    assert not bad, f"{fx.id} names real hosts: {bad}"


def test_no_real_looking_secrets():
    text = "\n".join(all_text(f) for f in FIXTURES)
    assert not re.search(r"AKIA[0-9A-Z]{16}", text)          # AWS key id shape
    assert not re.search(r"gh[pousr]_[A-Za-z0-9]{30,}", text)  # GitHub token shape
    assert not re.search(r"npm_[A-Za-z0-9]{30,}", text)


@pytest.mark.parametrize("fx", [f for f in FIXTURES if f.ecosystem == "pypi"], ids=lambda f: f.id)
def test_python_fixtures_parse(fx):
    for path, text in fx.files.items():
        if path.endswith(".py"):
            ast.parse(text)  # valid Python, so the AST rules are what get measured


def test_npm_fixtures_have_valid_package_json():
    from tripwire.bench.archive import package_json
    for f in FIXTURES:
        if f.ecosystem == "npm":
            assert json.loads(package_json(f))["name"] == f.name


@pytest.mark.parametrize("fx", FIXTURES[::7], ids=lambda f: f.id)
def test_archives_extract_cleanly(fx, tmp_path):
    name, data = build(fx)
    p = tmp_path / name
    p.write_bytes(data)
    rep = safe_extract(p, tmp_path / "x")
    assert rep.blocked == [] and len(rep.files) >= len(fx.files)


def test_archives_are_reproducible():
    fx = by_id("plain-lib")
    assert build(fx) == build(fx)


# ------------------------------------------------------------------ metric arithmetic

def test_prf():
    assert prf(8, 2, 2) == (0.8, 0.8, pytest.approx(0.8))
    assert prf(0, 0, 0) == (None, None, None)
    assert prf(0, 3, 0) == (0.0, None, None)
    assert prf(0, 0, 3) == (None, 0.0, None)


def fake(fid, label, signals, fired, score):
    from tripwire.bench.corpus import Fixture
    fx = Fixture(fid, "npm", "npm", label, frozenset(signals), {}, fid)
    ev = [Evidence(a, "r", 0.5, "m") for a in fired]
    return Outcome(fx, ScanResult("npm", fid, "1", score, "x", score >= 50, "", ev), 0.01)


def test_metrics_counts():
    outs = [fake("m1", MALICIOUS, {"network"}, {"network"}, 80),
            fake("m2", MALICIOUS, {"network", "credentials"}, {"credentials"}, 40),
            fake("b1", BENIGN, set(), {"network"}, 55),
            fake("b2", BENIGN, set(), set(), 0)]
    m = metrics(outs)
    assert m["per_analyzer"]["network"] == {"tp": 1, "fp": 1, "fn": 1, "precision": 0.5, "recall": 0.5, "f1": 0.5}
    assert m["overall"]["tp"] == 1 and m["overall"]["fp"] == 1 and m["overall"]["fn"] == 1
    assert [c["id"] for c in m["benign_flagged"]] == ["b1"]
    assert [c["id"] for c in m["malicious_missed"]] == ["m2"]
    assert {"id": "m2", "analyzer": "network", "score": 40} in m["category_misses"]
    report = format_report(m)
    assert "not real-world detection rates" in report and "b1: score 55" in report


def test_write_corpus_and_labels(tmp_path):
    assert write_corpus(tmp_path / "c") == len(FIXTURES)
    assert len(list((tmp_path / "c").rglob("*.*"))) == len(FIXTURES)
    write_labels(tmp_path / "labels.csv")
    lines = (tmp_path / "labels.csv").read_text().splitlines()
    assert len(lines) == len(FIXTURES) + 1


def test_keyword_prefilters_never_change_findings(monkeypatch):
    """The has_any() prefilters are a speed-up only: disabling them must give identical evidence."""
    from tripwire.analyzers import credentials, network, obfuscation
    from tripwire.bench.archive import package_json, pkg_info
    from tripwire.loader import package_from_texts
    from tripwire.scanner import analyze_package

    def packages():
        for f in FIXTURES:
            meta = {"package.json": package_json(f)} if f.ecosystem == "npm" else {"PKG-INFO": pkg_info(f)}
            yield package_from_texts({**meta, **f.files}, f.ecosystem, f.name, f.version)

    def key():
        return [sorted((e.analyzer, e.rule, e.weight, e.file, e.line) for e in analyze_package(p).evidence)
                for p in packages()]

    fast = key()
    for mod in (credentials, network, obfuscation):
        monkeypatch.setattr(mod, "has_any", lambda low, keys: True)
    assert key() == fast
