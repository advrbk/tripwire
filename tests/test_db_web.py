"""SQLite storage and the dashboard API (FastAPI TestClient)."""

import pytest
from fastapi.testclient import TestClient

from tripwire.db import MAX_SNIPPET, Database
from tripwire.models import Evidence, ScanResult
from tripwire.web.app import CSP, create_app


def result(name, score=0, level="none", flagged=False, eco="npm", evidence=None, version="1.0.0"):
    return ScanResult(eco, name, version, score, level, flagged, f"explain {name}", evidence or [], 3, 100)


EV = [Evidence("network", "raw_ip", 0.45, "raw ip", "a.js", 3, "x" * 1000),
      Evidence("credentials", "ssh_keys", 0.5, "ssh", "b.js", 1, None),
      Evidence("install_hooks", "npm_hook_build", 0.05, "build", None, None, None)]


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "t.db")
    d.save_result(result("clean-lib"), published_at="2026-11-18T10:00:00Z", artifact="clean-lib-1.0.0.tgz")
    d.save_result(result("bad_lib%", 92, "critical", True, evidence=EV))
    d.save_result(result("py-thing", 30, "low", eco="pypi", evidence=[EV[0]]))
    d.save_status("npm", "huge", "1.0.0", "skipped", "archive is 99999999 bytes")
    yield d
    d.close()


# ------------------------------------------------------------------ database

def test_has_release(db):
    assert db.has_release("npm", "clean-lib", "1.0.0")
    assert not db.has_release("pypi", "clean-lib", "1.0.0")


def test_list_newest_first_with_top_findings(db):
    rows, total = db.list_releases()
    assert total == 4 and rows[0]["name"] == "huge"
    bad = next(r for r in rows if r["name"] == "bad_lib%")
    assert bad["flagged"] is True and [f["rule"] for f in bad["top_findings"]] == ["ssh_keys", "raw_ip"]
    assert bad["analyzers"] == "credentials,network"  # only analysers at or above the fire threshold


@pytest.mark.parametrize("kw,names", [
    ({"ecosystem": "pypi"}, {"py-thing"}),
    ({"flagged": True}, {"bad_lib%"}),
    ({"min_score": 50}, {"bad_lib%"}),
    ({"level": "low"}, {"py-thing"}),
    ({"analyzer": "network"}, {"bad_lib%", "py-thing"}),
    ({"status": "skipped"}, {"huge"}),
    ({"q": "%"}, {"bad_lib%"}),      # LIKE wildcards are escaped, so % matches only a literal %
    ({"q": "_"}, {"bad_lib%"}),
    ({"q": "lib"}, {"clean-lib", "bad_lib%"}),
])
def test_filters(db, kw, names):
    rows, total = db.list_releases(**kw)
    assert {r["name"] for r in rows} == names and total == len(names)


def test_paging(db):
    rows, total = db.list_releases(limit=2, offset=2)
    assert total == 4 and len(rows) == 2


def test_get_release_has_all_findings_and_clipped_snippets(db):
    rid = next(r["id"] for r in db.list_releases()[0] if r["name"] == "bad_lib%")
    rel = db.get_release(rid)
    assert len(rel["findings"]) == 3
    assert len(rel["findings"][0]["snippet"] or "") <= MAX_SNIPPET
    assert db.get_release(999999) is None


def test_rescan_replaces_findings(db):
    db.save_result(result("bad_lib%", 10, "none", evidence=[]))
    rows, _ = db.list_releases(q="bad")
    assert rows[0]["score"] == 10 and rows[0]["top_findings"] == []


def test_status_upsert(db):
    db.save_status("npm", "huge", "1.0.0", "error", "second try failed")
    rows, total = db.list_releases(status="error")
    assert total == 1 and rows[0]["status_detail"] == "second try failed"


def test_stats(db):
    s = db.stats()
    assert s["by_ecosystem"]["npm"] == {"scanned": 2, "skipped": 1, "error": 0, "flagged": 1}
    assert s["levels"] == {"none": 1, "critical": 1, "low": 1}


def test_feed_state_round_trip(db):
    assert db.get_state("pypi") is None
    db.set_state("pypi", {"cursor": "x", "recent": ["a"]})
    db.set_state("pypi", {"cursor": "y", "recent": []})
    assert db.get_state("pypi") == {"cursor": "y", "recent": []}


def test_hostile_names_are_stored_as_data(db):
    name = "x'); DROP TABLE releases; --"
    db.save_result(result(name))
    assert db.has_release("npm", name, "1.0.0") and db.list_releases()[1] == 5


# ------------------------------------------------------------------ web API

@pytest.fixture
def client(db):
    with TestClient(create_app(db.path)) as c:
        yield c


def test_index_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "Tripwire" in r.text
    assert r.headers["content-security-policy"] == CSP
    assert "script-src 'self'" in CSP and "unsafe-inline" not in CSP
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("name,ctype", [("app.js", "text/javascript"), ("style.css", "text/css")])
def test_static_files(client, name, ctype):
    r = client.get(f"/static/{name}")
    assert r.status_code == 200 and r.headers["content-type"].startswith(ctype)


@pytest.mark.parametrize("path", ["/static/index.html", "/static/..%2Fapp.py", "/static/nope.js"])
def test_static_only_serves_known_files(client, path):
    assert client.get(path).status_code == 404


def test_api_releases(client):
    data = client.get("/api/releases", params={"flagged": "true"}).json()
    assert data["total"] == 1 and data["items"][0]["name"] == "bad_lib%"
    assert client.get("/api/releases", params={"ecosystem": "pypi", "min_score": 20}).json()["total"] == 1


@pytest.mark.parametrize("params", [{"analyzer": "nope"}, {"level": "extreme"}, {"min_score": 101},
                                    {"limit": 0}, {"limit": 501}, {"ecosystem": "cargo"}, {"q": "x" * 101}])
def test_api_rejects_bad_parameters(client, params):
    assert client.get("/api/releases", params=params).status_code == 422


def test_api_release_detail(client):
    rid = client.get("/api/releases", params={"flagged": "true"}).json()["items"][0]["id"]
    detail = client.get(f"/api/releases/{rid}").json()
    assert {f["analyzer"] for f in detail["findings"]} == {"network", "credentials", "install_hooks"}
    assert client.get("/api/releases/424242").status_code == 404
    assert client.get("/api/releases/abc").status_code == 422


def test_api_stats_and_health(client):
    s = client.get("/api/stats").json()
    assert "install_hooks" in s["analyzers"] and s["by_ecosystem"]["pypi"]["scanned"] == 1
    assert client.get("/healthz").json()["ok"] is True


def test_untrusted_markup_comes_back_as_plain_json(client, db):
    db.save_result(result("<script>alert(1)</script>", 60, "medium", True,
                          evidence=[Evidence("network", "raw_ip", 0.6, "<img src=x onerror=alert(1)>")]))
    item = client.get("/api/releases", params={"q": "script"}).json()["items"][0]
    assert item["name"] == "<script>alert(1)</script>"
    assert client.get("/api/releases", params={"q": "script"}).headers["content-type"] == "application/json"


def test_page_script_uses_text_content_only(client):
    js = client.get("/static/app.js").text
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "eval(" not in js


def test_api_docs_are_off(client):
    assert client.get("/docs").status_code == 404
