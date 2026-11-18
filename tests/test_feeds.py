"""Feed parsing and the polite HTTP client, against synthetic responses only."""

import json

import httpx
import pytest

from tripwire import USER_AGENT
from tripwire.db import Database
from tripwire.feeds import npm as npm_mod
from tripwire.feeds import pypi as pypi_mod
from tripwire.feeds.http import DownloadRefused, DownloadTooLarge, PoliteClient, check_download_url
from tripwire.feeds.npm import NpmCandidate, NpmFeed, encode_name
from tripwire.feeds.pypi import PyPICandidate, PyPIFeed, parse_rss

UPDATES = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>PyPI recent updates</title>
<item><title>alpha-lib 1.2.0</title><link>https://pypi.org/project/alpha-lib/1.2.0/</link>
  <pubDate>Wed, 18 Nov 2026 12:00:05 GMT</pubDate></item>
<item><title>beta 0.1</title><link>https://pypi.org/project/beta/0.1/</link>
  <pubDate>Wed, 18 Nov 2026 12:00:01 GMT</pubDate></item>
<item><title>brand-new 0.0.1</title><pubDate>Wed, 18 Nov 2026 12:00:03 GMT</pubDate></item>
<item><title>no-version-here</title><pubDate>Wed, 18 Nov 2026 12:00:00 GMT</pubDate></item>
</channel></rss>"""

NEWEST = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<item><title>brand-new added to PyPI</title><pubDate>Wed, 18 Nov 2026 12:00:02 GMT</pubDate></item>
<item><title>only-in-newest added to PyPI</title><pubDate>Wed, 18 Nov 2026 12:00:04 GMT</pubDate></item>
</channel></rss>"""


def mock_client(handler, **kw) -> PoliteClient:
    return PoliteClient(transport=httpx.MockTransport(handler), min_interval=0, sleep=lambda s: None, **kw)


def router(routes: dict[str, object]):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        key = str(request.url).split("?")[0]
        body = routes.get(key)
        if body is None:
            return httpx.Response(404)
        if isinstance(body, httpx.Response):
            return body
        text = body if isinstance(body, str) else json.dumps(body)
        return httpx.Response(200, text=text)

    handler.seen = seen
    return handler


@pytest.fixture
def db():
    d = Database(":memory:")
    yield d
    d.close()


# ------------------------------------------------------------------ PyPI RSS

def test_parse_updates_feed():
    items = parse_rss(UPDATES, newest=False)
    assert [(c.name, c.version) for c in items] == [("alpha-lib", "1.2.0"), ("beta", "0.1"), ("brand-new", "0.0.1")]
    assert items[0].published == "2026-11-18T12:00:05Z" and not items[0].new_package


def test_parse_newest_feed():
    items = parse_rss(NEWEST, newest=True)
    assert [(c.name, c.version, c.new_package) for c in items] == [("brand-new", None, True),
                                                                    ("only-in-newest", None, True)]


def test_rss_entity_expansion_is_refused():
    bomb = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>'
            "<rss><channel><item><title>&b;</title></item></channel></rss>")
    with pytest.raises(Exception) as info:
        parse_rss(bomb, newest=False)
    assert "Entities" in type(info.value).__name__ or "entit" in str(info.value).lower()


def test_rss_bad_date_is_tolerated():
    xml = "<rss><channel><item><title>x 1.0</title><pubDate>not a date</pubDate></item></channel></rss>"
    assert parse_rss(xml, newest=False)[0].published == ""


def test_pypi_poll_merges_feeds_and_marks_new(db):
    h = router({pypi_mod.UPDATES_URL: UPDATES, pypi_mod.NEWEST_URL: NEWEST})
    feed = PyPIFeed(mock_client(h), db)
    got = feed.poll()
    # oldest first; the versionless "newest" entry for brand-new is dropped because updates.xml names a version
    assert [c.key for c in got] == ["beta@0.1", "brand-new@0.0.1", "only-in-newest@?", "alpha-lib@1.2.0"]
    by = {c.name: c for c in got}
    assert by["brand-new"].new_package and by["brand-new"].version == "0.0.1"
    assert not by["alpha-lib"].new_package


def test_pypi_cursor_and_recent_survive_restart(db):
    h = router({pypi_mod.UPDATES_URL: UPDATES, pypi_mod.NEWEST_URL: NEWEST})
    feed = PyPIFeed(mock_client(h), db)
    for c in feed.poll():
        feed.commit(c)
    again = PyPIFeed(mock_client(h), db)  # new process, same database
    assert again.cursor == "2026-11-18T12:00:05Z"
    assert again.poll() == []


def test_pypi_newest_feed_failure_is_tolerated(db):
    h = router({pypi_mod.UPDATES_URL: UPDATES})  # packages.xml returns 404
    assert len(PyPIFeed(mock_client(h), db).poll()) == 3


PYPI_JSON = {
    "info": {"name": "Alpha-Lib", "version": "1.2.0"},
    "urls": [
        {"packagetype": "bdist_wheel", "filename": "alpha_lib-1.2.0-cp312-win_amd64.whl",
         "url": "https://files.pythonhosted.org/w1", "size": 10, "digests": {"sha256": "aa"}},
        {"packagetype": "bdist_wheel", "filename": "alpha_lib-1.2.0-py3-none-any.whl",
         "url": "https://files.pythonhosted.org/w2", "size": 10, "digests": {"sha256": "bb"}},
        {"packagetype": "sdist", "filename": "alpha_lib-1.2.0.tar.gz",
         "url": "https://files.pythonhosted.org/s", "size": 20, "digests": {"sha256": "cc"}},
    ],
}


def test_pypi_resolve_prefers_sdist(db):
    h = router({"https://pypi.org/pypi/alpha-lib/1.2.0/json": PYPI_JSON})
    r = PyPIFeed(mock_client(h), db).resolve(PyPICandidate("alpha-lib", "1.2.0", "2026-11-18T12:00:05Z", False))
    assert (r.name, r.filename, r.sha256, r.size) == ("Alpha-Lib", "alpha_lib-1.2.0.tar.gz", "cc", 20)
    assert r.key == "pypi:Alpha-Lib@1.2.0"


def test_pypi_resolve_pure_wheel_when_no_sdist(db):
    data = {**PYPI_JSON, "urls": PYPI_JSON["urls"][:2]}
    h = router({"https://pypi.org/pypi/alpha-lib/1.2.0/json": data})
    r = PyPIFeed(mock_client(h), db).resolve(PyPICandidate("alpha-lib", "1.2.0", "", False))
    assert r.filename.endswith("py3-none-any.whl")


def test_pypi_resolve_skips_yanked_and_empty(db):
    data = {"info": {"name": "x", "version": "1"}, "urls": [{**PYPI_JSON["urls"][2], "yanked": True}]}
    h = router({"https://pypi.org/pypi/x/1/json": data})
    assert PyPIFeed(mock_client(h), db).resolve(PyPICandidate("x", "1", "", False)) is None


def test_pypi_resolve_new_project_uses_latest(db):
    h = router({"https://pypi.org/pypi/only-in-newest/json": {**PYPI_JSON, "info": {"name": "only-in-newest",
                                                                                     "version": "0.3"}}})
    r = PyPIFeed(mock_client(h), db).resolve(PyPICandidate("only-in-newest", None, "", True))
    assert r.version == "0.3" and r.new_package


def test_pypi_name_is_url_quoted(db):
    h = router({})
    with pytest.raises(httpx.HTTPStatusError):
        PyPIFeed(mock_client(h), db).resolve(PyPICandidate("../../admin", "1", "", False))
    assert b"%2F" in h.seen[0].url.raw_path and b"/admin" not in h.seen[0].url.raw_path


# ------------------------------------------------------------------ npm changes feed

CHANGES = {
    "results": [
        {"seq": 101, "id": "left-pad-ng"},
        {"seq": 102, "id": "_design/app"},
        {"seq": 103, "id": "removed-pkg", "deleted": True},
        {"seq": 104, "id": "@scope/tool"},
        {"seq": 105, "id": "left-pad-ng"},
        {"seq": 106, "id": 12345},
    ],
    "last_seq": 110,
}


def test_npm_first_poll_starts_a_backlog_behind_head(db):
    h = router({npm_mod.REPLICATE_ROOT: {"update_seq": 1000}, npm_mod.CHANGES_URL: {"results": [], "last_seq": 1000}})
    feed = NpmFeed(mock_client(h), db, start_backlog=200)
    feed.poll()
    assert "since=800" in str(h.seen[1].url)


def test_npm_poll_filters_and_dedupes(db):
    h = router({npm_mod.CHANGES_URL: CHANGES})
    db.set_state("npm", {"since": 100})
    got = NpmFeed(mock_client(h), db).poll()
    assert [(c.name, c.seq) for c in got] == [("@scope/tool", 104), ("left-pad-ng", 105)]
    assert got[-1].batch_end == 110 and got[0].batch_end is None


def test_npm_commit_moves_cursor_to_batch_end(db):
    h = router({npm_mod.CHANGES_URL: CHANGES})
    db.set_state("npm", {"since": 100})
    feed = NpmFeed(mock_client(h), db)
    got = feed.poll()
    feed.commit(got[0])
    assert db.get_state("npm") == {"since": 104}
    feed.commit(got[1])
    assert db.get_state("npm") == {"since": 110}
    feed.commit(NpmCandidate("old", 50))  # never moves backwards
    assert feed.since == 110


def test_npm_batch_of_only_deletions_advances(db):
    h = router({npm_mod.CHANGES_URL: {"results": [{"seq": 7, "id": "x", "deleted": True}], "last_seq": 9}})
    db.set_state("npm", {"since": 5})
    feed = NpmFeed(mock_client(h), db)
    assert feed.poll() == [] and feed.since == 9


def test_npm_resolve(db):
    doc = {"name": "@scope/tool", "version": "2.0.0",
           "dist": {"tarball": "https://registry.npmjs.org/@scope/tool/-/tool-2.0.0.tgz", "integrity": "sha512-xx"}}
    h = router({"https://registry.npmjs.org/@scope%2Ftool/latest": doc})
    r = NpmFeed(mock_client(h), db).resolve(NpmCandidate("@scope/tool", 1))
    assert (r.name, r.version, r.filename, r.integrity) == ("@scope/tool", "2.0.0", "tool-2.0.0.tgz", "sha512-xx")


def test_npm_resolve_without_tarball(db):
    h = router({"https://registry.npmjs.org/x/latest": {"name": "x", "version": "1.0.0", "dist": {}}})
    assert NpmFeed(mock_client(h), db).resolve(NpmCandidate("x", 1)) is None


def test_encode_scoped_name():
    assert encode_name("@scope/pkg") == "@scope%2Fpkg"
    assert encode_name("plain") == "plain"


# ------------------------------------------------------------------ PoliteClient

def test_user_agent_is_generic():
    assert USER_AGENT.startswith("tripwire-portfolio/")
    assert "@" not in USER_AGENT and "http" not in USER_AGENT
    h = router({"https://pypi.org/x": "ok"})
    mock_client(h).get_text("https://pypi.org/x")
    assert h.seen[0].headers["User-Agent"] == USER_AGENT


def test_per_host_interval_is_respected():
    now = [0.0]
    sleeps = []

    def sleep(s):
        sleeps.append(round(s, 3))
        now[0] += s

    c = PoliteClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")),
                     per_host={"a.example": 2.0}, min_interval=0.5, sleep=sleep, clock=lambda: now[0])
    c.get_text("https://a.example/1")
    c.get_text("https://a.example/2")   # must wait 2.0
    c.get_text("https://b.example/1")   # other host: no wait
    c.get_text("https://b.example/2")   # default 0.5
    assert sleeps == [2.0, 0.5]


def test_429_retry_after_is_honoured():
    calls, sleeps = [], []

    def handler(r):
        calls.append(r)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return httpx.Response(200, text="ok")

    c = PoliteClient(transport=httpx.MockTransport(handler), min_interval=0, sleep=sleeps.append)
    assert c.get_text("https://pypi.org/x") == "ok"
    assert 7.0 in sleeps and len(calls) == 2


def test_server_errors_retry_then_give_up():
    calls = []
    c = PoliteClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(503)),
                     min_interval=0, sleep=lambda s: None, retries=2)
    with pytest.raises(httpx.HTTPStatusError):
        c.get_text("https://pypi.org/x")
    assert len(calls) == 3


def test_transport_errors_retry():
    calls = []

    def handler(r):
        calls.append(r)
        if len(calls) < 3:
            raise httpx.ConnectError("flaky")
        return httpx.Response(200, text="ok")

    assert mock_client(handler).get_text("https://pypi.org/x") == "ok" and len(calls) == 3


def test_get_text_size_cap():
    c = mock_client(lambda r: httpx.Response(200, content=b"x" * 5000))
    with pytest.raises(DownloadTooLarge):
        c.get_text("https://pypi.org/big", max_bytes=1000)


@pytest.mark.parametrize("url", ["http://files.pythonhosted.org/x", "https://example.com/x",
                                 "https://files.pythonhosted.org.example.invalid/x", "file:///etc/passwd"])
def test_download_host_allow_list(url):
    with pytest.raises(DownloadRefused):
        check_download_url(url)


def test_download_streams_with_cap(tmp_path):
    big = httpx.Response(200, stream=httpx.ByteStream(b"y" * 4096))
    c = mock_client(lambda r: big)
    dest = tmp_path / "f"
    with pytest.raises(DownloadTooLarge):
        c.download("https://registry.npmjs.org/x.tgz", dest, max_bytes=1000)
    assert not dest.exists()  # partial download deleted


def test_download_declared_length_too_big(tmp_path):
    resp = httpx.Response(200, headers={"Content-Length": "999999"}, stream=httpx.ByteStream(b"y"))
    with pytest.raises(DownloadTooLarge, match="declared"):
        mock_client(lambda r: resp).download("https://registry.npmjs.org/x.tgz", tmp_path / "f", max_bytes=10)


def test_download_ok(tmp_path):
    c = mock_client(lambda r: httpx.Response(200, stream=httpx.ByteStream(b"archive-bytes")))
    assert c.download("https://files.pythonhosted.org/p/x.tar.gz", tmp_path / "f", 1000) == 13
    assert (tmp_path / "f").read_bytes() == b"archive-bytes"
