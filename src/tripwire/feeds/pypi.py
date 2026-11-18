"""PyPI: RSS for "what changed", JSON API for "where is the file".

* ``/rss/updates.xml`` lists the latest ~100 releases (name + version).
* ``/rss/packages.xml`` lists the latest ~40 brand-new projects.
* ``/pypi/<name>/<version>/json`` gives the files and their sha256.

The RSS feeds have no cursor, so resume works on publish time: the state
keeps the newest pubDate processed plus the keys already seen at that time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote

from defusedxml import ElementTree as SafeET  # refuses entity-expansion tricks in untrusted XML

from ..db import Database
from ..models import ReleaseRef
from .http import PoliteClient

UPDATES_URL = "https://pypi.org/rss/updates.xml"
NEWEST_URL = "https://pypi.org/rss/packages.xml"
JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"
LATEST_JSON_URL = "https://pypi.org/pypi/{name}/json"
STATE_KEY = "pypi"
RECENT_KEEP = 500


@dataclass(frozen=True)
class PyPICandidate:
    name: str
    version: str | None
    published: str  # ISO 8601 UTC
    new_package: bool

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version or '?'}"


def _iso_utc(rfc822: str) -> str:
    dt = parsedate_to_datetime(rfc822)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_rss(xml_text: str, *, newest: bool) -> list[PyPICandidate]:
    root = SafeET.fromstring(xml_text)
    out = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        pub = item.findtext("pubDate") or ""
        try:
            published = _iso_utc(pub) if pub else ""
        except (TypeError, ValueError):
            published = ""
        if newest:
            name = title.removesuffix(" added to PyPI").strip()
            if name:
                out.append(PyPICandidate(name, None, published, True))
        else:
            parts = title.rsplit(" ", 1)
            if len(parts) == 2:
                out.append(PyPICandidate(parts[0], parts[1], published, False))
    return out


class PyPIFeed:
    ecosystem = "pypi"

    def __init__(self, client: PoliteClient, db: Database):
        self.client = client
        self.db = db
        state = db.get_state(STATE_KEY) or {}
        self.cursor: str = state.get("cursor", "")
        self.recent: list[str] = state.get("recent", [])

    def poll(self) -> list[PyPICandidate]:
        """New candidates since the saved position, oldest first."""
        items = parse_rss(self.client.get_text(UPDATES_URL), newest=False)
        try:
            items += parse_rss(self.client.get_text(NEWEST_URL), newest=True)
        except Exception:  # the "newest" feed is a bonus; updates.xml is enough
            pass
        new_names = {c.name for c in items if c.new_package}
        recent = set(self.recent)
        merged: dict[str, PyPICandidate] = {}
        for c in items:
            if c.published and self.cursor and c.published < self.cursor:
                continue
            if c.key in recent:
                continue
            if not c.new_package and c.name in new_names:
                c = PyPICandidate(c.name, c.version, c.published, True)
            if c.version is None and any(m.name == c.name for m in merged.values()):
                continue
            merged[c.key] = c
        # A "newest" entry without a version is dropped when updates.xml has the same name
        named = {c.name for c in merged.values() if c.version}
        result = [c for c in merged.values() if c.version or c.name not in named]
        return sorted(result, key=lambda c: (c.published, c.name))

    def resolve(self, cand: PyPICandidate) -> ReleaseRef | None:
        """Pick the file to scan: the sdist if present (it carries setup.py), else a wheel."""
        if cand.version:
            url = JSON_URL.format(name=quote(cand.name, safe=""), version=quote(cand.version, safe=""))
        else:
            url = LATEST_JSON_URL.format(name=quote(cand.name, safe=""))
        data = self.client.get_json(url)
        if not isinstance(data, dict):
            return None
        version = cand.version or (data.get("info") or {}).get("version")
        files = [u for u in data.get("urls") or [] if isinstance(u, dict) and not u.get("yanked")]
        if not files or not version:
            return None
        sdists = [u for u in files if u.get("packagetype") == "sdist"]
        wheels = [u for u in files if u.get("packagetype") == "bdist_wheel"]
        pure = [w for w in wheels if str(w.get("filename", "")).endswith("-none-any.whl")]
        choice = (sdists or pure or wheels or files)[0]
        return ReleaseRef(
            ecosystem="pypi", name=(data.get("info") or {}).get("name") or cand.name, version=version,
            artifact_url=choice["url"], filename=choice.get("filename", ""), size=choice.get("size"),
            sha256=(choice.get("digests") or {}).get("sha256"), published_at=cand.published or None,
            new_package=cand.new_package,
        )

    def commit(self, cand: PyPICandidate) -> None:
        """Mark one candidate as handled and persist the position."""
        if cand.published and cand.published > self.cursor:
            self.cursor = cand.published
        self.recent.append(cand.key)
        self.recent = self.recent[-RECENT_KEEP:]
        self.db.set_state(STATE_KEY, {"cursor": self.cursor, "recent": self.recent})
