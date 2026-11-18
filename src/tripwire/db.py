"""SQLite storage for scan results and feed cursors.

WAL mode lets the dashboard read while the watcher writes. Every query uses
parameters, never string formatting, because package names and evidence come
from untrusted archives.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS releases (
    id            INTEGER PRIMARY KEY,
    ecosystem     TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    published_at  TEXT,
    scanned_at    TEXT NOT NULL,
    status        TEXT NOT NULL,          -- scanned | skipped | error
    status_detail TEXT,
    score         INTEGER NOT NULL DEFAULT 0,
    level         TEXT NOT NULL DEFAULT 'none',
    flagged       INTEGER NOT NULL DEFAULT 0,
    explanation   TEXT,
    analyzers     TEXT,                   -- comma list of analysers that fired
    artifact      TEXT,
    file_count    INTEGER,
    total_bytes   INTEGER,
    source        TEXT NOT NULL DEFAULT 'live',
    UNIQUE (ecosystem, name, version)
);
CREATE INDEX IF NOT EXISTS releases_recent ON releases (scanned_at DESC);
CREATE INDEX IF NOT EXISTS releases_score ON releases (score DESC);
CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY,
    release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    analyzer   TEXT NOT NULL,
    rule       TEXT NOT NULL,
    weight     REAL NOT NULL,
    message    TEXT NOT NULL,
    file       TEXT,
    line       INTEGER,
    snippet    TEXT
);
CREATE INDEX IF NOT EXISTS findings_release ON findings (release_id);
CREATE TABLE IF NOT EXISTS feed_state (
    feed       TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

MAX_SNIPPET = 300


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ------------------------------------------------------------- writes

    def has_release(self, ecosystem: str, name: str, version: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM releases WHERE ecosystem=? AND name=? AND version=?",
                (ecosystem, name, version)).fetchone()
        return row is not None

    def save_result(self, result: ScanResult, *, published_at: str | None = None, artifact: str | None = None,
                    source: str = "live") -> int:
        with self.tx() as c:
            c.execute("DELETE FROM releases WHERE ecosystem=? AND name=? AND version=?",
                      (result.ecosystem, result.name, result.version))
            cur = c.execute(
                """INSERT INTO releases (ecosystem, name, version, published_at, scanned_at, status, score, level,
                   flagged, explanation, analyzers, artifact, file_count, total_bytes, source)
                   VALUES (?, ?, ?, ?, ?, 'scanned', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (result.ecosystem, result.name, result.version, published_at, utcnow(), result.score,
                 result.level, int(result.flagged), result.explanation, ",".join(sorted(result.fired_analyzers())),
                 artifact, result.file_count, result.total_bytes, source))
            rid = int(cur.lastrowid)
            c.executemany(
                """INSERT INTO findings (release_id, analyzer, rule, weight, message, file, line, snippet)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [(rid, e.analyzer, e.rule, e.weight, e.message, e.file, e.line,
                  (e.snippet or "")[:MAX_SNIPPET] or None) for e in result.evidence[:200]])
        return rid

    def save_status(self, ecosystem: str, name: str, version: str, status: str, detail: str, *,
                    published_at: str | None = None, artifact: str | None = None, source: str = "live") -> None:
        with self.tx() as c:
            c.execute(
                """INSERT INTO releases (ecosystem, name, version, published_at, scanned_at, status, status_detail,
                   artifact, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (ecosystem, name, version) DO UPDATE SET status=excluded.status,
                   status_detail=excluded.status_detail, scanned_at=excluded.scanned_at""",
                (ecosystem, name, version, published_at, utcnow(), status, detail[:500], artifact, source))

    # --------------------------------------------------------- feed state

    def get_state(self, feed: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM feed_state WHERE feed=?", (feed,)).fetchone()
        return json.loads(row["value"]) if row else None

    def set_state(self, feed: str, value: dict[str, Any]) -> None:
        with self.tx() as c:
            c.execute("""INSERT INTO feed_state (feed, value, updated_at) VALUES (?, ?, ?)
                         ON CONFLICT (feed) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                      (feed, json.dumps(value), utcnow()))

    # -------------------------------------------------------------- reads

    def list_releases(self, *, ecosystem: str | None = None, min_score: int = 0, flagged: bool | None = None,
                      level: str | None = None, analyzer: str | None = None, q: str | None = None,
                      status: str | None = None, source: str | None = None, limit: int = 50,
                      offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        where, args = ["score >= ?"], [min_score]
        if ecosystem:
            where.append("ecosystem = ?"); args.append(ecosystem)
        if flagged is not None:
            where.append("flagged = ?"); args.append(int(flagged))
        if level:
            where.append("level = ?"); args.append(level)
        if analyzer:
            where.append("(',' || analyzers || ',') LIKE ?"); args.append(f"%,{analyzer},%")
        if q:
            where.append("name LIKE ? ESCAPE '\\'")
            args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        if status:
            where.append("status = ?"); args.append(status)
        if source:
            where.append("source = ?"); args.append(source)
        clause = " AND ".join(where)
        with self._lock:
            total = self._conn.execute(f"SELECT COUNT(*) FROM releases WHERE {clause}", args).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM releases WHERE {clause} ORDER BY scanned_at DESC, id DESC LIMIT ? OFFSET ?",
                [*args, limit, offset]).fetchall()
            out = [dict(r) for r in rows]
            if out:
                ids = [r["id"] for r in out]
                marks = ",".join("?" * len(ids))
                fr = self._conn.execute(
                    f"""SELECT * FROM findings WHERE release_id IN ({marks}) AND weight >= 0.2
                        ORDER BY weight DESC, id""", ids).fetchall()
        by_id: dict[int, list[dict[str, Any]]] = {}
        for f in (fr if out else []):
            lst = by_id.setdefault(f["release_id"], [])
            if len(lst) < 5:
                lst.append(_finding(f))
        for r in out:
            r["flagged"] = bool(r["flagged"])
            r["top_findings"] = by_id.get(r["id"], [])
        return out, int(total)

    def get_release(self, rid: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM releases WHERE id=?", (rid,)).fetchone()
            if row is None:
                return None
            findings = self._conn.execute(
                "SELECT * FROM findings WHERE release_id=? ORDER BY weight DESC, id", (rid,)).fetchall()
        d = dict(row)
        d["flagged"] = bool(d["flagged"])
        d["findings"] = [_finding(f) for f in findings]
        return d

    def stats(self) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT ecosystem, status, COUNT(*) AS n, SUM(flagged) AS flagged FROM releases
                   GROUP BY ecosystem, status""").fetchall()
            levels = self._conn.execute(
                "SELECT level, COUNT(*) AS n FROM releases WHERE status='scanned' GROUP BY level").fetchall()
            last = self._conn.execute("SELECT MAX(scanned_at) FROM releases").fetchone()[0]
        out: dict[str, Any] = {"by_ecosystem": {}, "levels": {r["level"]: r["n"] for r in levels}, "last_scan": last}
        for r in rows:
            e = out["by_ecosystem"].setdefault(r["ecosystem"], {"scanned": 0, "skipped": 0, "error": 0, "flagged": 0})
            e[r["status"]] = r["n"]
            e["flagged"] += int(r["flagged"] or 0)
        return out


def _finding(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d.pop("release_id", None)
    return d
