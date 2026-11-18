"""Watch the feeds, download each new release into quarantine, scan, store.

One release at a time, in a single thread: the bottleneck is being polite to
the registries, not CPU, and a single thread keeps the rate limits simple.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx

from .db import Database
from .feeds.http import DownloadRefused, DownloadTooLarge, PoliteClient
from .feeds.npm import NpmFeed
from .feeds.pypi import PyPIFeed
from .models import ReleaseRef
from .quarantine import (ExtractionError, Limits, ensure_not_on_import_path, new_quarantine_dir, remove_tree,
                         verify_digest)
from .scanner import DEFAULT_QUARANTINE, scan_archive

# Minimum seconds between two requests to the same host. Deliberately slow:
# at most about one release per second per registry.
PER_HOST_INTERVAL = {
    "pypi.org": 1.0,               # RSS + JSON API
    "files.pythonhosted.org": 0.5,
    "replicate.npmjs.com": 2.0,
    "registry.npmjs.org": 0.5,
}


@dataclass
class RunStats:
    seen: int = 0
    scanned: int = 0
    flagged: int = 0
    skipped: int = 0
    errors: int = 0
    duplicates: int = 0
    by_ecosystem: dict[str, dict[str, int]] = field(default_factory=dict)
    flagged_names: list[tuple[str, str, str, int]] = field(default_factory=list)
    levels: dict[str, int] = field(default_factory=dict)
    scan_seconds: list[float] = field(default_factory=list)  # extract + parse + analyse, per release
    download_seconds: list[float] = field(default_factory=list)

    def bump(self, eco: str, key: str) -> None:
        e = self.by_ecosystem.setdefault(eco, {"seen": 0, "scanned": 0, "flagged": 0, "skipped": 0, "errors": 0})
        e[key] = e.get(key, 0) + 1

    def summary(self) -> dict:
        return {
            "seen": self.seen, "scanned": self.scanned, "flagged": self.flagged, "skipped": self.skipped,
            "errors": self.errors, "duplicates": self.duplicates, "by_ecosystem": self.by_ecosystem,
            "levels": dict(sorted(self.levels.items())),
            "scan_ms": percentiles(self.scan_seconds),
            "download_ms": percentiles(self.download_seconds),
            "flagged_releases": [list(x) for x in self.flagged_names],
        }


def percentiles(values: list[float]) -> dict[str, float | int | None]:
    """Nearest-rank p50 / p95 / max, in milliseconds."""
    if not values:
        return {"n": 0, "p50": None, "p95": None, "max": None}
    s = sorted(values)

    def rank(q: float) -> float:
        i = min(len(s) - 1, max(0, math.ceil(q * len(s)) - 1))
        return round(s[i] * 1000, 1)

    return {"n": len(s), "p50": rank(0.50), "p95": rank(0.95), "max": round(s[-1] * 1000, 1)}


class Pipeline:
    def __init__(self, db: Database, client: PoliteClient, *, quarantine: Path = DEFAULT_QUARANTINE,
                 limits: Limits = Limits(), log: Callable[[str], None] = print):
        self.db = db
        self.client = client
        self.quarantine = quarantine
        self.limits = limits
        self.log = log
        quarantine.mkdir(parents=True, exist_ok=True)
        ensure_not_on_import_path(quarantine)

    def process(self, ref: ReleaseRef, stats: RunStats) -> str:
        """Download, scan and store one release. Returns the outcome name."""
        eco = ref.ecosystem
        if self.db.has_release(eco, ref.name, ref.version):
            stats.duplicates += 1
            return "duplicate"
        stats.seen += 1
        stats.bump(eco, "seen")
        if ref.size is not None and ref.size > self.limits.max_archive_bytes:
            self.db.save_status(eco, ref.name, ref.version, "skipped", f"archive is {ref.size} bytes",
                                published_at=ref.published_at, artifact=ref.filename)
            stats.skipped += 1
            stats.bump(eco, "skipped")
            return "skipped"
        work = new_quarantine_dir(self.quarantine)
        try:
            # Never trust the remote filename for the local path.
            archive = work / ("download" + _safe_ext(ref.filename))
            t0 = time.perf_counter()
            self.client.download(ref.artifact_url, archive, self.limits.max_archive_bytes)
            t1 = time.perf_counter()
            if not verify_digest(archive, ref.sha256, ref.integrity):
                raise ExtractionError("digest does not match what the registry published")
            result = scan_archive(archive, ecosystem=eco, name=ref.name, version=ref.version,
                                  quarantine=work, limits=self.limits)
            stats.download_seconds.append(t1 - t0)
            stats.scan_seconds.append(time.perf_counter() - t1)
            self.db.save_result(result, published_at=ref.published_at, artifact=ref.filename)
            stats.scanned += 1
            stats.bump(eco, "scanned")
            stats.levels[result.level] = stats.levels.get(result.level, 0) + 1
            if result.flagged:
                stats.flagged += 1
                stats.bump(eco, "flagged")
                stats.flagged_names.append((eco, ref.name, ref.version, result.score))
                self.log(f"  FLAG {eco:4} {ref.name}=={ref.version} score={result.score} :: "
                         f"{result.explanation[:140]}")
            return "flagged" if result.flagged else "scanned"
        except DownloadTooLarge as exc:
            self.db.save_status(eco, ref.name, ref.version, "skipped", str(exc), artifact=ref.filename)
            stats.skipped += 1
            stats.bump(eco, "skipped")
            return "skipped"
        except ExtractionError as exc:
            self.db.save_status(eco, ref.name, ref.version, "error", f"extraction refused: {exc}",
                                artifact=ref.filename)
            stats.errors += 1
            stats.bump(eco, "errors")
            return "error"
        except (httpx.HTTPError, OSError, DownloadRefused) as exc:
            self.db.save_status(eco, ref.name, ref.version, "error", f"{type(exc).__name__}: {exc}"[:300],
                                artifact=ref.filename)
            stats.errors += 1
            stats.bump(eco, "errors")
            return "error"
        except Exception as exc:  # a bug on one odd release must not stop the watcher
            self.log(f"  ERROR {eco} {ref.name}=={ref.version}: {type(exc).__name__}: {exc}")
            self.db.save_status(eco, ref.name, ref.version, "error",
                                f"internal error: {type(exc).__name__}: {exc}"[:300], artifact=ref.filename)
            stats.errors += 1
            stats.bump(eco, "errors")
            return "error"
        finally:
            remove_tree(work)


def _safe_ext(filename: str) -> str:
    for ext in (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip", ".whl", ".tar"):
        if filename.lower().endswith(ext):
            return ext
    return ".bin"


def live_run(db: Database, *, seconds: float | None = None, ecosystems: tuple[str, ...] = ("pypi", "npm"),
             client: PoliteClient | None = None, quarantine: Path = DEFAULT_QUARANTINE,
             log: Callable[[str], None] = print, clock: Callable[[], float] = time.monotonic,
             sleep: Callable[[float], None] = time.sleep, pypi_poll_every: float = 60.0,
             npm_poll_every: float = 5.0, max_releases: int | None = None, once: bool = False,
             feeds: dict | None = None) -> RunStats:
    """Scan real new releases.

    Stops when ``seconds`` have passed, when ``max_releases`` releases have been
    handled (scanned, skipped or failed), or, with ``once``, after one poll of
    each feed has been worked through. ``feeds`` lets tests pass fakes.
    """
    own_client = client is None
    client = client or PoliteClient(per_host=PER_HOST_INTERVAL)
    pipe = Pipeline(db, client, quarantine=quarantine, log=log)
    if feeds is None:
        feeds = {}
        if "pypi" in ecosystems:
            feeds["pypi"] = PyPIFeed(client, db)
        if "npm" in ecosystems:
            feeds["npm"] = NpmFeed(client, db)
    queues: dict[str, deque] = {k: deque() for k in feeds}
    last_poll: dict[str, float] = {k: -1e9 for k in feeds}
    polled: set[str] = set()
    stats = RunStats()
    deadline = clock() + seconds if seconds is not None else math.inf
    turn = 0
    last_report = 0

    def finished() -> bool:
        if clock() >= deadline:
            return True
        if max_releases is not None and stats.seen >= max_releases:
            return True
        return once and polled == set(feeds) and not any(queues.values())

    try:
        while not finished():
            for eco, feed in feeds.items():
                if once and eco in polled:
                    continue
                gap = pypi_poll_every if eco == "pypi" else npm_poll_every
                if not queues[eco] and clock() - last_poll[eco] >= gap:
                    last_poll[eco] = clock()
                    polled.add(eco)
                    try:
                        found = feed.poll()
                        queues[eco].extend(found)
                        log(f"[{eco}] poll: {len(found)} new candidates")
                    except Exception as exc:  # network, bad XML/JSON, oversized feed: retry next round
                        log(f"[{eco}] poll failed: {type(exc).__name__}: {exc}")
            active = [e for e in feeds if queues[e]]
            if not active:
                if not finished():
                    sleep(1.0)
                continue
            eco = active[turn % len(active)]
            turn += 1
            cand = queues[eco].popleft()
            try:
                ref = feeds[eco].resolve(cand)
                if ref is not None:
                    pipe.process(ref, stats)
            except Exception as exc:  # e.g. 404 for a release deleted since the feed listed it
                stats.errors += 1
                stats.bump(eco, "errors")
                log(f"[{eco}] resolve failed for {getattr(cand, 'name', cand)}: {type(exc).__name__}")
            finally:
                feeds[eco].commit(cand)  # handled either way; resume after it
            if stats.seen and stats.seen % 25 == 0 and stats.seen != last_report:
                last_report = stats.seen
                log(f"... seen={stats.seen} scanned={stats.scanned} flagged={stats.flagged} "
                    f"skipped={stats.skipped} errors={stats.errors}")
    finally:
        if own_client:
            client.close()
    return stats
