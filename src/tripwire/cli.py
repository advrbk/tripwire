"""Command line: ``tripwire scan | watch | serve | bench``.

Exit codes for ``scan``: 0 = below the flag line, 1 = flagged, 2 = could not
scan (bad archive, refused by the extractor, missing path). That makes it
usable as a CI gate: ``tripwire scan dist/*.tar.gz || exit 1``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import unicodedata
from pathlib import Path

from . import __version__
from .models import ScanResult
from .quarantine import ExtractionError
from .scoring import FLAG_THRESHOLD

DEFAULT_DB = Path(os.environ.get("TRIPWIRE_DB", "data/tripwire.db"))
DEFAULT_QUARANTINE = Path(os.environ.get("TRIPWIRE_QUARANTINE", "quarantine"))
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".whl", ".zip", ".tar", ".tar.bz2", ".tar.xz")


def safe_text(s: object) -> str:
    """Make untrusted text safe to print to a terminal.

    Package names, paths and snippets come from archives. Control characters
    (ANSI escapes like ESC[2J, carriage returns that overwrite a line, bidi
    overrides) are replaced so a crafted file cannot rewrite the report.
    """
    out = []
    for ch in str(s):
        cat = unicodedata.category(ch)
        if ch == "\n":
            out.append(" ")
        elif cat in ("Cc", "Cf") or cat.startswith("Z") and ch != " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


# ------------------------------------------------------------------- scan

def format_result(r: ScanResult, show_all: bool = False) -> str:
    flag = "FLAGGED" if r.flagged else "not flagged"
    lines = [
        f"{safe_text(r.name)} {safe_text(r.version)} ({r.ecosystem})",
        f"Risk {r.score}/100  {r.level.upper()}  [{flag}; flag line is {FLAG_THRESHOLD}]",
        f"{r.file_count} files, {r.total_bytes:,} bytes of text read",
        "",
        safe_text(r.explanation),
    ]
    shown = [e for e in r.evidence if show_all or e.weight >= 0.2]
    hidden = len(r.evidence) - len(shown)
    if shown:
        lines += ["", "Evidence (strongest first):"]
        for e in shown:
            where = ""
            if e.file:
                where = f"  {safe_text(e.file)}" + (f":{e.line}" if e.line else "")
            lines.append(f"  {e.weight:4.2f}  {e.analyzer}/{e.rule}{where}")
            lines.append(f"        {safe_text(e.message)}")
            if e.snippet:
                lines.append(f"        > {safe_text(e.snippet)}")
    if hidden:
        lines.append(f"\n({hidden} context-only finding{'s' if hidden != 1 else ''} under 0.20 hidden; "
                     "use --all to show)")
    return "\n".join(lines)


def cmd_scan(args: argparse.Namespace) -> int:
    from .scanner import scan_archive, scan_directory

    target = Path(args.path)
    try:
        if target.is_dir():
            result = scan_directory(target, ecosystem=args.ecosystem, name=args.name, version=args.pkg_version)
        elif target.is_file():
            result = scan_archive(target, ecosystem=args.ecosystem, name=args.name, version=args.pkg_version,
                                  quarantine=Path(args.quarantine))
        else:
            print(f"tripwire: no such file or directory: {target}", file=sys.stderr)
            return 2
    except ExtractionError as exc:
        print(f"tripwire: refused to extract {target.name}: {safe_text(exc)}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_result(result, show_all=args.all))
    return 1 if result.flagged else 0


# ------------------------------------------------------------------ watch

def cmd_watch(args: argparse.Namespace) -> int:
    from .db import Database
    from .pipeline import live_run

    if args.limit is not None and args.limit < 1:
        print("tripwire: --limit must be at least 1", file=sys.stderr)
        return 2
    db = Database(args.db)
    ecos = tuple(args.ecosystem or ("pypi", "npm"))
    seconds = args.minutes * 60 if args.minutes else None
    print(f"Watching {', '.join(ecos)} -> {args.db}"
          + (f", up to {args.limit} releases" if args.limit else "")
          + (f", for {args.minutes:g} min" if args.minutes else "")
          + (", one poll" if args.once else "") + ". Ctrl+C to stop.")
    stats = None
    try:
        stats = live_run(db, seconds=seconds, ecosystems=ecos, quarantine=Path(args.quarantine),
                         max_releases=args.limit, once=args.once, log=lambda m: print(safe_text(m)))
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        db.close()
    if stats is None:
        return 0
    summary = stats.summary()
    print()
    print(format_watch_summary(summary))
    if args.stats_json:
        Path(args.stats_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.stats_json).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


def format_watch_summary(s: dict) -> str:
    sc, dl = s["scan_ms"], s["download_ms"]
    lines = [
        f"seen {s['seen']}  scanned {s['scanned']}  flagged {s['flagged']}  skipped {s['skipped']}  "
        f"errors {s['errors']}  duplicates {s['duplicates']}",
        "levels: " + (", ".join(f"{k} {v}" for k, v in s["levels"].items()) or "-"),
        f"scan time per release (extract + analyse): p50 {sc['p50']} ms, p95 {sc['p95']} ms, max {sc['max']} ms",
        f"download time per release: p50 {dl['p50']} ms, p95 {dl['p95']} ms",
    ]
    for eco, e in s["by_ecosystem"].items():
        lines.append(f"  {eco}: " + ", ".join(f"{k} {v}" for k, v in e.items()))
    return "\n".join(lines)


# ------------------------------------------------------------------ serve

def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .web.app import create_app

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: the dashboard has no login; anyone who can reach this address can read it.",
              file=sys.stderr)
    uvicorn.run(create_app(args.db), host=args.host, port=args.port, log_level="warning")
    return 0


# ------------------------------------------------------------------ bench

def cmd_bench(args: argparse.Namespace) -> int:
    from .bench.run import main as bench_main

    bench_main(as_json=args.json, corpus_dir=Path(args.write_corpus) if args.write_corpus else None,
               labels=Path(args.labels) if args.labels else None)
    return 0


# ------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tripwire", description="Static triage of new PyPI and npm releases. "
                                "Package code is parsed as text, never run.")
    p.add_argument("--version", action="version", version=f"tripwire {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a local folder or archive (.tar.gz, .tgz, .whl, .zip)")
    s.add_argument("path")
    s.add_argument("--json", action="store_true", help="print the result as JSON")
    s.add_argument("--all", action="store_true", help="also show context-only findings")
    s.add_argument("--ecosystem", choices=("pypi", "npm"), help="override detection (default: from content)")
    s.add_argument("--name", help="package name to use (default: from metadata)")
    s.add_argument("--pkg-version", help="version to use (default: from metadata)")
    s.add_argument("--quarantine", default=str(DEFAULT_QUARANTINE),
                   help="folder for temporary extraction (default: ./quarantine)")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="scan new releases from the live PyPI and npm feeds")
    w.add_argument("--db", default=str(DEFAULT_DB), help="SQLite file (default: data/tripwire.db)")
    w.add_argument("--quarantine", default=str(DEFAULT_QUARANTINE))
    w.add_argument("--limit", type=int, help="stop after this many releases")
    w.add_argument("--once", action="store_true", help="poll each feed once, scan what it listed, then stop")
    w.add_argument("--minutes", type=float, help="stop after this many minutes")
    w.add_argument("--ecosystem", action="append", choices=("pypi", "npm"),
                   help="limit to one ecosystem (repeatable; default both)")
    w.add_argument("--stats-json", help="also write the run summary to this JSON file")
    w.set_defaults(func=cmd_watch)

    v = sub.add_parser("serve", help="run the dashboard")
    v.add_argument("--db", default=str(DEFAULT_DB))
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8000)
    v.set_defaults(func=cmd_serve)

    b = sub.add_parser("bench", help="run the labelled benchmark corpus")
    b.add_argument("--json", action="store_true")
    b.add_argument("--write-corpus", metavar="DIR", help="also write the fixture archives to DIR")
    b.add_argument("--labels", metavar="CSV", help="also write the label index to CSV")
    b.set_defaults(func=cmd_bench)
    return p


def main(argv: list[str] | None = None) -> int:
    # Untrusted text must not crash a cp1252 Windows console.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
