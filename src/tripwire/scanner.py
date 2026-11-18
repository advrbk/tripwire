"""The scan pipeline: archive -> quarantine -> Package -> analysers -> score.

Nothing here runs package code. The only things done with package content are
reading bytes, decoding text, ``json.loads``, ``ast.parse`` and regexes.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .analyzers import ANALYZERS
from .loader import load_package
from .models import Evidence, Package, ScanResult
from .quarantine import ExtractionError, Limits, new_quarantine_dir, remove_tree, safe_extract
from .scoring import FLAG_THRESHOLD, score

# Library default: a folder under the system temp dir. (It used to be computed
# from this file's location, which pointed inside site-packages on a normal,
# non-editable install.) The CLI passes ./quarantine or --quarantine instead.
DEFAULT_QUARANTINE = Path(tempfile.gettempdir()) / "tripwire-quarantine"

TRAVERSAL_REASONS = ("path traversal", "absolute path", "drive letter")
COLLISION_REASONS = ("duplicate entry", "name collides")


def analyze_package(pkg: Package) -> ScanResult:
    evidence: list[Evidence] = []
    for analyzer in ANALYZERS:
        try:
            evidence.extend(analyzer.analyze(pkg))
        except RecursionError:
            evidence.append(Evidence(analyzer.name, "analyzer_error", 0.0,
                                     f"{analyzer.name} gave up on deeply nested code."))
        except Exception as exc:  # one analyser failing must not hide the others' findings
            evidence.append(Evidence(analyzer.name, "analyzer_error", 0.0,
                                     f"{analyzer.name} failed: {type(exc).__name__}."))
    evidence.extend(_archive_evidence(pkg))
    value, level, text = score(evidence)
    evidence.sort(key=lambda e: (-e.weight, e.analyzer, e.file or "", e.line or 0))
    return ScanResult(
        ecosystem=pkg.ecosystem, name=pkg.name, version=pkg.version, score=value, level=level,
        flagged=value >= FLAG_THRESHOLD, explanation=text, evidence=evidence,
        file_count=len(pkg.files) + pkg.binary_file_count + len(pkg.unreadable), total_bytes=sum(f.size for f in pkg.files),
    )


def _archive_evidence(pkg: Package) -> list[Evidence]:
    out = []
    escapes = [n for n, r in pkg.blocked_entries if r.startswith(TRAVERSAL_REASONS)]
    links = [n for n, r in pkg.blocked_entries if r in ("symlink", "hard link")]
    collisions = [n for n, r in pkg.blocked_entries if r.startswith(COLLISION_REASONS)]
    if escapes:
        out.append(Evidence("archive", "path_escape", 0.6,
                            f"The archive tries to write outside its own folder ({len(escapes)} entries, "
                            "blocked).", snippet=escapes[0][:160]))
    if links:
        out.append(Evidence("archive", "links", 0.2,
                            f"The archive contains {len(links)} symlink/hard-link entries (not extracted).",
                            snippet=links[0][:160]))
    if collisions:
        out.append(Evidence("archive", "name_collision", 0.2,
                            f"The archive has {len(collisions)} entries whose names repeat or collide on a "
                            "case-insensitive file system. Every copy was analysed; on install the last copy "
                            "wins, so a repeat can swap a file after a quick look.", snippet=collisions[0][:160]))
    if pkg.unreadable:
        out.append(Evidence("archive", "unreadable_files", 0.4,
                            f"{len(pkg.unreadable)} extracted file(s) could not be read back. The OS refused; "
                            "on Windows that usually means antivirus detected and removed them. Those files "
                            "were not analysed.", file=pkg.unreadable[0][:200]))
    return out


def scan_archive(archive: Path, *, ecosystem: str | None = None, name: str | None = None,
                 version: str | None = None, quarantine: Path = DEFAULT_QUARANTINE,
                 limits: Limits = Limits(), keep: bool = False) -> ScanResult:
    """Extract into a fresh quarantine folder, analyse, then delete the folder."""
    work = new_quarantine_dir(quarantine)
    try:
        report = safe_extract(archive, work / "x", limits)
        pkg = load_package(work / "x", report.files, ecosystem=ecosystem or _guess_ecosystem(archive),
                           name=name, version=version, blocked=report.blocked + report.collisions,
                           disk_paths=report.disk_paths)
        return analyze_package(pkg)
    finally:
        if not keep:
            remove_tree(work)


def scan_directory(root: Path, *, ecosystem: str | None = None, name: str | None = None,
                   version: str | None = None) -> ScanResult:
    """Scan an already-unpacked folder in place (read-only, links skipped)."""
    root = root.resolve()
    files: list[str] = []
    blocked: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in list(dirnames):
            full_dir = os.path.join(dirpath, d)
            if _is_link(full_dir):
                # os.walk does not treat NTFS junctions as links, so check them too:
                # a junction can point anywhere on the disk, or back up to a parent.
                blocked.append((os.path.relpath(full_dir, root).replace(os.sep, "/"), "symlink"))
                dirnames.remove(d)
            elif d in (".git", "node_modules", ".venv", "__pycache__"):
                dirnames.remove(d)
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if _is_link(full):
                blocked.append((rel, "symlink"))
                continue
            files.append(rel)
            if len(files) > Limits().max_members:
                raise ExtractionError("too many files")
    pkg = load_package(root, files, ecosystem=ecosystem, name=name, version=version, blocked=blocked)
    return analyze_package(pkg)


def _is_link(path: str) -> bool:
    return os.path.islink(path) or os.path.isjunction(path)


def _guess_ecosystem(archive: Path) -> str | None:
    n = archive.name.lower()
    if n.endswith(".whl"):
        return "pypi"
    if n.endswith(".tgz"):
        return "npm"
    return None  # decided from content (package.json present => npm)
