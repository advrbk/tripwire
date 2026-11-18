"""Core data types shared by every part of Tripwire.

Everything here is plain dataclasses so results can be stored, serialised to
JSON and compared in tests without any framework in the way.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

ECOSYSTEMS = ("pypi", "npm")

# An analyser "fires" on a package when at least one piece of evidence reaches
# this weight. Weaker evidence is still stored and shown, but it is context, not
# a signal on its own.
FIRE_THRESHOLD = 0.30


@dataclass(frozen=True)
class Evidence:
    """One suspicious thing an analyser found, with where it found it."""

    analyzer: str
    rule: str
    weight: float  # 0.0 - 1.0, how strongly this points at malware on its own
    message: str  # plain-English sentence, shown in the feed
    file: str | None = None
    line: int | None = None
    snippet: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PackageFile:
    """A file from an extracted archive. Only text is ever loaded."""

    path: str  # posix path relative to the package root
    text: str  # decoded text (may be truncated to the read limit)
    size: int  # size on disk in bytes
    truncated: bool = False

    @property
    def suffix(self) -> str:
        name = self.path.rsplit("/", 1)[-1]
        return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""

    @property
    def basename(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass
class Package:
    """A release as the analysers see it: metadata plus its text files."""

    ecosystem: str
    name: str
    version: str
    files: list[PackageFile] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    # Paths (relative) that the package manager runs at install time:
    # setup.py, .pth files, files named by npm lifecycle scripts.
    install_files: set[str] = field(default_factory=set)
    # npm lifecycle scripts that run on install: {"postinstall": "node x.js"}
    install_scripts: dict[str, str] = field(default_factory=dict)
    # Entries the safe extractor refused (path traversal, links, ...)
    blocked_entries: list[tuple[str, str]] = field(default_factory=list)
    binary_file_count: int = 0
    # Files that were extracted but could not be read back. On Windows this is
    # usually antivirus removing or locking a file it detected.
    unreadable: list[str] = field(default_factory=list)

    def file(self, path: str) -> PackageFile | None:
        for f in self.files:
            if f.path == path:
                return f
        return None

    def code_files(self) -> list[PackageFile]:
        return [f for f in self.files if f.suffix in CODE_SUFFIXES or f.path in self.install_files]


CODE_SUFFIXES = frozenset(
    {".py", ".pyw", ".pth", ".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx", ".sh", ".bash",
     ".ps1", ".bat", ".cmd", ".vbs", ".pl", ".rb", ".php", ".lua"}
)


@dataclass
class ScanResult:
    ecosystem: str
    name: str
    version: str
    score: int
    level: str
    flagged: bool
    explanation: str
    evidence: list[Evidence]
    file_count: int = 0
    total_bytes: int = 0

    def fired_analyzers(self) -> set[str]:
        return {e.analyzer for e in self.evidence if e.weight >= FIRE_THRESHOLD}

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fired_analyzers"] = sorted(self.fired_analyzers())
        return d


@dataclass(frozen=True)
class ReleaseRef:
    """A pointer to a release found on a public feed, before download."""

    ecosystem: str
    name: str
    version: str
    artifact_url: str
    filename: str
    size: int | None = None
    sha256: str | None = None  # PyPI publishes sha256 digests
    integrity: str | None = None  # npm publishes SRI strings ("sha512-...")
    published_at: str | None = None
    new_package: bool = False

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"
