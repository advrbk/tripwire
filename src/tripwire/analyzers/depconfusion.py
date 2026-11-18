"""Dependency-confusion signs.

The classic attack publishes a public package with the same name as a
company's private one and a huge version number (``99.0.0``), so build tools
that check both registries pick the public copy. A static scan cannot know
private names, so the rule is: absurd version + a name that is not a known
popular package. Calendar versions (``2024.11.5``) and date stamps are exempt.
"""

from __future__ import annotations

import re
from datetime import date

from ..models import Evidence, Package
from .base import ev
from .typosquat import normalize, popular

NAME = "depconfusion"
INTERNAL_HINT = re.compile(r"(?:^|[-_.@/])(internal|private|corp|intranet|infra|platform|core-lib|sdk)(?:$|[-_./])", re.I)


def major_version(version: str) -> int | None:
    m = re.match(r"^\s*v?(\d+)", version or "")
    return int(m.group(1)) if m else None


def is_calendar_major(major: int) -> bool:
    if 1990 <= major <= 2100:
        return True  # YYYY.x calendar versioning
    s = str(major)
    if len(s) == 8:  # YYYYMMDD
        try:
            date(int(s[:4]), int(s[4:6]), int(s[6:]))
            return True
        except ValueError:
            return False
    if len(s) == 6 and 1990 <= int(s[:4]) <= 2100 and 1 <= int(s[4:]) <= 12:
        return True  # YYYYMM
    return False


class DepConfusionAnalyzer:
    name = NAME

    def analyze(self, pkg: Package) -> list[Evidence]:
        major = major_version(pkg.version)
        if major is None or major < 99 or is_calendar_major(major):
            return []
        if normalize(pkg.name, pkg.ecosystem) in popular(pkg.ecosystem):
            return []
        weight = 0.55 if major >= 1000 else 0.45
        out = [ev(NAME, "absurd_version", weight,
                  f"Version {pkg.version} is far above normal numbering on a little-known name, the pattern "
                  "used to win dependency-confusion races against private packages.", None, None,
                  f"{pkg.name}=={pkg.version}")]
        if INTERNAL_HINT.search(pkg.name):
            out.append(ev(NAME, "internal_sounding_name", 0.2,
                          f"Name '{pkg.name}' sounds like a company-internal package.", None, None, pkg.name))
        desc = (pkg.metadata.get("description") or pkg.metadata.get("summary") or "").strip()
        if not desc and not pkg.metadata.get("repository") and not pkg.metadata.get("home-page"):
            out.append(ev(NAME, "empty_metadata", 0.15,
                          "No description, homepage or repository, typical of placeholder confusion packages.",
                          None, None, None))
        return out
