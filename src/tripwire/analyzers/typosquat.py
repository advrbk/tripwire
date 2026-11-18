"""Names built to be mistaken for popular packages.

Compared against a bundled list of popular names per ecosystem. Checks, from
strongest to weakest: look-alike characters (``rn`` for ``m``, ``0`` for
``o``), dropped separators (``crossenv`` for ``cross-env``), one-edit typos
(swapped, doubled, missing or keyboard-neighbour letters), two-edit typos on
long names, and bolted-on affixes (``requests-py``).
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources

from ..models import Evidence, Package
from .base import ev

NAME = "typosquat"

KEYBOARD_ROWS = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
# Single characters are mapped first, then pairs, and both names get the same
# treatment, so "c1ick" and "click" end up as the same canonical string.
HOMOGLYPH_CHARS = str.maketrans({"0": "o", "1": "l", "i": "l", "5": "s", "3": "e", "4": "a", "7": "t", "8": "b"})
HOMOGLYPH_PAIRS = [("rn", "m"), ("vv", "w"), ("cl", "d")]
AFFIXES_SUFFIX = ("-py", "py", "-python", "-js", "js", "-node", "2", "3", "-dev", "-lib", "-sdk", "-utils",
                  "-official", "-secure")
AFFIXES_PREFIX = ("py", "python-", "py-", "node-", "js-", "the-", "real-", "official-")


def normalize(name: str, ecosystem: str) -> str:
    name = name.strip().lower()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name)  # PEP 503
    return name


@lru_cache(maxsize=4)
def popular(ecosystem: str) -> tuple[str, ...]:
    text = resources.files("tripwire.data").joinpath(f"popular_{ecosystem}.txt").read_text(encoding="utf-8")
    seen: dict[str, None] = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            seen.setdefault(normalize(line, ecosystem), None)
    return tuple(seen)


@lru_cache(maxsize=1)
def _neighbours() -> dict[str, set[str]]:
    pos = {c: (r, i) for r, row in enumerate(KEYBOARD_ROWS) for i, c in enumerate(row)}
    out: dict[str, set[str]] = {c: set() for c in pos}
    for a, (ra, ia) in pos.items():
        for b, (rb, ib) in pos.items():
            if a != b and abs(ra - rb) <= 1 and abs(ia - ib) <= 1:
                out[a].add(b)
    return out


def osa_distance(a: str, b: str, cap: int = 3) -> int:
    """Optimal string alignment distance (Levenshtein + adjacent swaps)."""
    if abs(len(a) - len(b)) >= cap:
        return cap
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) >= cap:
            return cap
        prev2, prev = prev, cur
    return min(prev[-1], cap)


def describe_single_edit(cand: str, target: str) -> tuple[str, float]:
    """Name the kind of one-character typo and how deliberate it looks."""
    if len(cand) == len(target):
        diffs = [i for i, (x, y) in enumerate(zip(cand, target)) if x != y]
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            return "two letters swapped", 0.65
        if len(diffs) == 1:
            x, y = cand[diffs[0]], target[diffs[0]]
            if x in _neighbours().get(y, set()):
                return f"'{y}' replaced by the keyboard neighbour '{x}'", 0.65
            return f"'{y}' replaced by '{x}'", 0.55
    if len(cand) == len(target) + 1:
        for i in range(len(cand)):
            if cand[:i] + cand[i + 1:] == target:
                if (i > 0 and cand[i] == cand[i - 1]) or (i + 1 < len(cand) and cand[i] == cand[i + 1]):
                    return f"letter '{cand[i]}' doubled", 0.6
                return f"extra letter '{cand[i]}'", 0.55
    if len(cand) + 1 == len(target):
        for i in range(len(target)):
            if target[:i] + target[i + 1:] == cand:
                return f"letter '{target[i]}' left out", 0.6
    return "one character changed", 0.55


def _deglyph(s: str) -> str:
    s = s.translate(HOMOGLYPH_CHARS)
    for fake, real in HOMOGLYPH_PAIRS:
        s = s.replace(fake, real)
    return s


def _has_glyph_trick(cand: str, target: str) -> bool:
    """The candidate uses a substitute the target does not (digits, rn, vv...)."""
    return any(c.isdigit() for c in cand if c not in target) or any(
        fake in cand and fake not in target for fake, _ in HOMOGLYPH_PAIRS) or (
        cand.count("i") != target.count("i"))


def _strip_seps(s: str) -> str:
    return re.sub(r"[-_.]", "", s)


def find_squat_target(name: str, ecosystem: str) -> tuple[str, str, float] | None:
    """Return (popular target, reason, weight) for the closest match, or None."""
    cand = normalize(name, ecosystem)
    targets = popular(ecosystem)
    if cand in targets:
        return None
    scoped = cand.startswith("@")
    best: tuple[str, str, float] | None = None
    for target in targets:
        if target.startswith("@") != scoped or len(target) < 4:
            continue
        hit = _compare(cand, target)
        if hit and (best is None or hit[1] > best[2]):
            best = (target, hit[0], hit[1])
    return best


def _compare(cand: str, target: str) -> tuple[str, float] | None:
    if cand != target and _deglyph(cand) == _deglyph(target) and _has_glyph_trick(cand, target):
        return "uses look-alike characters", 0.7
    if _strip_seps(cand) == _strip_seps(target):
        return "same letters with separators removed or added", 0.6
    if len(target) >= 5:
        d = osa_distance(cand, target)
        if d == 1:
            return describe_single_edit(cand, target)
        if d == 2 and len(target) >= 9:
            return "two characters changed", 0.4
    for suf in AFFIXES_SUFFIX:
        if cand == target + suf:
            return f"popular name with '{suf}' added", 0.35
    for pre in AFFIXES_PREFIX:
        if cand == pre + target:
            return f"popular name with '{pre}' added", 0.35
    return None


class TyposquatAnalyzer:
    name = NAME

    def analyze(self, pkg: Package) -> list[Evidence]:
        hit = find_squat_target(pkg.name, pkg.ecosystem)
        if hit is None:
            return []
        target, reason, weight = hit
        return [ev(NAME, "name_lookalike", weight,
                   f"Name '{pkg.name}' looks like the popular package '{target}' ({reason}).",
                   None, None, f"{pkg.name} ~ {target}")]
