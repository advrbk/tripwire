"""Combine evidence into one 0-100 risk score and a short explanation.

How the number is built:

1. Inside one analyser, each rule counts once (its strongest hit), so a big
   package with the same weak pattern in 200 files does not pile up points.
   Evidence under 0.2 is context only and adds nothing.
2. Rules combine with a "noisy OR": ``1 - (1-a)(1-b)...``. Two independent
   0.5 signals give 0.75, never more than 1.
3. Analysers combine the same way.
4. Some pairs are much worse together than apart (reads secrets *and* has a
   webhook; runs at install *and* has a look-alike name). Those add a bonus.
"""

from __future__ import annotations

from collections import defaultdict

from .models import FIRE_THRESHOLD, Evidence

FLAG_THRESHOLD = 50
CONTEXT_ONLY = 0.2

COMBOS: list[tuple[frozenset[str], float, str]] = [
    (frozenset({"credentials", "network"}), 0.20,
     "It reads secrets and also contains a place to send them."),
    (frozenset({"depconfusion", "install_hooks"}), 0.20,
     "A dependency-confusion style version that also runs code during install."),
    (frozenset({"install_hooks", "credentials"}), 0.15,
     "Code that runs during install sits next to reads of secrets."),
    (frozenset({"typosquat", "install_hooks"}), 0.15,
     "A look-alike name that also runs code during install."),
    (frozenset({"install_hooks", "obfuscation"}), 0.10,
     "The install-time code is hidden behind encoding."),
    (frozenset({"install_hooks", "network"}), 0.10,
     "Install-time code next to an unusual network destination."),
    (frozenset({"typosquat", "network"}), 0.10,
     "A look-alike name with an unusual network destination."),
    (frozenset({"typosquat", "credentials"}), 0.10,
     "A look-alike name that also reads secrets."),
]


def level_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= FLAG_THRESHOLD:
        return "medium"
    if score >= 20:
        return "low"
    return "none"


def analyzer_strengths(evidence: list[Evidence]) -> dict[str, float]:
    best: dict[tuple[str, str], float] = {}
    for e in evidence:
        k = (e.analyzer, e.rule)
        best[k] = max(best.get(k, 0.0), e.weight)
    per: dict[str, float] = defaultdict(lambda: 1.0)
    for (analyzer, _rule), w in best.items():
        if w >= CONTEXT_ONLY:
            per[analyzer] *= 1.0 - min(w, 0.97)
    return {a: round(1.0 - keep, 4) for a, keep in per.items()}


def score(evidence: list[Evidence]) -> tuple[int, str, str]:
    """Return (score 0-100, level, explanation)."""
    strengths = analyzer_strengths(evidence)
    keep = 1.0
    for s in strengths.values():
        keep *= 1.0 - s
    base = 1.0 - keep
    fired = {e.analyzer for e in evidence if e.weight >= FIRE_THRESHOLD}
    combos = [(bonus, text) for need, bonus, text in COMBOS if need <= fired]
    total = min(1.0, base + sum(b for b, _ in combos))
    value = int(round(total * 100))
    level = level_for(value)
    return value, level, explain(value, level, evidence, strengths, [t for _, t in combos])


def explain(value: int, level: str, evidence: list[Evidence], strengths: dict[str, float],
            combo_texts: list[str]) -> str:
    if value == 0 or not strengths:
        return "No suspicious signals found."
    top = sorted(strengths.items(), key=lambda kv: -kv[1])
    parts = []
    for analyzer, _s in top[:3]:
        strongest = max((e for e in evidence if e.analyzer == analyzer), key=lambda e: e.weight)
        parts.append(strongest.message.rstrip(".") + ".")
    if combo_texts:
        parts.append(combo_texts[0])
    head = f"Risk {value}/100 ({level})."
    if value < FLAG_THRESHOLD:
        head += " Below the flag line; shown for context."
    return " ".join([head] + parts)
