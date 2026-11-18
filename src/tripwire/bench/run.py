"""Run the labelled corpus through the real scanner and score the rules.

Per analyser:
  TP = fixture written to show that category, and the analyser fired
  FN = fixture written to show that category, and the analyser stayed quiet
  FP = fixture NOT written to show that category (benign or another
       category), and the analyser fired anyway

"Fired" means at least one finding of weight >= 0.30 (FIRE_THRESHOLD), the
same definition the dashboard uses. Overall numbers use the real flag line
(score >= 50) against the malicious / benign label.
"""

from __future__ import annotations

import csv
import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from ..analyzers import ANALYZER_NAMES
from ..models import FIRE_THRESHOLD, ScanResult
from ..scanner import scan_archive
from ..scoring import FLAG_THRESHOLD
from .archive import build
from .corpus import BENIGN, CATEGORIES, FIXTURES, MALICIOUS, Fixture


@dataclass
class Outcome:
    fixture: Fixture
    result: ScanResult
    seconds: float

    @property
    def fired(self) -> set[str]:
        return self.result.fired_analyzers() & set(ANALYZER_NAMES)


def scan_fixture(fx: Fixture, workdir: Path) -> Outcome:
    filename, data = build(fx)
    folder = workdir / fx.id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / filename
    path.write_bytes(data)
    t0 = time.perf_counter()
    result = scan_archive(path, ecosystem=fx.ecosystem, name=fx.name, version=fx.version,
                          quarantine=workdir / "_q")
    return Outcome(fx, result, time.perf_counter() - t0)


def run_corpus(fixtures: list[Fixture] | None = None) -> list[Outcome]:
    fixtures = FIXTURES if fixtures is None else fixtures
    with tempfile.TemporaryDirectory(prefix="tripwire-bench-") as tmp:
        return [scan_fixture(fx, Path(tmp)) for fx in fixtures]


def prf(tp: int, fp: int, fn: int) -> tuple[float | None, float | None, float | None]:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    return p, r, f


def metrics(outcomes: list[Outcome]) -> dict:
    per: dict[str, dict] = {}
    for a in CATEGORIES:
        tp = sum(1 for o in outcomes if a in o.fixture.signals and a in o.fired)
        fn = sum(1 for o in outcomes if a in o.fixture.signals and a not in o.fired)
        fp = sum(1 for o in outcomes if a not in o.fixture.signals and a in o.fired)
        p, r, f = prf(tp, fp, fn)
        per[a] = {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f}

    def overall(threshold: int) -> dict:
        tp = sum(1 for o in outcomes if o.fixture.label == MALICIOUS and o.result.score >= threshold)
        fn = sum(1 for o in outcomes if o.fixture.label == MALICIOUS and o.result.score < threshold)
        fp = sum(1 for o in outcomes if o.fixture.label == BENIGN and o.result.score >= threshold)
        p, r, f = prf(tp, fp, fn)
        return {"threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f}

    times = sorted(o.seconds for o in outcomes)
    return {
        "fixtures": len(outcomes),
        "malicious": sum(1 for o in outcomes if o.fixture.label == MALICIOUS),
        "benign": sum(1 for o in outcomes if o.fixture.label == BENIGN),
        "per_analyzer": per,
        "overall": overall(FLAG_THRESHOLD),
        "sweep": [overall(t) for t in (20, 35, 50, 70, 85)],
        "scan_ms_p50": round(times[len(times) // 2] * 1000, 1) if times else None,
        "false_positives": [_fp_row(o, a) for o in outcomes for a in sorted(o.fired - o.fixture.signals)],
        "benign_flagged": [_case(o) for o in outcomes if o.fixture.label == BENIGN and o.result.flagged],
        "malicious_missed": [_case(o) for o in outcomes if o.fixture.label == MALICIOUS and not o.result.flagged],
        "category_misses": [{"id": o.fixture.id, "analyzer": a, "score": o.result.score}
                            for o in outcomes for a in sorted(o.fixture.signals - o.fired)],
    }


def _fp_row(o: Outcome, analyzer: str) -> dict:
    top = max((e for e in o.result.evidence if e.analyzer == analyzer and e.weight >= FIRE_THRESHOLD),
              key=lambda e: e.weight)
    return {"id": o.fixture.id, "label": o.fixture.label, "analyzer": analyzer, "rule": top.rule,
            "weight": top.weight, "score": o.result.score, "message": top.message}


def _case(o: Outcome) -> dict:
    return {"id": o.fixture.id, "score": o.result.score, "level": o.result.level,
            "fired": sorted(o.fired), "note": o.fixture.note}


def _pct(x: float | None) -> str:
    return "  -  " if x is None else f"{x:5.2f}"


def format_report(m: dict) -> str:
    lines = [
        f"Tripwire benchmark: {m['fixtures']} fixtures ({m['malicious']} malicious-signal, {m['benign']} benign)",
        "Self-made, inert corpus: these numbers show the rules work as designed, not real-world detection rates.",
        "",
        f"{'analyser':<15}{'TP':>4}{'FP':>4}{'FN':>4}  {'prec':>5}  {'recall':>6}  {'F1':>5}",
        "-" * 50,
    ]
    for a, r in m["per_analyzer"].items():
        lines.append(f"{a:<15}{r['tp']:>4}{r['fp']:>4}{r['fn']:>4}  {_pct(r['precision'])}  "
                     f"{_pct(r['recall']):>6}  {_pct(r['f1'])}")
    o = m["overall"]
    lines += ["-" * 50,
              f"{'overall (>=' + str(o['threshold']) + ')':<15}{o['tp']:>4}{o['fp']:>4}{o['fn']:>4}  "
              f"{_pct(o['precision'])}  {_pct(o['recall']):>6}  {_pct(o['f1'])}",
              "", "Flag-line sweep (malicious vs benign):",
              f"  {'score >=':<9}{'TP':>4}{'FP':>4}{'FN':>4}  {'prec':>5}  {'recall':>6}"]
    for s in m["sweep"]:
        lines.append(f"  {s['threshold']:<9}{s['tp']:>4}{s['fp']:>4}{s['fn']:>4}  {_pct(s['precision'])}  "
                     f"{_pct(s['recall']):>6}")
    lines += ["", f"Median scan time per fixture: {m['scan_ms_p50']} ms", "",
              "False positives (analyser fired on a fixture not written for its category):"]
    for fp in m["false_positives"] or [{"id": "none"}]:
        if fp["id"] == "none":
            lines.append("  none")
            continue
        lines.append(f"  [{fp['label']}] {fp['id']}: {fp['analyzer']}/{fp['rule']} w={fp['weight']:.2f} "
                     f"(score {fp['score']})")
    lines += ["", "Benign fixtures over the flag line:"]
    lines += [f"  {c['id']}: score {c['score']} ({', '.join(c['fired'])})" for c in m["benign_flagged"]] or ["  none"]
    lines += ["", "Malicious-signal fixtures under the flag line:"]
    lines += [f"  {c['id']}: score {c['score']} fired={','.join(c['fired']) or '-'}"
              + (f"  [{c['note']}]" if c["note"] else "") for c in m["malicious_missed"]] or ["  none"]
    return "\n".join(lines)


def write_labels(path: Path) -> None:
    """A CSV index of the corpus: id, ecosystem, label, signal categories, note."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "ecosystem", "kind", "package", "version", "label", "signals", "note"])
        for fx in FIXTURES:
            w.writerow([fx.id, fx.ecosystem, fx.kind, fx.name, fx.version, fx.label,
                        " ".join(sorted(fx.signals)), fx.note])


def write_corpus(folder: Path) -> int:
    """Write every fixture as an archive file, for inspection. Returns the count."""
    for fx in FIXTURES:
        filename, data = build(fx)
        d = folder / fx.label / fx.id
        d.mkdir(parents=True, exist_ok=True)
        (d / filename).write_bytes(data)
    return len(FIXTURES)


def main(as_json: bool = False, corpus_dir: Path | None = None, labels: Path | None = None,
         out=print) -> dict:
    if corpus_dir is not None:
        out(f"wrote {write_corpus(corpus_dir)} fixture archives to {corpus_dir}")
    if labels is not None:
        write_labels(labels)
    m = metrics(run_corpus())
    out(json.dumps(m, indent=2) if as_json else format_report(m))
    return m
