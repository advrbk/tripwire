"""Run the Tripwire benchmark and refresh the files in this folder.

    python benchmark/run_benchmark.py            # print the report, refresh labels.csv and results.txt
    python benchmark/run_benchmark.py --corpus   # also write every fixture archive to benchmark/corpus/

Same as ``tripwire bench``. The corpus itself lives in
``src/tripwire/bench/corpus.py`` so the CLI and the tests can use it; this
script only writes outputs next to itself:

* ``labels.csv``  - one row per fixture: id, ecosystem, label, signal categories, note
* ``results.txt`` - the report printed below
* ``corpus/``     - (optional, git-ignored) the archives, for poking at by hand

The corpus is self-made and inert. The numbers show the rules behave as
designed on these cases; they are not real-world detection rates.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", action="store_true", help="also write fixture archives to benchmark/corpus/")
    args = ap.parse_args()

    from tripwire.bench.run import main as bench_main

    lines: list[str] = []
    bench_main(corpus_dir=HERE / "corpus" if args.corpus else None, labels=HERE / "labels.csv",
               out=lines.append)
    report = "\n".join(lines)
    (HERE / "results.txt").write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
