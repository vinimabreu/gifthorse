"""Run gifthorse over the benchmark corpus and write the results summary.

The corpus is data only: gifthorse reads each archive in memory and never
extracts, installs or runs anything. Run it with ``python -I`` from outside the
corpus folder; the package is imported from the source folder given first.
Not part of the package; standard library only.

    python -I benchmark/run_bench.py src benchmark/manifest.json \\
        benchmark/corpus benchmark/results.json

The summary lists, per package, the verdict and each finding above info by
rule, severity and member path. It carries no evidence text from the packages.
"""

from __future__ import annotations

import collections
import json
import sys
import time
from pathlib import Path
from typing import Any, TypedDict, cast


class Record(TypedDict):
    """One corpus file: what it is, where it came from, and its SHA-256."""

    ecosystem: str
    name: str
    version: str
    url: str
    sha256: str


def corpus_file(corpus: Path, record: Record) -> Path:
    if record["ecosystem"] == "npm":
        return corpus / "npm" / f"{record['name'].replace('/', '__')}-{record['version']}.tgz"
    return corpus / "pypi" / record["url"].rsplit("/", 1)[-1]


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    src, manifest_path, corpus, out_path = (Path(arg).resolve() for arg in argv)
    sys.path.insert(0, str(src))
    import gifthorse

    records = cast(list[Record], json.loads(manifest_path.read_text(encoding="utf-8")))
    rows: list[dict[str, Any]] = []
    verdicts: collections.Counter[str] = collections.Counter()
    rule_hits: collections.Counter[str] = collections.Counter()
    missing = 0
    started = time.perf_counter()
    for record in records:
        path = corpus_file(corpus, record)
        if not path.is_file():
            missing += 1
            print(f"{'MISSING':12} {record['ecosystem']:5} {record['name']}", flush=True)
            continue
        report = gifthorse.scan_path(path)
        verdict = report.verdict.value
        counted = sorted(
            (f for f in report.findings if f.severity.value != "info"),
            key=lambda f: (f.path, f.rule_id),
        )
        for finding in counted:
            rule_hits[finding.rule_id] += 1
        verdicts[verdict] += 1
        rows.append(
            {
                "ecosystem": record["ecosystem"],
                "name": record["name"],
                "version": record["version"],
                "verdict": verdict,
                "findings": [
                    {"rule": f.rule_id, "severity": f.severity.value, "path": f.path}
                    for f in counted
                ],
            }
        )
        print(f"{verdict:12} {record['ecosystem']:5} {record['name']}", flush=True)
    elapsed = time.perf_counter() - started
    summary = {
        "packages": len(rows),
        "missing": missing,
        "verdicts": dict(sorted(verdicts.items())),
        "rule_hits": dict(sorted(rule_hits.items())),
        "results": rows,
    }
    out_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"\n{len(rows)} packages in {elapsed:.1f}s: {dict(sorted(verdicts.items()))}")
    print(f"rule hits above info: {dict(sorted(rule_hits.items()))}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
