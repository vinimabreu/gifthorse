"""The README and the docs quote the code and the measured results; keep them honest."""

from __future__ import annotations

import json
import re

from gifthorse import registry

from .conftest import ROOT

README = ROOT / "README.md"


def _between(text: str, name: str) -> str:
    match = re.search(rf"<!-- {name}:start -->\n?(.*?)\n?<!-- {name}:end -->", text, re.DOTALL)
    assert match is not None, f"README is missing the {name} markers"
    return match.group(1)


def test_readme_family_table_matches_the_registry() -> None:
    rows = [
        line
        for line in _between(README.read_text(encoding="utf-8"), "families").splitlines()
        if line.startswith("| ") and not line.startswith("| Family")
    ]
    quoted = {
        cells[0]: sorted(rule.strip() for rule in cells[1].split(","))
        for cells in ([c.strip() for c in row.strip("|").split("|")] for row in rows)
    }
    families: dict[str, list[str]] = {}
    for rule in registry.all_rules():
        families.setdefault(rule.family, []).append(rule.id)
    assert quoted == {family: sorted(ids) for family, ids in families.items()}


def test_readme_benchmark_numbers_match_the_results_file() -> None:
    summary = json.loads((ROOT / "benchmark" / "results.json").read_text(encoding="utf-8"))
    counts = summary["verdicts"]
    expected = (
        f"{counts.get('NO FINDINGS', 0)} NO FINDINGS, {counts.get('REVIEW', 0)} REVIEW "
        f"and {counts.get('BLOCK', 0)} BLOCK"
    )
    text = README.read_text(encoding="utf-8")
    assert _between(text, "bench") == expected
    assert f"list of {summary['packages']} popular" in text
    manifest = json.loads((ROOT / "benchmark" / "manifest.json").read_text(encoding="utf-8"))
    assert summary["packages"] == len(manifest) and summary["missing"] == 0


def test_benchmark_results_carry_no_evidence_text() -> None:
    summary = json.loads((ROOT / "benchmark" / "results.json").read_text(encoding="utf-8"))
    for row in summary["results"]:
        for finding in row["findings"]:
            assert set(finding) == {"rule", "severity", "path"}, row["name"]


def test_json_doc_example_is_the_real_demo_report_abridged() -> None:
    from examples.demo import sample_zip

    from gifthorse import scan_bytes

    text = (ROOT / "docs" / "JSON.md").read_text(encoding="utf-8")
    match = re.search(r"```json\n(.*?)```", text, re.DOTALL)
    assert match is not None
    example = json.loads(match.group(1))
    real = scan_bytes("brief.zip", sample_zip()).to_dict()
    assert list(example) == list(real)
    real_findings = {f["rule"]: f for f in real["findings"]}
    for finding in example["findings"]:
        assert finding == real_findings[finding["rule"]]
    for key in (
        "schema",
        "targets",
        "unreadable",
        "verdict",
        "indicators",
        "coverage",
        "counts",
        "limits",
    ):
        assert example[key] == real[key], key
