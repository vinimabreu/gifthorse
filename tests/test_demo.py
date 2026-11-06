"""The README pastes the demo output and the test count; keep both honest."""

from __future__ import annotations

import re
import subprocess
import sys

from examples.demo import hero_output

from .conftest import ROOT


def _hero_block() -> str:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"<!-- hero:start -->\n```text\n(.*?)```\n<!-- hero:end -->", text, re.DOTALL)
    assert match is not None, "README is missing the hero block markers"
    return match.group(1)


def test_readme_hero_block_matches_the_demo_output() -> None:
    assert _hero_block() == hero_output()


def test_demo_runs_as_a_script_and_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "examples" / "demo.py")],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == hero_output()


def test_readme_test_badge_matches_the_collected_count() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    badge = re.search(r"tests-(\d+)%20passing", text)
    assert badge is not None
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    per_file = re.findall(r"^tests/\S+: (\d+)$", result.stdout, re.MULTILINE)
    assert per_file, result.stdout[-500:]
    assert int(badge.group(1)) == sum(int(n) for n in per_file)
