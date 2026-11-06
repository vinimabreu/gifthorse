"""Disable one rule at a time and check that the test suite notices.

For every rule id in the registry, the full suite runs with that rule turned
into a no-op through the test-only seam in ``tests/conftest.py`` (the
``GIFTHORSE_TEST_DISABLE_RULE`` variable). A rule is "killed" when at least one
test fails without it. A rule that survives is a rule no test protects.

Stdlib only, and not part of the package. Run from the repository root:

    PYTHONPATH=src python tools/mutation_check.py

Exit code 0 when every rule is killed, 1 when one survives or the unmutated
suite is not green to begin with.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MUTANT_ENV = "GIFTHORSE_TEST_DISABLE_RULE"
_FAILED = re.compile(r"^(?:FAILED|ERROR) (\S+)", re.MULTILINE)


def rule_ids() -> list[str]:
    sys.path.insert(0, str(ROOT / "src"))
    from gifthorse import registry

    return [rule.id for rule in registry.all_rules()]


def run_suite(rule_id: str | None) -> tuple[int, list[str]]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env.pop(MUTANT_ENV, None)
    if rule_id is not None:
        env[MUTANT_ENV] = rule_id
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider", "-o", "addopts="],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    failed = sorted(set(_FAILED.findall(proc.stdout)))
    return proc.returncode, failed


def main() -> int:
    code, failed = run_suite(None)
    if code != 0:
        print("The unmutated suite is not green; fix it first:", *failed, sep="\n  ")
        return 1
    survivors: list[str] = []
    ids = rule_ids()
    for rule_id in ids:
        code, failed = run_suite(rule_id)
        killed = code != 0 and bool(failed)
        if not killed:
            survivors.append(rule_id)
        status = "killed" if killed else "SURVIVED"
        print(f"{rule_id}  {status}  {len(failed)} failing test(s)")
        for test in failed:
            print(f"    {test}")
    print(f"\n{len(ids) - len(survivors)} of {len(ids)} rules killed")
    if survivors:
        print("Survivors (no test notices them):", " ".join(survivors))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
