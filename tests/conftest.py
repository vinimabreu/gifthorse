from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from gifthorse import engine, registry
from gifthorse.entries import Budget, Entry
from gifthorse.model import Finding, Limits, Severity

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "gifthorse"

# Test-only seam for tools/mutation_check.py. When this variable names a rule,
# the suite runs as if that rule did not exist: its findings are removed before
# escalation (so nothing downstream sees them) and after it (so a rule that only
# escalation produces is removed too). There is no switch like this in the
# package itself; a user cannot turn a rule off.
MUTANT_ENV = "GIFTHORSE_TEST_DISABLE_RULE"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Guarantee 4: the whole suite runs with the network cut off."""

    def deny(*args: object, **kwargs: object) -> object:
        raise OSError("network is disabled during tests")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    yield


@pytest.fixture(autouse=True)
def _disabled_rule(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    rule_id = os.environ.get(MUTANT_ENV, "")
    if not rule_id:
        yield
        return
    registry.get(rule_id)  # an unknown id fails loudly instead of testing nothing
    original = engine._escalate

    def without_rule(findings: list[Finding]) -> list[Finding]:
        kept = [f for f in findings if f.rule_id != rule_id]
        return [f for f in original(kept) if f.rule_id != rule_id]

    monkeypatch.setattr(engine, "_escalate", without_rule)
    yield


@pytest.fixture(autouse=True)
def _report_invariants(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Checked on every scan the suite runs, not on chosen fixtures only.

    A skip that could have held code never ends in NO FINDINGS, and every
    finding carries a severity inside the range its rule declares.
    """

    original = engine._run

    def checked(
        entries: list[Entry], target: str, target_kind: str, limits: Limits, budget: Budget
    ) -> tuple[Finding, ...]:
        findings = original(entries, target, target_kind, limits, budget)
        capable = [s.path for s in budget.coverage.skipped if s.executable_capable]
        counted = [f for f in findings if f.severity is not Severity.INFO]
        assert not capable or counted, f"capable skip with no finding: {capable}"
        for finding in findings:
            levels = registry.get(finding.rule_id).levels
            assert finding.severity in levels, (
                f"{finding.rule_id} emitted {finding.severity.value}, outside its declared "
                f"range {sorted(level.value for level in levels)}"
            )
        return findings

    monkeypatch.setattr(engine, "_run", checked)
    yield
