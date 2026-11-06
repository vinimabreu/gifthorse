"""Core data model: severities, verdicts, rules, findings, coverage, report.

No I/O, no analysis. Everything here is plain data so the engine and the two
renderers (text and JSON) share one shape and the JSON stays a thin mirror of
the objects.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from typing import Any


class Severity(enum.Enum):
    """Finding severities, ordered info < review < block."""

    INFO = "info"
    REVIEW = "review"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.INFO: 0, Severity.REVIEW: 1, Severity.BLOCK: 2}


class Verdict(enum.Enum):
    """The one-line answer for a target."""

    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    NO_FINDINGS = "NO FINDINGS"

    @classmethod
    def from_severity(cls, severity: Severity | None) -> Verdict:
        if severity is Severity.BLOCK:
            return cls.BLOCK
        if severity is Severity.REVIEW:
            return cls.REVIEW
        return cls.NO_FINDINGS


@dataclass(frozen=True)
class Rule:
    """One entry in the rule registry.

    ``trigger`` says, in plain words, the user action that would set the rule
    off; ``next_step`` says what to do instead. Both are shown to the user so
    the tool is usable with no security background.
    """

    id: str
    title: str
    family: str
    severity: Severity
    means: str
    why: str
    trigger: str
    next_step: str
    # Other severities the rule can emit, and the condition for them, written
    # to follow the base severity: "review; block when it reaches the network".
    also: tuple[Severity, ...] = ()
    when: str = ""

    @property
    def levels(self) -> frozenset[Severity]:
        """Every severity a finding of this rule can carry."""

        return frozenset({self.severity, *self.also})

    def severity_text(self) -> str:
        if not self.also:
            return self.severity.value
        others = " or ".join(level.value for level in self.also)
        return f"{self.severity.value}; {others} {self.when}"

    def severity_range(self) -> str:
        """The levels from lowest to highest, for a table column."""

        return "/".join(level.value for level in sorted(self.levels, key=lambda s: s.rank))


@dataclass(frozen=True)
class Indicator:
    """One extracted indicator, raw and defanged, for an abuse report."""

    kind: str
    value: str
    defanged: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value, "defanged": self.defanged}


@dataclass(frozen=True)
class Finding:
    """One result. ``line`` is 0 when the finding is about a name, not a line."""

    rule_id: str
    severity: Severity
    target: str
    path: str
    line: int
    message: str
    evidence: str
    indicators: tuple[Indicator, ...] = ()

    @property
    def sort_key(self) -> tuple[str, str, int, str]:
        return (self.target, self.path, self.line, self.rule_id)

    def location(self) -> str:
        where = f"{self.target}{self.path}"
        if self.line:
            where = f"{where}:{self.line}"
        return where

    def to_dict(self) -> dict[str, Any]:
        from . import registry

        rule = registry.get(self.rule_id)
        return {
            "rule": self.rule_id,
            "title": rule.title,
            "severity": self.severity.value,
            "target": self.target,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "trigger": rule.trigger,
            "next_step": rule.next_step,
            "indicators": [i.to_dict() for i in self.indicators],
        }


@dataclass(frozen=True)
class Skipped:
    """A present entry that was not inspected, and why.

    ``executable_capable`` is True when the skipped entry could have held code
    or an executable. The report refuses to say NO FINDINGS while any such
    entry was skipped: a negative from a scan that silently dropped part of the
    input is not a negative.
    """

    path: str
    reason: str
    executable_capable: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "reason": self.reason,
            "executable_capable": self.executable_capable,
        }


@dataclass
class Coverage:
    """How much of the target was actually inspected."""

    present: int = 0
    inspected: int = 0
    skipped: list[Skipped] = field(default_factory=list)

    def merge(self, other: Coverage) -> None:
        self.present += other.present
        self.inspected += other.inspected
        self.skipped.extend(other.skipped)

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "inspected": self.inspected,
            "skipped": [s.to_dict() for s in self.skipped],
        }


@dataclass(frozen=True)
class Limits:
    """Bounds on work done per target. Hitting one is a finding, never a crash."""

    max_entries: int = 10_000
    max_total_bytes: int = 256 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    max_depth: int = 3
    max_ratio: int = 100
    max_line: int = 4096

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if value < 0:
                raise ValueError(f"{name} must be zero or more, got {value}")
        if self.max_line < 1:
            raise ValueError("max_line must be at least 1")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_entries": self.max_entries,
            "max_total_bytes": self.max_total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "max_depth": self.max_depth,
            "max_ratio": self.max_ratio,
            "max_line": self.max_line,
        }


@dataclass
class Report:
    """The whole result of a run over one or more targets."""

    targets: tuple[str, ...]
    findings: tuple[Finding, ...]
    coverage: Coverage
    limits: Limits
    # Paths given to the command line that could not be read at all.
    unreadable: tuple[str, ...] = ()
    schema: str = "gifthorse.report/1"

    @property
    def verdict(self) -> Verdict:
        top = self._top_counted_severity()
        return Verdict.from_severity(top)

    def _top_counted_severity(self) -> Severity | None:
        best: Severity | None = None
        for finding in self.findings:
            if finding.severity is Severity.INFO:
                continue
            if best is None or finding.severity.rank > best.rank:
                best = finding.severity
        return best

    def indicators(self) -> tuple[Indicator, ...]:
        seen: dict[tuple[str, str], Indicator] = {}
        for finding in self.findings:
            for indicator in finding.indicators:
                seen.setdefault((indicator.kind, indicator.value), indicator)
        return tuple(seen.values())

    def counts(self) -> dict[str, int]:
        out = {"block": 0, "review": 0, "info": 0}
        for finding in self.findings:
            out[finding.severity.value] += 1
        return out

    def sorted_findings(self, *, include_info: bool = True) -> tuple[Finding, ...]:
        kept = [f for f in self.findings if include_info or f.severity is not Severity.INFO]
        return tuple(sorted(kept, key=lambda f: f.sort_key))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "targets": list(self.targets),
            "unreadable": list(self.unreadable),
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "indicators": [i.to_dict() for i in self.indicators()],
            "coverage": self.coverage.to_dict(),
            "counts": self.counts(),
            "limits": self.limits.to_dict(),
        }

    def with_findings(self, findings: tuple[Finding, ...]) -> Report:
        return replace(self, findings=findings)
