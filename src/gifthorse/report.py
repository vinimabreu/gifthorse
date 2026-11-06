"""Render a Report as text or JSON, and the help views (rules, explain, iocs).

Indicators and evidence are always defanged. Member paths and target names are
shown as they are, except that in text output control and direction-changing
characters are escaped, so a hostile name cannot rewrite the terminal. Color is
used only on a terminal and never when NO_COLOR is set. JSON is a direct mirror
of ``Report.to_dict``.
"""

from __future__ import annotations

import json

from . import registry
from .defang import escape_controls
from .model import Finding, Report, Severity, Verdict

_ADVICE = {
    Verdict.BLOCK: "Do not open or run anything from this package.",
    Verdict.REVIEW: "Do not run it yet; part of it needs a human look or a safer copy.",
    Verdict.NO_FINDINGS: "No findings. This is not a clearance; static checks can be evaded.",
}

_SEV_LABEL = {Severity.BLOCK: "block", Severity.REVIEW: "review", Severity.INFO: "info"}
_SEV_COLOR = {Severity.BLOCK: "31", Severity.REVIEW: "33", Severity.INFO: "36"}
_VERDICT_COLOR = {Verdict.BLOCK: "31", Verdict.REVIEW: "33", Verdict.NO_FINDINGS: "32"}


def render_text(
    report: Report,
    *,
    verbose: bool = False,
    quiet: bool = False,
    color: bool = False,
) -> str:
    lines: list[str] = []
    target = report.targets[0] if report.targets else "(input)"
    verdict = report.verdict
    banner = f"{escape_controls(target)}: {_paint(verdict.value, _VERDICT_COLOR[verdict], color)}"
    lines.append(banner)
    if quiet:
        return "\n".join(lines)
    lines.append(_ADVICE[verdict])
    lines.append("")

    findings = report.sorted_findings(include_info=verbose)
    for finding in findings:
        lines.extend(_format_finding(finding, color))

    lines.append(_coverage_line(report))
    lines.append(_counts_line(report))
    return "\n".join(lines)


def _format_finding(finding: Finding, color: bool) -> list[str]:
    rule = registry.get(finding.rule_id)
    sev = _SEV_LABEL[finding.severity]
    tag = _paint(f"[{sev}]", _SEV_COLOR[finding.severity], color)
    loc = escape_controls(finding.location())
    out = [
        f"  {tag} {finding.rule_id} {rule.title}",
        f"    at {loc}" if loc else "    at (target)",
        f"    {escape_controls(finding.message)}",
    ]
    if finding.evidence:
        out.append(f"    evidence: {escape_controls(finding.evidence)}")
    out.append(f"    trigger: {rule.trigger}")
    out.append(f"    next: {rule.next_step}")
    out.append("")
    return out


def _coverage_line(report: Report) -> str:
    cov = report.coverage
    noun = "file" if cov.present == 1 else "files"
    base = f"inspected {cov.inspected} of {cov.present} {noun}"
    if cov.skipped:
        reasons: dict[str, int] = {}
        for item in cov.skipped:
            key = _short_reason(item.reason)
            reasons[key] = reasons.get(key, 0) + 1
        detail = ", ".join(f"{count} {name}" for name, count in sorted(reasons.items()))
        base += f"; {len(cov.skipped)} skipped: {detail}"
    return base


def _short_reason(reason: str) -> str:
    if reason.startswith("cap:"):
        return "limit reached"
    if reason.startswith("rar content"):
        return "names only"
    if reason == "symlink not followed":
        return "symlink"
    return reason


def _counts_line(report: Report) -> str:
    counts = report.counts()
    total = sum(counts.values())
    noun = "finding" if total == 1 else "findings"
    return (
        f"{total} {noun}: {counts['block']} block, {counts['review']} review, {counts['info']} info"
    )


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def render_iocs(report: Report) -> str:
    indicators = report.indicators()
    if not indicators:
        return "No indicators extracted."
    lines = ["Indicators (defanged, for an abuse report):"]
    for ind in sorted(indicators, key=lambda i: (i.kind, i.value)):
        lines.append(f"  {ind.kind:8} {escape_controls(ind.defanged)}")
    return "\n".join(lines)


def render_rule_list() -> str:
    lines = ["id     severity      family          title"]
    for rule in registry.all_rules():
        lines.append(f"{rule.id:6} {rule.severity_range():12}  {rule.family:15} {rule.title}")
    return "\n".join(lines)


def render_rules_markdown() -> str:
    lines = [
        "# Rules",
        "",
        "This file is generated from the rule registry in the code. Do not edit it",
        "by hand; a test fails if it drifts from the registry.",
        "",
    ]
    for rule in registry.all_rules():
        lines.append(f"## {rule.id} {rule.title}")
        lines.append("")
        lines.append(f"- Severity: {rule.severity_text()}")
        lines.append(f"- Family: {rule.family}")
        lines.append(f"- What it means: {rule.means}")
        lines.append(f"- Why it matters: {rule.why}")
        lines.append(f"- What sets it off: {rule.trigger}")
        lines.append(f"- What to do instead: {rule.next_step}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_explain(rule_id: str) -> str | None:
    """The full text of one rule, or None when no rule has that id."""

    key = rule_id.upper()
    try:
        rule = registry.get(key)
    except KeyError:
        return None
    return "\n".join(
        [
            f"{rule.id} {rule.title}",
            f"Severity: {rule.severity_text()}",
            f"Family: {rule.family}",
            "",
            f"What it means: {rule.means}",
            f"Why it matters: {rule.why}",
            f"What sets it off: {rule.trigger}",
            f"What to do instead: {rule.next_step}",
        ]
    )


def _paint(text: str, code: str, color: bool) -> str:
    if not color:
        return text
    return f"\033[{code}m{text}\033[0m"
