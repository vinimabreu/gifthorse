"""The scan engine. Enumerate, build context, run rules, escalate, report.

Two phases per target: first every entry is enumerated (names and metadata,
content read into memory under caps), then the rules run. The package context
(is this a code project, does it carry a git repository) is computed between
the phases because several rules depend on it.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from . import rules
from .archives import detect_kind, read_archive
from .entries import Budget, Entry, read_regular_file, walk_directory
from .kinds import (
    ARCHIVE_EXTS,
    DEPENDENCY_SKIP,
    ENTRY_CAP_SKIP,
    LINK_SKIP,
    NOT_REGULAR_SKIP,
    ext_of,
    is_toolchain_config,
)
from .model import Coverage, Finding, Limits, Report, Severity, Skipped


def scan_bytes(name: str, data: bytes, limits: Limits | None = None) -> Report:
    """Scan bytes as a named target. No I/O beyond the bytes given."""

    limits = limits or Limits()
    budget = Budget(limits=limits)
    kind = detect_kind(data)
    if kind is None and data and ext_of(_basename(name)) in ARCHIVE_EXTS:
        # Named like an archive, read as none: never treat it as one opaque file.
        budget.present()
        budget.skip(f"<{ext_of(_basename(name))[1:]} archive>", "unreadable format")
        entries = []
        target_kind = "file"
    elif kind is None:
        entries = _single_file_entry(name, data, budget)
        target_kind = "file"
    elif kind in ("rar4", "7z"):
        entries = _unreadable_archive(name, kind, budget)
        target_kind = kind
    else:
        entries = _enumerate_archive(data, budget, depth=1, name_hint=name)
        target_kind = kind
    findings = _run(entries, name, target_kind, limits, budget)
    return Report(
        targets=(name,),
        findings=findings,
        coverage=budget.coverage,
        limits=limits,
    )


def scan_path(path: str | Path, limits: Limits | None = None) -> Report:
    """Scan a file, directory or archive on disk, read-only."""

    limits = limits or Limits()
    target = Path(path)
    name = str(path)
    # The path named on the command line is followed if it is a link: it is
    # resolved once here and the real file is what gets opened. Inside the
    # package, links never are. A missing or unreadable path raises.
    info = os.stat(target)
    if stat.S_ISDIR(info.st_mode):
        budget = Budget(limits=limits)
        entries = walk_directory(target, budget)
        entries = _expand_dir_archives(entries, budget)
        findings = _run(entries, name, "dir", limits, budget)
        return Report((name,), findings, budget.coverage, limits)
    if not stat.S_ISREG(info.st_mode):
        # A FIFO, a socket or a device is never opened.
        return _skipped_target(name, NOT_REGULAR_SKIP, limits, info.st_mode)
    if info.st_size > limits.max_total_bytes:
        # Reading a prefix would make a big archive look corrupt, so nothing is
        # read and the cap is the finding.
        return _skipped_target(name, "cap: file larger than the total-bytes limit", limits)
    data, problem = read_regular_file(Path(os.path.realpath(target)), limits.max_total_bytes + 1)
    if data is None:
        if problem == NOT_REGULAR_SKIP:
            return _skipped_target(name, problem, limits, info.st_mode)
        raise PermissionError(f"cannot open {name}")
    if len(data) > limits.max_total_bytes:
        return _skipped_target(name, "cap: file larger than the total-bytes limit", limits)
    return scan_bytes(name, data, limits)


def _skipped_target(name: str, reason: str, limits: Limits, mode: int = 0) -> Report:
    budget = Budget(limits=limits)
    budget.present()
    budget.skip(_basename(name), reason, executable_capable=True)
    entries = [Entry(rel=_basename(name), mode=mode)]
    findings = _run(entries, name, "file", limits, budget)
    return Report((name,), findings, budget.coverage, limits)


def _basename(name: str) -> str:
    return name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def _single_file_entry(name: str, data: bytes, budget: Budget) -> list[Entry]:
    budget.count_entry()
    budget.present()
    truncated = len(data) > budget.limits.max_file_bytes
    kept = data[: budget.limits.max_file_bytes]
    budget.take(len(kept))
    basename = _basename(name)
    if truncated:
        budget.skip(basename, "cap: file larger than per-file limit")
    else:
        budget.inspected()
    return [Entry(rel=basename, data=kept, size=len(data), container="file", truncated=truncated)]


def _unreadable_archive(name: str, kind: str, budget: Budget) -> list[Entry]:
    budget.present()
    label = "RAR4" if kind == "rar4" else "7z"
    budget.skip(f"<{label} archive>", "unreadable format")
    return []


def _enumerate_archive(data: bytes, budget: Budget, depth: int, name_hint: str = "") -> list[Entry]:
    kind = detect_kind(data)
    if kind is None or kind in ("rar4", "7z"):
        return []
    entries = read_archive(kind, data, budget, name_hint)
    result: list[Entry] = []
    for entry in entries:
        result.append(entry)
        if entry.data is None or entry.is_dir:
            continue
        result.extend(_expand_nested(entry, budget, depth))
    return result


def _expand_nested(entry: Entry, budget: Budget, depth: int) -> list[Entry]:
    """Open a member that is itself an archive, to the depth cap.

    Skips recorded inside the nested archive are given the member's path as a
    prefix, so the coverage block names them in full.
    """

    if entry.data is None:
        return []
    sub_kind = detect_kind(entry.data)
    if sub_kind is None:
        if entry.data and not entry.truncated and ext_of(entry.name) in ARCHIVE_EXTS:
            # Named like an archive but no reader recognizes it.
            budget.skip(entry.rel, "unreadable format")
        return []
    if sub_kind in ("rar4", "7z"):
        # Confirmed by magic and not readable here, whatever its name says.
        budget.skip(entry.rel, "unreadable format", executable_capable=True)
        return []
    if depth >= budget.limits.max_depth:
        budget.skip(entry.rel, "cap: nesting depth, archive not expanded")
        return []
    mark = len(budget.coverage.skipped)
    nested = _enumerate_archive(entry.data, budget, depth + 1, name_hint=entry.name)
    budget.prefix_skips_since(mark, entry.rel)
    for item in nested:
        item.rel = f"{entry.rel}!/{item.rel}"
    return nested


def _expand_dir_archives(entries: list[Entry], budget: Budget) -> list[Entry]:
    result: list[Entry] = []
    for entry in entries:
        result.append(entry)
        if entry.data is None or entry.is_dir:
            continue
        result.extend(_expand_nested(entry, budget, depth=0))
    return result


def _run(
    entries: list[Entry], target: str, target_kind: str, limits: Limits, budget: Budget
) -> tuple[Finding, ...]:
    budget.finish()
    ctx = rules.build_context(entries)
    findings: list[Finding] = []
    findings.extend(rules.rule_git_present(ctx, target, target_kind))
    findings.extend(rules.rule_dependency_folders(ctx, target, target_kind))
    findings.extend(rules.rule_app_bundles(ctx, target, target_kind))
    for entry in entries:
        content = rules.content_findings(entry, ctx, target, target_kind, limits.max_line)
        # A script is let off by a project only when it was read and neither
        # dropper rule found a chain in it; a single GH202 step keeps the
        # shelter, since GH202 itself holds the verdict at REVIEW.
        chain = any(
            f.rule_id == "GH201" or (f.rule_id == "GH202" and f.severity is Severity.BLOCK)
            for f in content
        )
        cleared = rules.content_was_read(entry) and not chain
        findings.extend(rules.rule_name(entry, ctx, target, target_kind, content_cleared=cleared))
        findings.extend(rules.rule_shadow(entry, ctx, target, target_kind))
        findings.extend(content)
    findings.extend(_coverage_findings(target, target_kind, budget.coverage))
    findings = _escalate(findings)
    return tuple(findings)


def _coverage_findings(target: str, target_kind: str, coverage: Coverage) -> list[Finding]:
    """Turn every skip that could have held code into a finding.

    Any capable skip produces a REVIEW, including one with a reason added later
    and not listed here: the fallback is GH104, so no capable skip can ever end
    in NO FINDINGS.
    """

    out: list[Finding] = []
    for skipped in coverage.skipped:
        if not skipped.executable_capable:
            continue
        path = _skip_display(skipped, target_kind)
        what = _skip_subject(skipped)
        reason = skipped.reason
        if reason == ENTRY_CAP_SKIP:
            rule = "GH105"
            verb = "was" if " 1 entry " in f" {what} " else "were"
            message = (
                f"{what.capitalize()} {verb} not read for content (too many entries); "
                "the names were still checked."
            )
        elif reason.startswith("cap:"):
            rule = "GH105"
            message = (
                f"A limit was reached ({reason[4:].strip()}), so {what} was not fully inspected."
            )
        elif reason == DEPENDENCY_SKIP:
            rule = "GH109"
            message = rules.dependency_message(skipped.path)
        elif reason == "encrypted":
            rule = "GH104"
            message = f"{what.capitalize()} is encrypted, so its content could not be inspected."
        elif reason.startswith("rar content"):
            rule = "GH104"
            message = "RAR content is not inspected; only the member names were read."
        elif reason == LINK_SKIP:
            rule = "GH104"
            message = "Link inside the package; its target is not followed."
        elif reason == "unreadable format":
            rule = "GH104"
            message = f"{what.capitalize()} could not be read in a format the tool inspects."
        else:
            rule = "GH104"
            message = f"{what.capitalize()} was not inspected ({reason})."
        out.append(Finding(rule, Severity.REVIEW, target, path, 0, message, reason))
    return out


def _skip_parts(skipped: Skipped) -> tuple[str, str]:
    """Split a skip path into the member it belongs to and a pseudo name.

    Whole-archive skips are recorded under a pseudo name such as
    ``<zip archive>``, alone for the target itself or after ``!/`` for a
    nested member. The pseudo name is never shown as if it were a member.
    """

    head, sep, tail = skipped.path.rpartition("!/")
    last = tail if sep else skipped.path
    if last.startswith("<") and last.endswith(">"):
        return (head if sep else ""), last[1:-1]
    return skipped.path, ""


def _skip_subject(skipped: Skipped) -> str:
    _member, pseudo = _skip_parts(skipped)
    if pseudo:
        return f"the {pseudo}"
    if skipped.reason == DEPENDENCY_SKIP:
        return "the folder"
    return "this member"


def _skip_display(skipped: Skipped, target_kind: str) -> str:
    member, _pseudo = _skip_parts(skipped)
    if not member:
        return ""
    return Entry(rel=member).display(target_kind)


def _escalate(findings: list[Finding]) -> list[Finding]:
    by_file: dict[tuple[str, str], set[str]] = {}
    for finding in findings:
        by_file.setdefault((finding.target, finding.path), set()).add(finding.rule_id)

    hidden = {"GH601", "GH602", "GH606"}
    blocked_403 = {
        key
        for key, rule_ids in by_file.items()
        if key[1] and is_toolchain_config(key[1]) and rule_ids & hidden
    }
    out: list[Finding] = []
    added_403: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.target, finding.path)
        rule_ids = by_file[key]
        if finding.rule_id == "GH403" and key in blocked_403:
            continue  # replaced by the BLOCK below
        new = finding
        if finding.rule_id == "GH606" and "GH602" in rule_ids:
            new = _bump(
                finding,
                Severity.BLOCK,
                "A blockchain remote call feeds a decoded string that is then run as code.",
            )
        out.append(new)
        if key in blocked_403 and key not in added_403:
            added_403.add(key)
            out.append(
                Finding(
                    "GH403",
                    Severity.BLOCK,
                    finding.target,
                    finding.path,
                    0,
                    "A build config that runs on load carries hidden or self-decoding code.",
                    "toolchain config",
                )
            )
    return out


def _bump(finding: Finding, severity: Severity, message: str) -> Finding:
    return Finding(
        finding.rule_id,
        severity,
        finding.target,
        finding.path,
        finding.line,
        message,
        finding.evidence,
        finding.indicators,
    )
