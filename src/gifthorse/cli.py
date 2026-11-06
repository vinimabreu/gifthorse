"""Command line: parse arguments, scan each target, print, set the exit code.

Exit code: 0 below the --fail-on threshold, 1 at or above it, 2 for a usage
error or a target that cannot be read. When several paths are given and one of
them cannot be read, a 1 from another path takes precedence over the 2.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, report
from .defang import escape_controls
from .engine import scan_path
from .model import Coverage, Finding, Limits, Report, Severity, Verdict

_THRESHOLD = {
    "block": Severity.BLOCK,
    "review": Severity.REVIEW,
    "never": None,
}


def _non_negative(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {value!r}") from None
    if number < 0:
        raise argparse.ArgumentTypeError(f"must be zero or more, got {number}")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gifthorse",
        description="Inspect a file, folder or archive from a stranger without running it.",
    )
    parser.add_argument("paths", nargs="*", metavar="PATH", help="files, directories or archives")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--iocs", action="store_true", help="print the defanged indicators block")
    parser.add_argument("--fail-on", choices=("block", "review", "never"), default="block")
    parser.add_argument("--verbose", action="store_true", help="also show info findings")
    parser.add_argument("--quiet", action="store_true", help="only the verdict line per target")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--max-entries", type=_non_negative, default=None)
    parser.add_argument("--max-total-bytes", type=_non_negative, default=None)
    parser.add_argument("--max-file-bytes", type=_non_negative, default=None)
    parser.add_argument("--max-depth", type=_non_negative, default=None)
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--explain", metavar="RULE", default=None)
    parser.add_argument("--version", action="version", version=f"gifthorse {__version__}")
    return parser


def _limits(args: argparse.Namespace) -> Limits:
    base = Limits()
    return Limits(
        max_entries=args.max_entries if args.max_entries is not None else base.max_entries,
        max_total_bytes=(
            args.max_total_bytes if args.max_total_bytes is not None else base.max_total_bytes
        ),
        max_file_bytes=(
            args.max_file_bytes if args.max_file_bytes is not None else base.max_file_bytes
        ),
        max_depth=args.max_depth if args.max_depth is not None else base.max_depth,
    )


def _use_color(args: argparse.Namespace) -> bool:
    if args.no_color or args.format == "json":
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        print(report.render_rule_list())
        return 0
    if args.explain is not None:
        text = report.render_explain(args.explain)
        if text is None:
            sys.stderr.write(f"gifthorse: no rule {args.explain!r}; --list-rules shows every id.\n")
            return 2
        print(text)
        return 0
    if not args.paths:
        parser.print_usage(sys.stderr)
        sys.stderr.write("gifthorse: give at least one PATH, or use --list-rules/--explain.\n")
        return 2

    limits = _limits(args)
    color = _use_color(args)
    reports: list[Report] = []
    unreadable: list[str] = []
    for path in args.paths:
        try:
            reports.append(scan_path(Path(path), limits))
        except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as exc:
            sys.stderr.write(
                f"gifthorse: cannot read {escape_controls(path)}: {escape_controls(str(exc))}\n"
            )
            unreadable.append(path)

    if not reports:
        return 2

    _emit(reports, args, color, tuple(args.paths), tuple(unreadable))

    threshold = _THRESHOLD[args.fail_on]
    code = _exit_code(reports, threshold)
    return 2 if unreadable and code == 0 else code


def _emit(
    reports: list[Report],
    args: argparse.Namespace,
    color: bool,
    targets: tuple[str, ...],
    unreadable: tuple[str, ...],
) -> None:
    if args.format == "json":
        merged = _merge(reports, targets, unreadable)
        print(report.render_json(merged))
        return
    blocks: list[str] = []
    for rep in reports:
        blocks.append(report.render_text(rep, verbose=args.verbose, quiet=args.quiet, color=color))
        if args.iocs:
            blocks.append(report.render_iocs(rep))
    print("\n\n".join(blocks))


def _merge(reports: list[Report], targets: tuple[str, ...], unreadable: tuple[str, ...]) -> Report:
    """One report for the whole run. ``targets`` lists every path given, in
    order, the unreadable ones included; ``unreadable`` names those."""

    findings: tuple[Finding, ...] = ()
    coverage = Coverage()
    for rep in reports:
        findings = findings + rep.findings
        coverage.merge(rep.coverage)
    return Report(targets, findings, coverage, reports[0].limits, unreadable=unreadable)


def _exit_code(reports: list[Report], threshold: Severity | None) -> int:
    if threshold is None:
        return 0
    for rep in reports:
        verdict = rep.verdict
        if verdict is Verdict.BLOCK and Severity.BLOCK.rank >= threshold.rank:
            return 1
        if verdict is Verdict.REVIEW and Severity.REVIEW.rank >= threshold.rank:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
