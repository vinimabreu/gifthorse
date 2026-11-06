"""The tool scans its own repository and must find nothing above info level.

The repository's own text contains the very tokens the rules look for: this
file and the docs talk about eval, atob, download-and-run and blockchain calls.
A clean result here is what proves the rules are scoped to the file kinds that
should carry those tokens and not to prose, tests or documentation.

What is scanned is the repository as someone would receive it: the files git
tracks or would add, plus the git config and hooks. Local build output is left
out on purpose. A ``__pycache__`` folder that running the suite just wrote is a
REVIEW by design (a shipped compiled cache can run in place of the source), so
scanning the working copy as it sits on disk would measure the test run, not
the repository.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from gifthorse import Verdict, scan_path

from .conftest import ROOT


def _received_copy(dest: Path, subdir: str = "") -> Path:
    try:
        listed = subprocess.run(
            [
                "git",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                subdir or ".",
            ],
            cwd=ROOT,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git is not available to list the repository's files")
    names = [n for n in listed.decode("utf-8").split("\0") if n]
    if not subdir:
        git_dir = ROOT / ".git"
        extra = [git_dir / "config", *sorted((git_dir / "hooks").glob("*"))]
        names.extend(p.relative_to(ROOT).as_posix() for p in extra if p.is_file())
    for name in names:
        source = ROOT / name
        if not source.is_file():
            continue  # listed but deleted in the working copy
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return dest / subdir if subdir else dest


def _above_info(path: Path) -> list[tuple[str, str]]:
    report = scan_path(path)
    found = report.sorted_findings(include_info=False)
    return [(f.rule_id, f.location()) for f in found]


def test_the_repository_scans_to_no_findings(tmp_path: Path) -> None:
    copy = _received_copy(tmp_path / "repo")
    report = scan_path(copy)
    assert report.coverage.present > 50
    assert report.verdict is Verdict.NO_FINDINGS, _above_info(copy)


def test_src_package_alone_scans_clean(tmp_path: Path) -> None:
    copy = _received_copy(tmp_path / "repo", "src/gifthorse")
    report = scan_path(copy)
    assert report.coverage.present >= 10
    assert report.verdict is Verdict.NO_FINDINGS, _above_info(copy)
