"""A naive extension filter, run next to gifthorse on the acceptance shapes.

The naive filter is the kind of check a platform or a mail scanner applies to an
attachment: list the archive's member names and flag the archive when a member
ends in a risky extension. It is given the same member names gifthorse reads
(the zip directory, or the RAR5 headers) and does not open nested archives.
The table this test computes is the one quoted in the README, and the README
copy is checked against it byte for byte.
"""

from __future__ import annotations

import io
import re
import zipfile

from gifthorse import Verdict, scan_bytes
from gifthorse.rar5 import read_rar5_names

from .conftest import ROOT
from .shapes import Shape, all_shapes

RISKY_EXTENSIONS = frozenset(
    {".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".lnk", ".hta", ".jar"}
)


def member_names(data: bytes) -> list[str]:
    if data.startswith(b"PK"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return [info.filename for info in archive.infolist() if not info.is_dir()]
    return [name for name, is_dir, _link in read_rar5_names(data).rows if not is_dir]


def naive_flags(data: bytes) -> list[str]:
    """Members a naive extension filter would flag."""

    flagged: list[str] = []
    for name in member_names(data):
        base = name.rsplit("/", 1)[-1]
        dot = base.rfind(".")
        ext = base[dot:].lower() if dot > 0 else ""
        at_root = "/" not in name
        if ext in RISKY_EXTENSIONS or (ext == ".js" and at_root):
            flagged.append(name)
    return flagged


def _row(item: Shape) -> str:
    hits = [name.rsplit("/", 1)[-1] for name in naive_flags(item.data)]
    naive = f"flagged ({', '.join(hits)})" if hits else "not flagged"
    verdict = scan_bytes(item.target, item.data).verdict.value
    return f"| {item.key} | {item.summary} | {naive} | {verdict} |"


def baseline_table() -> str:
    lines = [
        "| Shape | What it is | Naive extension filter | gifthorse |",
        "|---|---|---|---|",
    ]
    lines.extend(_row(item) for item in all_shapes())
    return "\n".join(lines) + "\n"


def test_naive_filter_result_per_shape_is_what_was_measured() -> None:
    flagged = {item.key: naive_flags(item.data) for item in all_shapes()}
    assert flagged["S1"] == ["Project Requirements and Budget.vbs"]
    assert flagged["S2"] == ["Project Requirements and Budget.vbs"]
    assert flagged["S3"] == ["postcss.config.js"]  # only because it sits at the root
    assert flagged["S4"] == []
    assert flagged["S5"] == []
    assert flagged["S6"] == []
    assert flagged["B8"] == ["gradlew.bat", "gradle/wrapper/gradle-wrapper.jar"]
    for key in ("B1", "B2", "B3", "B4", "B5", "B6", "B7"):
        assert flagged[key] == [], key


def test_gifthorse_blocks_every_malicious_shape_and_passes_every_benign_one() -> None:
    for item in all_shapes():
        verdict = scan_bytes(item.target, item.data).verdict
        expected = Verdict.BLOCK if item.malicious else Verdict.NO_FINDINGS
        assert verdict is expected, item.key


def test_the_naive_filter_misses_three_malicious_shapes_and_flags_one_benign() -> None:
    shapes = all_shapes()
    missed = [s.key for s in shapes if s.malicious and not naive_flags(s.data)]
    false_alarms = [s.key for s in shapes if not s.malicious and naive_flags(s.data)]
    assert missed == ["S4", "S5", "S6"]
    assert false_alarms == ["B8"]


def test_readme_quotes_the_measured_table() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"<!-- baseline:start -->\n(.*?)<!-- baseline:end -->", text, re.DOTALL)
    assert match is not None, "README is missing the baseline table markers"
    assert match.group(1) == baseline_table()
