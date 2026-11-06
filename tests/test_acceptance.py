"""The acceptance test from the spec: six BLOCK shapes, eight NO FINDINGS shapes."""

from __future__ import annotations

from gifthorse import Verdict, scan_bytes
from gifthorse.model import Report

from .shapes import shape


def _scan(key: str) -> Report:
    item = shape(key)
    return scan_bytes(item.target, item.data)


def _rule_ids(report: Report, *, include_info: bool = True) -> set[str]:
    return {f.rule_id for f in report.sorted_findings(include_info=include_info)}


def _line_of(report: Report, rule_id: str) -> int:
    for finding in report.sorted_findings():
        if finding.rule_id == rule_id:
            return finding.line
    raise AssertionError(f"{rule_id} did not fire")


# ---------------------------------------------------------------------------
# S1 .. S6 must come back BLOCK with the stated rules
# ---------------------------------------------------------------------------


def test_s1_zip_document_package_with_vbs_dropper() -> None:
    report = _scan("S1")
    assert report.verdict is Verdict.BLOCK
    ids = _rule_ids(report)
    assert "GH101" in ids
    assert "GH201" in ids
    assert _line_of(report, "GH201") >= 1


def test_s2_rar5_same_contents_names_only() -> None:
    report = _scan("S2")
    assert report.verdict is Verdict.BLOCK
    ids = _rule_ids(report)
    assert "GH101" in ids  # from the name alone
    assert "GH104" in ids  # content not inspectable, review note
    assert report.coverage.inspected == 0


def test_s3_postcss_offscreen_eval_and_blockchain_channel() -> None:
    report = _scan("S3")
    assert report.verdict is Verdict.BLOCK
    ids = _rule_ids(report)
    assert {"GH601", "GH602", "GH606", "GH403"} <= ids
    # GH606 is escalated to block in the presence of GH602 in the same file.
    sev = {
        f.rule_id: f.severity.value
        for f in report.sorted_findings()
        if f.rule_id in ("GH602", "GH606", "GH403")
    }
    assert sev["GH606"] == "block"


def test_s4_git_repo_zip_with_active_hooks() -> None:
    report = _scan("S4")
    assert report.verdict is Verdict.BLOCK
    ids = _rule_ids(report)
    assert "GH301" in ids
    assert "GH108" in ids
    assert _line_of(report, "GH301") >= 1


def test_s5_installer_shell_script_with_persistence() -> None:
    report = _scan("S5")
    assert report.verdict is Verdict.BLOCK
    ids = _rule_ids(report)
    assert "GH407" in ids
    block_407 = [
        f for f in report.sorted_findings() if f.rule_id == "GH407" and f.severity.value == "block"
    ]
    assert block_407, "the installer with persistence must be a block"


def test_s6_vscode_task_runs_on_folder_open() -> None:
    report = _scan("S6")
    assert report.verdict is Verdict.BLOCK
    assert "GH501" in _rule_ids(report)


# ---------------------------------------------------------------------------
# B1 .. B8 must come back NO FINDINGS (info findings allowed)
# ---------------------------------------------------------------------------


def _assert_clean(report: Report) -> None:
    assert report.verdict is Verdict.NO_FINDINGS, [
        (f.rule_id, f.severity.value, f.location()) for f in report.sorted_findings()
    ]


def test_b1_create_next_app_style() -> None:
    _assert_clean(_scan("B1"))


def test_b2_vite_react_template() -> None:
    _assert_clean(_scan("B2"))


def test_b3_package_json_husky_prepare() -> None:
    _assert_clean(_scan("B3"))


def test_b4_plain_setuptools_package() -> None:
    _assert_clean(_scan("B4"))


def test_b5_git_repo_with_sample_hooks_only() -> None:
    report = _scan("B5")
    _assert_clean(report)
    assert "GH108" in {f.rule_id for f in report.sorted_findings(include_info=True)}


def test_b6_document_package_with_images_pdf_and_macos_cruft() -> None:
    _assert_clean(_scan("B6"))


def test_b7_vscode_tasks_without_run_on() -> None:
    _assert_clean(_scan("B7"))


def test_b8_java_gradle_project_with_wrapper_jar() -> None:
    _assert_clean(_scan("B8"))
