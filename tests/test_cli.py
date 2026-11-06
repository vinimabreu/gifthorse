"""Command line behavior: verdicts, exit codes, formats, and the help views."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from gifthorse.cli import main

from . import builders as b

# These tests write a zip that carries a script-shaped member to disk. On
# Windows CI endpoint protection may quarantine it, so they are skipped there;
# the in-memory tests cover the same logic on every platform.
no_disk_dropper_on_windows = pytest.mark.skipif(
    sys.platform == "win32", reason="endpoint protection may quarantine the fixture"
)


def _write_zip(path: Path, members: dict[str, bytes], **kw: object) -> Path:
    path.write_bytes(b.make_zip(members, **kw))  # type: ignore[arg-type]
    return path


def _dropper_zip(tmp_path: Path) -> Path:
    return _write_zip(
        tmp_path / "brief.zip",
        {"shot.png": b.PNG, "doc.vbs": b.vbs_dropper().encode()},
    )


def _clean_zip(tmp_path: Path) -> Path:
    return _write_zip(tmp_path / "ok.zip", {"brief.pdf": b.PDF, "shot.png": b.PNG})


@no_disk_dropper_on_windows
def test_block_target_exits_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main([str(_dropper_zip(tmp_path))])
    out = capsys.readouterr().out
    assert code == 1
    assert "BLOCK" in out
    assert "GH201" in out


def test_clean_target_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main([str(_clean_zip(tmp_path))])
    out = capsys.readouterr().out
    assert code == 0
    assert "NO FINDINGS" in out
    assert "not" in out.lower()  # the advice line says this is not a clearance


@no_disk_dropper_on_windows
def test_fail_on_never_exits_zero_even_on_block(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([str(_dropper_zip(tmp_path)), "--fail-on", "never"])
    capsys.readouterr()
    assert code == 0


def test_fail_on_review_exits_one_on_review(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write_zip(tmp_path / "enc.zip", {"a.txt": b"x", "s.bin": b"y"}, encrypt=("s.bin",))
    code = main([str(path), "--fail-on", "review"])
    out = capsys.readouterr().out
    assert code == 1
    assert "REVIEW" in out


def test_review_with_default_fail_on_block_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write_zip(tmp_path / "enc.zip", {"a.txt": b"x", "s.bin": b"y"}, encrypt=("s.bin",))
    code = main([str(path)])
    capsys.readouterr()
    assert code == 0


@no_disk_dropper_on_windows
def test_json_output_is_valid_and_versioned(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([str(_dropper_zip(tmp_path)), "--format", "json"])
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert code == 1
    assert doc["schema"] == "gifthorse.report/1"
    assert doc["verdict"] == "BLOCK"
    assert any(f["rule"] == "GH201" for f in doc["findings"])
    assert "coverage" in doc and "counts" in doc
    for finding in doc["findings"]:
        assert finding["trigger"].strip()
        assert finding["next_step"].strip()
        assert finding["title"].strip()


@no_disk_dropper_on_windows
def test_iocs_block_prints_defanged_indicators(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main([str(_dropper_zip(tmp_path)), "--iocs"])
    out = capsys.readouterr().out
    assert "Indicators" in out
    assert "[.]" in out  # defanged host
    assert "http://" not in out  # never a live scheme in text output


def test_quiet_prints_only_the_verdict(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main([str(_clean_zip(tmp_path)), "--quiet"])
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1
    assert "NO FINDINGS" in out[0]


@no_disk_dropper_on_windows
def test_text_output_shows_trigger_and_next_step(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main([str(_dropper_zip(tmp_path))])
    out = capsys.readouterr().out
    assert "trigger:" in out
    assert "next:" in out
    assert "inspected" in out  # coverage line


def test_unreadable_target_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["/no/such/path/at/all.zip"])
    err = capsys.readouterr().err
    assert code == 2
    assert "cannot read" in err


def test_no_path_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([])
    assert code == 2


def test_list_rules(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--list-rules"])
    out = capsys.readouterr().out
    assert code == 0
    assert "GH201" in out
    assert "GH601" in out


def test_explain(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--explain", "gh201"])
    out = capsys.readouterr().out
    assert code == 0
    assert "GH201" in out
    assert "What to do instead" in out


def test_explain_unknown_rule_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--explain", "GH999"])
    captured = capsys.readouterr()
    assert code == 2
    assert "no rule" in captured.err
    assert captured.out == ""


def test_list_rules_shows_the_severity_range(capsys: pytest.CaptureFixture[str]) -> None:
    main(["--list-rules"])
    rows = {line.split()[0]: line for line in capsys.readouterr().out.splitlines()[1:]}
    assert "review/block" in rows["GH401"]
    assert "info/block" in rows["GH103"]
    assert " block " in rows["GH201"] + " "


def test_no_color_keeps_output_plain(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main([str(_clean_zip(tmp_path)), "--no-color"])
    out = capsys.readouterr().out
    assert "\033[" not in out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "gifthorse" in capsys.readouterr().out


@no_disk_dropper_on_windows
def test_multiple_targets_merge_in_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a = _clean_zip(tmp_path)
    c = _dropper_zip(tmp_path)
    code = main([str(a), str(c), "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 1
    assert len(doc["targets"]) == 2
    assert doc["verdict"] == "BLOCK"


@no_disk_dropper_on_windows
def test_json_targets_list_unreadable_paths_and_a_block_wins_over_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = str(tmp_path / "missing.zip")
    dropper = str(_dropper_zip(tmp_path))
    code = main([missing, dropper, "--format", "json"])
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["targets"] == [missing, dropper]
    assert doc["unreadable"] == [missing]
    assert code == 1  # the block on a readable target takes precedence over 2
    assert "cannot read" in captured.err


def test_an_unreadable_path_next_to_a_clean_one_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = str(tmp_path / "missing.zip")
    code = main([str(_clean_zip(tmp_path)), missing, "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 2
    assert doc["unreadable"] == [missing]


def test_negative_limits_are_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    for flag in ("--max-entries", "--max-total-bytes", "--max-file-bytes", "--max-depth"):
        with pytest.raises(SystemExit) as exc:
            main([flag, "-1", "x.zip"])
        assert exc.value.code == 2, flag
    assert "zero or more" in capsys.readouterr().err


def test_zero_limits_are_accepted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main([str(_clean_zip(tmp_path)), "--max-depth", "0", "--quiet"])
    assert code == 0
    capsys.readouterr()


def test_counts_line_uses_the_singular_for_one_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write_zip(tmp_path / "enc.zip", {"a.txt": b"x", "s.bin": b"y"}, encrypt=("s.bin",))
    main([str(path)])
    out = capsys.readouterr().out
    assert "1 finding: 0 block, 1 review, 0 info" in out
    assert "1 findings" not in out
