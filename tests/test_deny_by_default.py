"""Deny by default: what is not read, not followed or not judged by type is a REVIEW.

NO FINDINGS means nothing was found, never that a package is safe. Each test
here fails if a shortcut that let a file pass quietly comes back. Every
fixture is benign and built in the test: plain text, ``echo hi`` scripts, empty
folders and empty compressed streams.
"""

from __future__ import annotations

import bz2
import io
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

from gifthorse import Limits, Verdict, scan_bytes, scan_path
from gifthorse.cli import main
from gifthorse.entries import Entry, decode_text, read_regular_file
from gifthorse.kinds import NOT_REGULAR_SKIP
from gifthorse.model import Report
from gifthorse.rules import _git_config_entries, content_was_read

from . import builders as b

PACKAGE_JSON = b'{"name": "x", "version": "1.0.0"}'
ECHO_BAT = b"@echo off\necho hi\n"


def hits(report: Report) -> set[tuple[str, str]]:
    return {(f.rule_id, f.severity.value) for f in report.findings}


def gh101(report: Report) -> str:
    levels = [f.severity.value for f in report.findings if f.rule_id == "GH101"]
    return max(levels, key=["review", "block"].index) if levels else ""


# A project comes only from a manifest whose content confirms it ----------------


def test_a_pyproject_without_a_section_is_not_a_manifest() -> None:
    loose = b.make_zip(
        {"pyproject.toml": b"name = 'x'\n", "scan.png": b.PNG, "start.bat": ECHO_BAT}
    )
    assert gh101(scan_bytes("brief.zip", loose)) == "block"
    real = b.make_zip(
        {"pyproject.toml": b"[project]\nname = 'x'\n", "scan.png": b.PNG, "start.bat": ECHO_BAT}
    )
    assert gh101(scan_bytes("proj.zip", real)) == ""


def test_a_git_head_and_config_do_not_make_a_project() -> None:
    data = b.make_zip(
        {
            ".git/HEAD": b"ref: refs/heads/main\n",
            ".git/config": b"[core]\n\tbare = false\n",
            "scan.png": b.PNG,
            "start.bat": ECHO_BAT,
        }
    )
    assert gh101(scan_bytes("repo.zip", data)) == "block"


def test_a_src_folder_does_not_make_a_project() -> None:
    empty = b.make_zip({"src/": b"", "scan.png": b.PNG, "start.bat": ECHO_BAT})
    assert gh101(scan_bytes("brief.zip", empty)) == "block"
    filled = b.make_zip(
        {"src/main.c": b"int main(void) { return 0; }\n", "scan.png": b.PNG, "start.bat": ECHO_BAT}
    )
    assert gh101(scan_bytes("brief.zip", filled)) == "block"


def test_a_github_workflow_does_not_make_a_project() -> None:
    data = b.make_zip(
        {
            ".github/workflows/ci.yml": b"on: push\njobs:\n  t:\n    runs-on: x\n",
            "scan.png": b.PNG,
            "start.bat": ECHO_BAT,
        }
    )
    assert gh101(scan_bytes("brief.zip", data)) == "block"


def test_an_unread_script_inside_a_project_is_not_released() -> None:
    names_only = b.make_rar5({"package.json": PACKAGE_JSON, "tools/build.bat": ECHO_BAT})
    assert gh101(scan_bytes("proj.rar", names_only)) == "block"
    longer = ECHO_BAT * 4  # larger than the manifest, so only the script is cut
    past_the_cap = b.make_zip({"package.json": PACKAGE_JSON, "tools/build.bat": longer})
    report = scan_bytes("proj.zip", past_the_cap, Limits(max_file_bytes=len(PACKAGE_JSON)))
    assert gh101(report) == "block"
    read = scan_bytes("proj.zip", past_the_cap)
    assert gh101(read) == ""


def test_a_vbs_read_inside_a_project_is_review_and_unread_is_block() -> None:
    read = b.make_zip({"package.json": PACKAGE_JSON, "tools/a.vbs": b'WScript.Echo "hi"\n'})
    report = scan_bytes("proj.zip", read)
    assert gh101(report) == "review"
    assert report.verdict is Verdict.REVIEW
    unread = b.make_rar5({"package.json": PACKAGE_JSON, "tools/a.vbs": b'WScript.Echo "hi"\n'})
    assert gh101(scan_bytes("proj.rar", unread)) == "block"


# .git files and git config includes are never followed --------------------------


def test_a_gitfile_is_review_and_not_followed() -> None:
    outside = scan_bytes("w.zip", b.make_zip({".git": b"gitdir: ../x\n", "notes.txt": b"x\n"}))
    assert outside.verdict is Verdict.REVIEW
    assert ("GH108", "review") in hits(outside)
    inside = scan_bytes(
        "w.zip",
        b.make_zip(
            {".git": b"gitdir: meta\n", "meta/HEAD": b"ref: refs/heads/main\n", "notes.txt": b"x\n"}
        ),
    )
    assert inside.verdict is Verdict.REVIEW
    assert [f.path for f in inside.findings if f.rule_id == "GH108"] == ["!/.git"]


def test_a_gitfile_does_not_make_a_project() -> None:
    data = b.make_zip({".git": b"gitdir: ../x\n", "scan.png": b.PNG, "start.bat": ECHO_BAT})
    assert gh101(scan_bytes("w.zip", data)) == "block"


def test_a_git_include_is_review_and_never_followed() -> None:
    for header in (b"[include]", b'[includeIf "gitdir:x/"]'):
        cfg = b"[core]\n\tbare = false\n" + header + b"\n\tpath = other\n"
        data = b.make_zip({"notes.txt": b"x\n", ".git/config": cfg, ".git/other": b"[core]\n"})
        report = scan_bytes("repo.zip", data)
        assert [(f.rule_id, f.severity.value) for f in report.findings if f.rule_id == "GH302"] == [
            ("GH302", "review")
        ], header
        assert report.verdict is Verdict.REVIEW


# The git config is read the way git reads it -----------------------------------


def _gh302(cfg: bytes) -> list[tuple[str, int]]:
    report = scan_bytes("repo.zip", b.make_zip({"notes.txt": b"x\n", ".git/config": cfg}))
    return [(f.severity.value, f.line) for f in report.findings if f.rule_id == "GH302"]


def test_git_config_values_keep_comment_characters_inside_quotes() -> None:
    entries = _git_config_entries('[core]\n\teditor = "./e.sh --tag=#1;2" # note\n')
    assert entries == [("core", "", "editor", "./e.sh --tag=#1;2", 2)]


def test_git_config_comments_outside_quotes_are_dropped() -> None:
    assert _gh302(b"[core]\n# editor = ./e.sh\n;\tpager = ./p.sh\n\tbare = false\n") == []


def test_git_config_line_continuation_is_joined() -> None:
    cfg = b'[alias]\n\thi = "\\\n!echo hi"\n'
    assert _git_config_entries(cfg.decode()) == [("alias", "", "hi", "!echo hi", 2)]
    assert _gh302(cfg) == [("block", 2)]


def test_git_config_subsections_are_read_with_their_escapes() -> None:
    cfg = '[url "ext::echo \\"hi\\""]\n\tinsteadOf = https://example.invalid/\n'
    assert _git_config_entries(cfg) == [
        ("url", 'ext::echo "hi"', "insteadof", "https://example.invalid/", 2)
    ]
    assert _gh302(cfg.encode()) == [("block", 2)]
    plain = b'[url "https://mirror.example.invalid/"]\n\tinsteadOf = https://example.invalid/\n'
    assert _gh302(plain) == []


def test_git_config_old_dotted_section_is_read() -> None:
    assert _gh302(b"[diff.x]\n\tcommand = ./d.sh\n") == [("block", 2)]


def test_git_config_protocol_allowed_always_is_review() -> None:
    assert _gh302(b'[protocol "ext"]\n\tallow = always\n') == [("review", 2)]
    assert _gh302(b"[protocol]\n\tallow = always\n") == [("review", 2)]
    assert _gh302(b'[protocol "ext"]\n\tallow = never\n') == []


@pytest.mark.parametrize(
    "header,key",
    [
        ("[core]", "gitProxy"),
        ("[core]", "alternateRefsCommand"),
        ('[difftool "t"]', "cmd"),
        ('[difftool "t"]', "path"),
        ('[mergetool "t"]', "cmd"),
        ('[mergetool "t"]', "path"),
        ('[gpg "ssh"]', "program"),
        ('[gpg "ssh"]', "defaultKeyCommand"),
        ("[interactive]", "diffFilter"),
        ('[remote "o"]', "uploadpack"),
        ('[remote "o"]', "receivepack"),
        ('[remote "o"]', "vcs"),
        ("[uploadpack]", "packObjectsHook"),
        ("[gc]", "recentObjectsHook"),
        ('[hook "h"]', "command"),
        ("[sendemail]", "sendmailCmd"),
        ("[sendemail]", "toCmd"),
        ("[sendemail]", "ccCmd"),
        ("[sendemail]", "headerCmd"),
        ("[imap]", "tunnel"),
        ('[tar "tgz"]', "command"),
        ('[trailer "t"]', "command"),
        ('[trailer "t"]', "cmd"),
        ('[browser "b"]', "cmd"),
        ('[browser "b"]', "path"),
        ('[man "m"]', "cmd"),
        ('[man "m"]', "path"),
        ('[guitool "g"]', "cmd"),
        ("[instaweb]", "httpd"),
        ('[credential "https://example.invalid"]', "helper"),
    ],
)
def test_every_git_key_that_runs_a_program_is_block(header: str, key: str) -> None:
    assert _gh302(f"{header}\n\t{key} = ./run.sh\n".encode()) == [("block", 2)], key


def test_git_keys_that_take_a_boolean_or_a_host_are_quiet_with_one() -> None:
    assert _gh302(b"[core]\n\tfsmonitor = yes\n[pager]\n\tbranch = false\n") == []
    assert _gh302(b"[sendemail]\n\tsmtpServer = smtp.example.invalid\n") == []
    assert _gh302(b"[pager]\n\tlog = ./p.sh\n") == [("block", 2)]
    assert _gh302(b"[sendemail]\n\tsmtpServer = /usr/local/bin/send\n") == [("block", 2)]


def test_gh302_reports_the_most_severe_finding_in_a_file() -> None:
    cfg = b"[include]\n\tpath = other\n[core]\n\teditor = ./e.sh\n"
    assert _gh302(cfg) == [("block", 4)]


# macOS application bundles -------------------------------------------------------


def test_an_empty_app_bundle_in_a_zip_is_block() -> None:
    report = scan_bytes("meeting.zip", b.make_zip({"Meeting.app/Contents/MacOS/": b""}))
    assert [(f.rule_id, f.severity.value, f.path) for f in report.findings] == [
        ("GH101", "block", "!/Meeting.app")
    ]


def test_an_app_bundle_is_block_inside_a_project_and_in_any_case() -> None:
    data = b.make_zip(
        {"package.json": PACKAGE_JSON, "dist/meeting.APP/contents/macos/meeting": b"x\n"}
    )
    report = scan_bytes("proj.zip", data)
    assert ("GH101", "block", "!/dist/meeting.APP") in {
        (f.rule_id, f.severity.value, f.path) for f in report.findings
    }


def test_an_app_bundle_folder_on_disk_is_block(tmp_path: Path) -> None:
    (tmp_path / "pkg" / "Meeting.app" / "Contents" / "MacOS").mkdir(parents=True)
    report = scan_path(tmp_path / "pkg")
    assert [(f.rule_id, f.severity.value, f.path) for f in report.findings] == [
        ("GH101", "block", "/Meeting.app")
    ]


def test_folders_that_are_not_a_bundle_are_quiet() -> None:
    data = b.make_zip(
        {
            "Meeting.app/Contents/Resources/notes.txt": b"x\n",
            "docs/Contents/MacOS/notes.txt": b"x\n",
            "Other.app/Contents/MacOS": b"x\n",  # a file named MacOS, not a folder
        }
    )
    assert "GH101" not in {f.rule_id for f in scan_bytes("p.zip", data).findings}


# Many compressed streams: linear, and capped ----------------------------------


def _zip_of_empty_bz2_streams(count: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("notes.txt.bz2", bz2.compress(b"") * count)
    return buf.getvalue()


def test_thousands_of_empty_bz2_streams_finish_fast_and_hold_review() -> None:
    data = _zip_of_empty_bz2_streams(5000)
    start = time.perf_counter()
    report = scan_bytes("p.zip", data)
    assert time.perf_counter() - start < 1.0
    assert report.verdict is Verdict.REVIEW
    assert ("GH105", "review") in hits(report)
    assert [s.reason for s in report.coverage.skipped] == ["cap: too many compressed streams"]


def test_streams_up_to_the_cap_are_still_read() -> None:
    body = bz2.compress(b"x\n") + bz2.compress(b"") * 255
    report = scan_bytes("notes.txt.bz2", body)
    assert report.verdict is Verdict.NO_FINDINGS
    assert report.coverage.inspected == 1


# Text: UTF-32 marks, and null characters after decoding ------------------------


def test_utf32_text_with_a_mark_is_decoded() -> None:
    assert decode_text(b"\xff\xfe\x00\x00" + "echo hi".encode("utf-32-le")) == "echo hi"
    assert decode_text(b"\x00\x00\xfe\xff" + "echo hi".encode("utf-32-be")) == "echo hi"


def test_a_utf32_script_in_a_project_is_read() -> None:
    body = b"\xff\xfe\x00\x00" + ECHO_BAT.decode().encode("utf-32-le")
    data = b.make_zip({"package.json": PACKAGE_JSON, "tools/build.bat": body})
    assert gh101(scan_bytes("proj.zip", data)) == ""


def test_a_null_left_after_decoding_a_marked_text_means_not_read() -> None:
    plain = Entry(rel="build.bat", data=b"\xef\xbb\xbf" + ECHO_BAT)
    assert content_was_read(plain)
    nul = Entry(rel="build.bat", data=b"\xef\xbb\xbf@echo off\x00\necho hi\n")
    assert not content_was_read(nul)
    data = b.make_zip({"package.json": PACKAGE_JSON, "tools/build.bat": nul.data or b""})
    assert gh101(scan_bytes("proj.zip", data)) == "block"


# The command-line target and the read path ------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_a_link_given_on_the_command_line_is_resolved_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    real = tmp_path / "ok.zip"
    real.write_bytes(b.make_zip({"notes.txt": b"x\n"}))
    link = tmp_path / "link.zip"
    os.symlink(real, link)
    assert scan_path(link).verdict is Verdict.NO_FINDINGS
    assert main([str(link)]) == 0
    capsys.readouterr()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX open semantics")
def test_the_read_rechecks_the_opened_file_type(tmp_path: Path) -> None:
    folder = tmp_path / "folder"
    folder.mkdir()
    assert read_regular_file(folder, 16) == (None, NOT_REGULAR_SKIP)
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        assert read_regular_file(fifo, 16) == (None, NOT_REGULAR_SKIP)
