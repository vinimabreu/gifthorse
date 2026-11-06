"""Scripts inside and outside projects: markers, GH201, GH202, programs.

A project lowers how scripts and programs are judged, so a marker counts only
when its content confirms it, a script is let off only when it was read and
holds no download-and-run chain, and GH202 grades a script by the steps it
contains. Every shape is assembled in builders from fragments and is inert.
"""

from __future__ import annotations

from gifthorse import Verdict, scan_bytes
from gifthorse.model import Report

from . import builders as b

REAL_PACKAGE = b'{"name": "app", "scripts": {"test": "node test.js"}}'


def ids(report: Report) -> set[str]:
    return {f.rule_id for f in report.sorted_findings()}


def sev(report: Report, rule_id: str) -> str:
    levels = [f.severity.value for f in report.sorted_findings() if f.rule_id == rule_id]
    return "block" if "block" in levels else (levels[0] if levels else "")


# GH202: download plus in-memory run is a block, one step is a review -----------


def test_gh202_powershell_download_and_in_memory_run_is_block() -> None:
    data = b.make_zip({"scan1.png": b.PNG, "Budget.ps1": b.ps_download_run().encode()})
    report = scan_bytes("brief.zip", data)
    assert report.verdict is Verdict.BLOCK
    assert sev(report, "GH202") == "block"


def test_gh202_single_download_step_in_a_bat_is_review() -> None:
    data = b.make_zip(
        {"package.json": REAL_PACKAGE, "tools/fetch.bat": b.bat_single_step().encode()}
    )
    report = scan_bytes("proj.zip", data)
    assert sev(report, "GH202") == "review"
    assert report.verdict is Verdict.REVIEW


def test_gh202_maven_wrapper_cmd_that_downloads_a_jar_is_review() -> None:
    data = b.make_zip({"pom.xml": b"<project></project>", "mvnw.cmd": b.mvnw_cmd().encode()})
    report = scan_bytes("proj.zip", data)
    assert sev(report, "GH202") == "review"


def test_gh202_quiet_on_the_gradle_wrapper_bat() -> None:
    data = b.make_zip(
        {"build.gradle": b"plugins { id 'java' }\n", "gradlew.bat": b.gradlew_bat().encode()}
    )
    assert "GH202" not in ids(scan_bytes("proj.zip", data))


def test_gh202_quiet_on_an_ordinary_build_bat() -> None:
    data = b.make_zip(
        {"package.json": REAL_PACKAGE, "make.bat": b"@echo off\nsphinx-build . _build\n"}
    )
    assert "GH202" not in ids(scan_bytes("proj.zip", data))


# GH201 covers Windows Script Host code in a JavaScript file --------------------


def test_gh201_wsh_jscript_dropper_in_a_js_file_is_block_even_in_a_project() -> None:
    data = b.make_zip({"package.json": REAL_PACKAGE, "src/x.js": b.wsh_jscript_dropper().encode()})
    report = scan_bytes("proj.zip", data)
    assert report.verdict is Verdict.BLOCK
    assert "GH201" in ids(report)


def test_gh201_fires_on_a_lone_wscript_shell_object_in_a_js_file() -> None:
    data = b.make_zip({"package.json": REAL_PACKAGE, "src/x.js": b.wsh_jscript_signal().encode()})
    assert "GH201" in ids(scan_bytes("proj.zip", data))


def test_gh201_quiet_on_browser_era_xmlhttp_fallback() -> None:
    body = (
        "var xhr = window.XMLHttpRequest "
        "? new XMLHttpRequest() "
        ": new Active" + "XObject('Microsoft.XML" + "HTTP');\nxhr.open('GET', url);\n"
    ).encode()
    data = b.make_zip({"package.json": REAL_PACKAGE, "src/http.js": body})
    assert "GH201" not in ids(scan_bytes("proj.zip", data))


def test_core_js_style_htmlfile_activexobject_is_quiet() -> None:
    body = b"var doc = new ActiveXObject('htmlfile');\ndoc.write('<script></script>');\n"
    data = b.make_zip({"package.json": REAL_PACKAGE, "internals/create.js": body})
    assert "GH201" not in ids(scan_bytes("proj.zip", data))


# A project shelters a script only when it was read and is clean ----------------


def test_a_benign_vbs_in_a_real_project_is_review() -> None:
    data = b.make_zip({"package.json": REAL_PACKAGE, "tools/a.vbs": b'WScript.Echo "hi"\n'})
    report = scan_bytes("proj.zip", data)
    assert report.verdict is Verdict.REVIEW
    assert sev(report, "GH101") == "review"


def test_a_benign_bat_in_a_real_project_stays_quiet() -> None:
    data = b.make_zip({"package.json": REAL_PACKAGE, "tools/a.bat": b"@echo off\necho hi\n"})
    assert scan_bytes("proj.zip", data).verdict is Verdict.NO_FINDINGS


def test_a_vbs_dropper_in_a_project_is_block_by_name_and_content() -> None:
    data = b.make_zip(
        {"package.json": REAL_PACKAGE, "scan.png": b.PNG, "Budget.vbs": b.vbs_dropper().encode()}
    )
    report = scan_bytes("brief.zip", data)
    assert sev(report, "GH101") == "block"
    assert sev(report, "GH201") == "block"


def test_a_names_only_vbs_beside_a_manifest_is_not_sheltered() -> None:
    data = b.make_rar5(
        {"package.json": REAL_PACKAGE, "scan.png": b.PNG, "Budget.vbs": b"rem placeholder"}
    )
    assert sev(scan_bytes("brief.rar", data), "GH101") == "block"


# Markers count only when their content confirms them ---------------------------


def test_an_empty_package_json_is_not_a_project() -> None:
    data = b.make_zip({"package.json": b"{}", "scan.png": b.PNG, "Budget.ps1": b'Write-Host "x"\n'})
    assert sev(scan_bytes("brief.zip", data), "GH101") == "block"


def test_a_prose_requirements_txt_is_not_a_project() -> None:
    data = b.make_zip(
        {
            "requirements.txt": b"Scope: landing page\nBudget: 500\n",
            "scan.png": b.PNG,
            "setup.sh": b"#!/bin/sh\necho hi\n",
        }
    )
    assert sev(scan_bytes("brief.zip", data), "GH101") == "block"


def test_a_real_requirements_txt_is_a_project() -> None:
    data = b.make_zip(
        {
            "requirements.txt": b"requests>=2.0\nflask\n",
            "scripts/build.sh": b"#!/bin/sh\npip install -r requirements.txt\n",
        }
    )
    assert "GH101" not in ids(scan_bytes("proj.zip", data))


def test_an_empty_dockerfile_is_not_a_project_but_a_real_one_is() -> None:
    empty = b.make_zip(
        {"Dockerfile": b"# notes\n", "scan.png": b.PNG, "run.bat": b"@echo off\nrunme\n"}
    )
    assert sev(scan_bytes("brief.zip", empty), "GH101") == "block"
    real = b.make_zip(
        {"Dockerfile": b"FROM python:3.13\nCOPY . /app\n", "scripts/run.bat": b"@echo off\n"}
    )
    assert "GH101" not in ids(scan_bytes("proj.zip", real))


def test_a_github_folder_never_makes_a_project() -> None:
    funding = b.make_zip(
        {".github/FUNDING.yml": b"github: someone\n", "scan.png": b.PNG, "run.bat": b"@echo off\n"}
    )
    assert sev(scan_bytes("brief.zip", funding), "GH101") == "block"
    workflow = b.make_zip(
        {
            ".github/workflows/ci.yml": b"on: push\njobs:\n  t:\n    runs-on: x\n",
            "scripts/run.bat": b"@echo off\n",
        }
    )
    assert sev(scan_bytes("proj.zip", workflow), "GH101") == "block"


def test_an_empty_src_folder_is_not_a_project() -> None:
    data = b.make_zip({"src/": b"", "scan.png": b.PNG, "Budget.bat": b"@echo off\nbad\n"})
    assert sev(scan_bytes("brief.zip", data), "GH101") == "block"


# A binary program beside a manifest is a block; deeper is a review -------------


def test_a_program_in_the_manifest_folder_is_block() -> None:
    data = b.make_zip({"package.json": REAL_PACKAGE, "Setup.exe": b"MZ" + bytes(300)})
    assert sev(scan_bytes("proj.zip", data), "GH101") == "block"


def test_a_program_below_the_manifest_folder_is_review() -> None:
    data = b.make_zip({"package.json": REAL_PACKAGE, "tools/launcher.exe": b"MZ" + bytes(300)})
    assert sev(scan_bytes("proj.zip", data), "GH101") == "review"


def test_a_wrapped_project_with_the_program_beside_the_manifest_is_block() -> None:
    data = b.make_zip({"proj/package.json": REAL_PACKAGE, "proj/Setup.exe": b"MZ" + bytes(300)})
    assert sev(scan_bytes("proj.zip", data), "GH101") == "block"
