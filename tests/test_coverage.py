"""Coverage: nothing that could hold code is skipped without a finding.

Each case here is a way a scan could read less than it should and still answer
NO FINDINGS. Every one must come back at least REVIEW, and each has a benign
twin that must stay quiet.
"""

from __future__ import annotations

import gzip
import io
import lzma
import os
import sys
import tarfile
from pathlib import Path

import pytest

from gifthorse import Limits, Verdict, scan_bytes, scan_path
from gifthorse.model import Report

from . import builders as b

no_disk_dropper_on_windows = pytest.mark.skipif(
    sys.platform == "win32", reason="endpoint protection may quarantine the fixture"
)


def ids(report: Report) -> set[str]:
    return {f.rule_id for f in report.sorted_findings()}


def _write(root: Path, files: dict[str, bytes]) -> Path:
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def _symlink(link: Path, target: str) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")


# Shipped dependency folders: folder mode and archive mode agree -----------------


_DEP_TREE = {
    "package.json": b'{"name": "x"}',
    "src/index.js": b"console.log(1)\n",
    "node_modules/left-pad/index.js": b"module.exports = 1\n",
}


def test_a_shipped_node_modules_is_review_in_a_folder_and_in_a_zip(tmp_path: Path) -> None:
    folder = scan_path(_write(tmp_path / "proj", _DEP_TREE))
    archive = scan_bytes("proj.zip", b.make_zip(_DEP_TREE))
    assert folder.verdict is Verdict.REVIEW
    assert archive.verdict is Verdict.REVIEW
    assert "GH109" in ids(folder) and "GH109" in ids(archive)
    skipped = {s.path: s for s in folder.coverage.skipped}
    assert skipped["node_modules"].executable_capable is True
    assert folder.coverage.present == 3  # package.json, src/index.js, node_modules


def test_shipped_venv_and_compiled_cache_folders_are_review(tmp_path: Path) -> None:
    tree = {
        "pyproject.toml": b"[project]\n",
        "pkg/__init__.py": b"",
        "pkg/__pycache__/__init__.cpython-313.pyc": b"\xf3\r\r\n" + bytes(12),
        ".venv/pyvenv.cfg": b"home = /usr/bin\n",
    }
    report = scan_path(_write(tmp_path / "proj", tree))
    hits = sorted(
        f.location().rsplit("/", 2)[-2:][-1]
        for f in report.sorted_findings()
        if f.rule_id == "GH109"
    )
    assert hits == [".venv", "__pycache__"]
    assert report.verdict is Verdict.REVIEW


def test_a_venv_stub_folder_in_a_folder_is_read_not_skipped(tmp_path: Path) -> None:
    tree = {"pyproject.toml": b"[project]\n", "stubs/venv/__init__.pyi": b"x: int\n"}
    report = scan_path(_write(tmp_path / "proj", tree))
    assert report.verdict is Verdict.NO_FINDINGS
    assert report.coverage.skipped == []
    assert report.coverage.inspected == 2


def test_an_old_tar_without_magic_is_read_as_a_tar() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        body = b.vbs_dropper().encode()
        info = tarfile.TarInfo("Budget.vbs")
        info.size = len(body)
        tar.addfile(info, io.BytesIO(body))
    raw = bytearray(buf.getvalue())
    raw[257:265] = bytes(8)  # drop the ustar magic and version, as an old tar has none
    raw[148:156] = b"        "
    raw[148:155] = f"{sum(raw[:512]):06o}\x00".encode()
    data = b.make_zip({"shot.png": b.PNG, "fixtures/old.tar": bytes(raw)})
    report = scan_bytes("brief.zip", data)
    assert "GH201" in ids(report)
    assert "GH104" not in ids(report)


def test_tool_caches_and_build_metadata_are_read_like_any_folder(tmp_path: Path) -> None:
    tree = {
        "pyproject.toml": b"[project]\n",
        "pkg/__init__.py": b"",
        ".mypy_cache/3.13/cache.db": b"\x00" * 16,
        ".pytest_cache/v/cache/nodeids": b"[]",
        "pkg.egg-info/PKG-INFO": b"Name: pkg\n",
    }
    report = scan_path(_write(tmp_path / "proj", tree))
    assert report.verdict is Verdict.NO_FINDINGS
    assert report.coverage.skipped == []
    assert report.coverage.inspected == 5


@no_disk_dropper_on_windows
def test_a_dropper_inside_a_folder_named_like_a_cache_is_found(tmp_path: Path) -> None:
    tree = {"scan1.png": b.PNG, "Invoice_cache/Budget.vbs": b.vbs_dropper().encode()}
    report = scan_path(_write(tmp_path / "brief", tree))
    assert report.verdict is Verdict.BLOCK
    assert "GH201" in ids(report)


def test_a_folder_without_dependency_folders_skips_nothing(tmp_path: Path) -> None:
    report = scan_path(
        _write(tmp_path / "proj", {"package.json": b'{"name": "x"}', "a.js": b"1\n"})
    )
    assert report.coverage.skipped == []
    assert report.verdict is Verdict.NO_FINDINGS


# Links are never followed ------------------------------------------------------


def _link_review(report: Report, path: str) -> None:
    """The link is a REVIEW of its own (GH104) and was not counted as read."""

    assert report.verdict is Verdict.REVIEW
    assert ("GH104", path) in {(f.rule_id, f.path) for f in report.findings}
    assert [s.reason for s in report.coverage.skipped if s.path == path.lstrip("/!")] == [
        "symlink not followed"
    ]


def test_a_folder_link_named_like_a_config_is_review_and_not_followed(tmp_path: Path) -> None:
    root = _write(tmp_path / "proj", {"package.json": b'{"name": "x"}', "assets/data.txt": b"x\n"})
    _symlink(root / "postcss.config.js", "assets/data.txt")
    report = scan_path(root)
    _link_review(report, "/postcss.config.js")
    assert report.coverage.inspected == 2  # package.json and data.txt, not the link


def test_a_folder_link_to_nothing_is_review(tmp_path: Path) -> None:
    root = _write(tmp_path / "proj", {"package.json": b'{"name": "x"}'})
    _symlink(root / "postcss.config.js", "assets/missing.js")
    report = scan_path(root)
    assert report.verdict is Verdict.REVIEW
    review = [f for f in report.sorted_findings() if f.severity.value == "review"]
    assert [(f.rule_id, f.path) for f in review] == [("GH104", "/postcss.config.js")]


def test_a_folder_link_to_a_plain_file_inside_is_review(tmp_path: Path) -> None:
    root = _write(tmp_path / "proj", {"docs/notes.txt": b"x\n"})
    _symlink(root / "notes.txt", "docs/notes.txt")
    report = scan_path(root)
    _link_review(report, "/notes.txt")
    assert [f.severity.value for f in report.sorted_findings() if f.rule_id == "GH103"] == ["info"]


def test_a_folder_link_to_a_folder_inside_is_review(tmp_path: Path) -> None:
    root = _write(tmp_path / "proj", {"docs/notes.txt": b"x\n"})
    _symlink(root / "manual", "docs")
    report = scan_path(root)
    _link_review(report, "/manual")


def test_a_folder_link_that_leaves_the_root_is_block(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("x\n", encoding="utf-8")
    root = _write(tmp_path / "proj", {"readme.txt": b"hi\n"})
    _symlink(root / "data.txt", "../outside.txt")
    report = scan_path(root)
    hits = [f for f in report.sorted_findings() if f.rule_id == "GH103"]
    assert hits and hits[0].severity.value == "block"
    assert report.verdict is Verdict.BLOCK


def test_a_zip_link_to_a_plain_file_is_review_and_not_followed() -> None:
    data = b.make_zip_with_symlink(
        {"package.json": b'{"name": "x"}', "notes.txt": b"x\n"}, "readme.txt", "notes.txt"
    )
    report = scan_bytes("p.zip", data)
    _link_review(report, "!/readme.txt")


def test_a_rar5_link_with_a_plain_name_is_review() -> None:
    data = b.make_rar5(
        {"notes.txt": b"x", "readme.txt": b""}, links={"readme.txt": ("notes.txt", 1)}
    )
    report = scan_bytes("p.rar", data)
    _link_review(report, "!/readme.txt")


def test_a_zip_link_that_points_at_nothing_is_review() -> None:
    data = b.make_zip_with_symlink(
        {"package.json": b'{"name": "x"}'}, "postcss.config.js", "assets/missing.js"
    )
    report = scan_bytes("p.zip", data)
    assert report.verdict is Verdict.REVIEW
    assert "GH104" in ids(report)


# Format detection beyond the first bytes ---------------------------------------


def test_a_zip_with_a_byte_prepended_is_still_read_as_a_zip() -> None:
    zipped = b.make_zip({"shot.png": b.PNG, "Budget.vbs": b.vbs_dropper().encode()})
    report = scan_bytes("brief.zip", b"X" + zipped)
    assert report.verdict is Verdict.BLOCK
    assert {"GH101", "GH201"} <= ids(report)
    assert report.coverage.present == 2


def test_an_opaque_file_without_an_archive_name_stays_one_file() -> None:
    report = scan_bytes("notes.bin", b"\x01\x02 not an archive \x03")
    assert report.verdict is Verdict.NO_FINDINGS
    assert report.coverage.present == 1


def test_a_target_named_like_an_archive_that_is_not_one_is_review() -> None:
    report = scan_bytes("brief.zip", b"this is plain text, not a zip\n")
    assert report.verdict is Verdict.REVIEW
    hits = [f for f in report.sorted_findings() if f.rule_id == "GH104"]
    assert hits and hits[0].location() == "brief.zip"


def test_a_nested_member_named_like_an_archive_that_is_not_one_is_review() -> None:
    data = b.make_zip(
        {
            "package.json": b'{"name": "x"}',
            "assets/data.zip": b"plain text\n",
            "assets/empty.zip": b"",
        }
    )
    report = scan_bytes("p.zip", data)
    hits = [f for f in report.sorted_findings() if f.rule_id == "GH104"]
    assert [f.path for f in hits] == ["!/assets/data.zip"]


# Unreadable payloads, partial reads, nested formats this tool does not read ---


def test_a_truncated_compressed_tar_without_a_compressed_name_is_review() -> None:
    whole = b.make_tar({"install.sh": b.installer_with_persistence().encode()})
    report = scan_bytes("download", whole[: len(whole) // 2])
    assert report.verdict is Verdict.REVIEW
    assert "GH104" in ids(report)


def test_a_valid_single_gzip_without_a_compressed_name_is_read() -> None:
    report = scan_bytes("download", gzip.compress(b"just some notes\n"))
    assert report.verdict is Verdict.NO_FINDINGS
    assert report.coverage.inspected == 1


def test_a_single_xz_file_is_decompressed_and_read() -> None:
    body = lzma.compress(b.installer_with_persistence().encode())
    report = scan_bytes("install.sh.xz", body)
    assert report.verdict is Verdict.BLOCK
    assert "GH407" in ids(report)
    truncated = scan_bytes("install.sh.xz", body[: len(body) // 2])
    assert truncated.verdict is Verdict.REVIEW


def test_a_rar5_broken_after_some_names_keeps_the_rest_as_a_skip() -> None:
    whole = b.make_rar5({"a.txt": b"one", "b.txt": b"two", "c.txt": b"three"})
    cut = whole.index(b"b.txt") + 2
    report = scan_bytes("x.rar", whole[:cut])
    paths = {s.path for s in report.coverage.skipped}
    assert "<rest of rar archive>" in paths
    assert report.verdict is Verdict.REVIEW


def test_a_tar_broken_after_some_members_keeps_what_it_read() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, body in (
            ("shot.png", b.PNG),
            ("Budget.vbs", b.vbs_dropper().encode()),
            ("notes.txt", b"x" * 600),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    raw = bytearray(buf.getvalue())
    third = raw.index(b"notes.txt")
    raw[third + 148 : third + 156] = b"garbage!"  # break the third header's checksum
    report = scan_bytes("brief.tar", bytes(raw))
    assert "<rest of tar archive>" in {s.path for s in report.coverage.skipped}
    assert report.verdict is Verdict.BLOCK  # the dropper before the break was read
    assert "GH201" in ids(report)


def test_a_complete_tar_records_no_remainder() -> None:
    report = scan_bytes("ok.tar.gz", b.make_tar({"a.txt": b"one", "b.txt": b"two"}))
    assert report.coverage.skipped == []
    assert report.verdict is Verdict.NO_FINDINGS


def test_a_nested_7z_or_rar4_under_a_data_name_is_review() -> None:
    from gifthorse.rar5 import RAR4_SIGNATURE

    seven = b"7z\xbc\xaf\x27\x1c" + bytes(40)
    rar4 = RAR4_SIGNATURE + bytes(40)
    data = b.make_zip(
        {"package.json": b'{"name": "x"}', "assets/data.bin": seven, "assets/blob.dat": rar4}
    )
    report = scan_bytes("p.zip", data)
    hits = sorted(f.path for f in report.sorted_findings() if f.rule_id == "GH104")
    assert hits == ["!/assets/blob.dat", "!/assets/data.bin"]


# The total-bytes cap on a file read from disk --------------------------------


@no_disk_dropper_on_windows
def test_a_file_over_the_total_cap_is_a_cap_finding_not_a_corrupt_archive(
    tmp_path: Path,
) -> None:
    path = tmp_path / "next-app.zip"
    path.write_bytes(b.make_zip({f"f{i}.txt": os.urandom(64) for i in range(40)}))
    report = scan_path(path, Limits(max_total_bytes=1024))
    hits = [f for f in report.sorted_findings() if f.severity.value != "info"]
    assert [(f.rule_id, f.location()) for f in hits] == [("GH105", str(path))]
    assert report.coverage.inspected == 0


def test_a_corrupt_zip_is_located_at_the_target_name() -> None:
    report = scan_bytes("next-app.zip", b"PK\x03\x04" + bytes(60))
    hits = [f for f in report.sorted_findings() if f.rule_id == "GH104"]
    assert hits and hits[0].location() == "next-app.zip"
    assert "<" not in hits[0].location()


# Strange filesystem objects: never NO FINDINGS, never a hang -------------------

_SCAN_ONE = (
    "import sys; sys.path.insert(0, sys.argv[1]); from gifthorse import scan_path; "
    "r = scan_path(sys.argv[2]); print(r.verdict.value)"
)


def _scan_in_child(path: Path) -> str:
    """Scan in a separate process with a timeout: a blocked open on a FIFO
    could not be interrupted from inside the test process."""

    import subprocess

    from .conftest import ROOT

    result = subprocess.run(
        [sys.executable, "-P", "-c", _SCAN_ONE, str(ROOT / "src"), str(path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _short_dir() -> Path:
    import tempfile

    base = "/tmp" if os.path.isdir("/tmp") else None
    return Path(tempfile.mkdtemp(prefix="gh-", dir=base))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
@no_disk_dropper_on_windows
def test_strange_filesystem_objects_never_end_in_no_findings(tmp_path: Path) -> None:
    import shutil
    import socket
    import stat as stat_module

    dropper = b.vbs_dropper().encode()
    cases: dict[str, Path] = {}

    fifo = _write(tmp_path / "fifo", {"scan1.png": b.PNG})
    os.mkfifo(fifo / "README.md")
    cases["fifo"] = fifo

    locked_dir = _write(tmp_path / "locked_dir", {"scan1.png": b.PNG, "docs/notes.txt": dropper})
    locked_file = _write(tmp_path / "locked_file", {"scan1.png": b.PNG, "notes.txt": dropper})

    broken = _write(tmp_path / "broken", {"scan1.png": b.PNG})
    _symlink(broken / "notes.txt", "missing.txt")
    cases["broken symlink"] = broken

    loop = _write(tmp_path / "loop", {"scan1.png": b.PNG})
    _symlink(loop / "a.txt", "b.txt")
    _symlink(loop / "b.txt", "a.txt")
    cases["symlink loop"] = loop

    outside = _write(tmp_path / "elsewhere", {"notes.txt": dropper})
    dir_out = _write(tmp_path / "dir_out", {"scan1.png": b.PNG})
    _symlink(dir_out / "docs", str(outside))
    cases["folder symlink out of the root"] = dir_out

    dir_in = _write(tmp_path / "dir_in", {"scan1.png": b.PNG, "docs/Budget.vbs": dropper})
    _symlink(dir_in / "docs2", "docs")
    cases["folder symlink inside the root"] = dir_in

    sock_root = _short_dir()
    try:
        (sock_root / "scan1.png").write_bytes(b.PNG)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(sock_root / "notes.sock"))
            cases["socket"] = sock_root
        except OSError:
            server.close()
            server = None  # type: ignore[assignment]
        os.chmod(locked_dir / "docs", 0)
        os.chmod(locked_file / "notes.txt", 0)
        if os.geteuid() != 0:  # root reads mode-000 entries anyway
            cases["folder with mode 000"] = locked_dir
            cases["file with mode 000"] = locked_file
        verdicts = {label: _scan_in_child(path) for label, path in cases.items()}
        verdicts["FIFO given as the target"] = _scan_in_child(fifo / "README.md")
    finally:
        os.chmod(locked_dir / "docs", stat_module.S_IRWXU)
        os.chmod(locked_file / "notes.txt", stat_module.S_IRUSR | stat_module.S_IWUSR)
        if "socket" in cases and server is not None:
            server.close()
        shutil.rmtree(sock_root, ignore_errors=True)
    assert "NO FINDINGS" not in verdicts.values(), verdicts
    assert verdicts["folder symlink out of the root"] == "BLOCK"
    assert verdicts["folder symlink inside the root"] == "BLOCK"


def test_a_fifo_member_of_a_tar_is_a_skip_that_holds_review() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        png = tarfile.TarInfo("brief/scan1.png")
        png.size = len(b.PNG)
        tar.addfile(png, io.BytesIO(b.PNG))
        fifo = tarfile.TarInfo("brief/README.md")
        fifo.type = tarfile.FIFOTYPE
        tar.addfile(fifo)
    report = scan_bytes("brief.tar", buf.getvalue())
    assert report.verdict is Verdict.REVIEW
    assert ("brief/README.md", "not a regular file") in {
        (s.path, s.reason) for s in report.coverage.skipped
    }


def test_an_ordinary_folder_has_no_skips(tmp_path: Path) -> None:
    report = scan_path(_write(tmp_path / "plain", {"a.txt": b"x\n", "b/c.txt": b"y\n"}))
    assert report.coverage.skipped == []
    assert report.verdict is Verdict.NO_FINDINGS


# Multistream bzip2 and xz -------------------------------------------------------


@pytest.mark.parametrize("streams", [2, 3])
@pytest.mark.parametrize("kind", ["bz2", "xz", "gz"])
def test_a_payload_in_a_later_compressed_stream_is_read(kind: str, streams: int) -> None:
    import bz2

    def compress(part: bytes) -> bytes:
        if kind == "bz2":
            return bz2.compress(part)
        if kind == "xz":
            return lzma.compress(part)
        return gzip.compress(part)

    parts = [b"#!/bin/sh\necho step\n"] * (streams - 1) + [b.installer_with_persistence().encode()]
    body = b"".join(compress(part) for part in parts)
    report = scan_bytes(f"install.sh.{kind}", body)
    assert report.verdict is Verdict.BLOCK, kind
    assert "GH407" in ids(report)


def test_a_multistream_file_of_benign_streams_is_quiet() -> None:
    import bz2

    body = bz2.compress(b"#!/bin/sh\necho one\n") + bz2.compress(b"echo two\n")
    report = scan_bytes("setup.sh.bz2", body)
    assert report.verdict is Verdict.NO_FINDINGS
    assert report.coverage.inspected == 1


# Entry cap: names past the cap are still name-checked --------------------------


def test_a_dropper_name_past_the_entry_cap_is_still_blocked() -> None:
    members = {f"img/{i:03d}.png": b"" for i in range(50)}
    members["Project Requirements and Budget.vbs"] = b.vbs_dropper().encode()
    report = scan_bytes("brief.zip", b.make_zip(members), Limits(max_entries=10))
    hits = {(f.rule_id, f.severity.value) for f in report.findings}
    assert ("GH101", "block") in hits
    assert [f.rule_id for f in report.findings if f.rule_id == "GH105"] == ["GH105"]
    assert [s.path for s in report.coverage.skipped] == ["<41 entries past the entry limit>"]
    assert report.coverage.present == 51


def test_within_the_entry_cap_there_is_no_cap_finding() -> None:
    members = {f"img/{i:03d}.png": b"" for i in range(5)}
    report = scan_bytes("brief.zip", b.make_zip(members), Limits(max_entries=10))
    assert report.verdict is Verdict.NO_FINDINGS
