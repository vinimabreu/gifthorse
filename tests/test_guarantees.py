"""The guarantees from the spec: the scanner must not become the attack surface.

Each guarantee has a test here. Several are meta-tests over ``src/`` that fail
the build if the engine ever reaches for a dangerous primitive.
"""

from __future__ import annotations

import ast
import gzip
import importlib
import io
import os
import pkgutil
import random
import re
import socket
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from types import ModuleType

import pytest

import gifthorse
from gifthorse import Limits, Verdict, scan_bytes, scan_path

from . import builders as b
from .conftest import ROOT, SRC

SRC_FILES = sorted(SRC.rglob("*.py"))


def _trees() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text(encoding="utf-8"))) for p in SRC_FILES]


# ---------------------------------------------------------------------------
# Guarantee 1: never executes, imports, evaluates or compiles scanned content
# ---------------------------------------------------------------------------

_FORBIDDEN_CALLS = {"exec", "eval", "compile", "__import__"}
_FORBIDDEN_IMPORTS = {
    "subprocess",
    "importlib",
    "pickle",
    "marshal",
    "shelve",
    "ctypes",
    "shutil",
}
_FORBIDDEN_OS_ATTRS = {"system", "popen", "symlink", "link"}


def test_src_never_calls_exec_eval_compile_or_import() -> None:
    offenders: list[str] = []
    for path, tree in _trees():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in _FORBIDDEN_CALLS
            ):
                offenders.append(f"{path.name}:{node.lineno} calls {node.func.id}")
            if (
                isinstance(node, ast.Name)
                and node.id in _FORBIDDEN_CALLS
                and isinstance(node.ctx, ast.Load)
            ):
                offenders.append(f"{path.name}:{node.lineno} references {node.id}")
    assert not offenders, offenders


def test_src_never_imports_dangerous_modules() -> None:
    offenders: list[str] = []
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in _FORBIDDEN_IMPORTS:
                        offenders.append(f"{path.name}:{node.lineno} imports {alias.name}")
            if isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root in _FORBIDDEN_IMPORTS:
                    offenders.append(f"{path.name}:{node.lineno} imports from {node.module}")
    assert not offenders, offenders


def test_src_never_uses_dangerous_os_attributes() -> None:
    offenders: list[str] = []
    for path, tree in _trees():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            value = node.value
            is_os = isinstance(value, ast.Name) and value.id == "os"
            forbidden = node.attr in _FORBIDDEN_OS_ATTRS or node.attr.startswith(("exec", "spawn"))
            if is_os and forbidden:
                offenders.append(f"{path.name}:{node.lineno} uses os.{node.attr}")
    assert not offenders, offenders


# ---------------------------------------------------------------------------
# Guarantee 2: never extracts or writes to disk
# ---------------------------------------------------------------------------

_WRITE_MODES = set("wax+")


def test_src_never_extracts_and_never_opens_for_writing() -> None:
    offenders: list[str] = []
    for path, tree in _trees():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute):
                if func.attr in ("extract", "extractall"):
                    offenders.append(f"{path.name}:{node.lineno} calls .{func.attr}")
                move_like = func.attr in ("copy", "copy2", "copyfile", "move", "symlink", "link")
                if move_like and _value_name(func.value) in ("shutil", "os"):
                    offenders.append(f"{path.name}:{node.lineno} calls .{func.attr}")
            name = _open_name(func)
            if name is not None and _opens_for_write(node):
                offenders.append(f"{path.name}:{node.lineno} opens for writing")
    assert not offenders, offenders


def _value_name(value: ast.expr) -> str:
    return value.id if isinstance(value, ast.Name) else ""


def _open_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name) and func.id == "open":
        return "open"
    if isinstance(func, ast.Attribute) and func.attr == "open":
        return "open"
    return None


def _opens_for_write(call: ast.Call) -> bool:
    mode: str | None = None
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        value = call.args[1].value
        if isinstance(value, str):
            mode = value
    for kw in call.keywords:
        if kw.arg != "mode" or not isinstance(kw.value, ast.Constant):
            continue
        if isinstance(kw.value.value, str):
            mode = kw.value.value
    if mode is None:
        return False
    return bool(_WRITE_MODES & set(mode))


def test_scanning_a_traversal_archive_writes_nothing(tmp_path: Path) -> None:
    data = b.make_zip_traversal("../../escaped.txt", b"payload")
    before = _snapshot(tmp_path)
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        report = scan_bytes("evil.zip", data)
    finally:
        os.chdir(cwd)
    assert report.verdict is Verdict.BLOCK
    assert "GH103" in {f.rule_id for f in report.sorted_findings()}
    assert _snapshot(tmp_path) == before
    assert not (tmp_path.parent / "escaped.txt").exists()
    assert not (tmp_path.parent.parent / "escaped.txt").exists()


def _snapshot(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


# ---------------------------------------------------------------------------
# Guarantee 3: never follows symlinks
# ---------------------------------------------------------------------------


def test_directory_walk_does_not_follow_a_symlink_out_of_root(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("WinHttp download and run marker SENTINEL\n", encoding="utf-8")
    root = tmp_path / "package"
    root.mkdir()
    (root / "readme.txt").write_text("hello\n", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    report = scan_path(root)
    blob = "\n".join(f"{f.message} {f.evidence}" for f in report.sorted_findings())
    assert "SENTINEL" not in blob
    reasons = {s.reason for s in report.coverage.skipped}
    assert "symlink not followed" in reasons


# ---------------------------------------------------------------------------
# Guarantee 4: no network
# ---------------------------------------------------------------------------


def test_network_is_disabled_during_the_suite() -> None:
    with pytest.raises(OSError):
        socket.create_connection(("example.invalid", 80), timeout=0.1)


# ---------------------------------------------------------------------------
# Guarantee 5: bounded work on hostile input
# ---------------------------------------------------------------------------


def test_too_many_entries_is_review_not_crash() -> None:
    members = {f"file{i}.txt": b"ok" for i in range(10)}
    data = b.make_zip(members)
    report = scan_bytes("many.zip", data, Limits(max_entries=3))
    assert report.verdict is Verdict.REVIEW
    assert "GH105" in {f.rule_id for f in report.sorted_findings()}


def test_oversize_script_member_is_review() -> None:
    data = b.make_zip({"package.json": b'{"name": "x"}', "dist/big.js": b"a" * 5000})
    report = scan_bytes("big.zip", data, Limits(max_file_bytes=1000))
    assert report.verdict is Verdict.REVIEW
    assert "GH105" in {f.rule_id for f in report.sorted_findings()}


def test_oversize_c_source_is_listed_but_not_review() -> None:
    data = b.make_zip({"setup.py": b"", "src/amalgamation.c": b"int x;\n" * 2000})
    report = scan_bytes("big.zip", data, Limits(max_file_bytes=1000))
    assert report.verdict is Verdict.NO_FINDINGS
    skipped = report.coverage.skipped
    assert [s.path for s in skipped] == ["src/amalgamation.c"]
    assert skipped[0].executable_capable is False


def test_a_highly_compressed_array_is_read_not_skipped_for_its_ratio() -> None:
    inner = b.make_zip({"matrix.npy": b"\x93NUMPY" + bytes(400_000)})
    data = b.make_zip({"pyproject.toml": b"[project]\n", "tests/data/case.npz": inner})
    report = scan_bytes("pkg.zip", data)
    assert report.verdict is Verdict.NO_FINDINGS
    assert report.coverage.skipped == []
    assert report.coverage.inspected == 3


def test_a_small_dropper_that_compresses_far_past_the_ratio_is_read() -> None:
    body = b.vbs_dropper() + ("\n" + " " * 200) * 400  # deflates far better than 100 to 1
    data = b.make_zip({"shot.png": b.PNG, "Budget.vbs": body.encode()})
    import zipfile

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        info = archive.getinfo("Budget.vbs")
        assert info.file_size > 100 * info.compress_size
        assert info.file_size < Limits().max_file_bytes
    report = scan_bytes("brief.zip", data)
    assert report.verdict is Verdict.BLOCK
    assert "GH201" in {f.rule_id for f in report.findings}


def test_corrupt_archive_is_review_not_silent_no_findings() -> None:
    from gifthorse.rar5 import RAR5_SIGNATURE

    cases = [
        ("x.zip", b"PK\x03\x04" + bytes(60)),
        ("x.rar", RAR5_SIGNATURE + bytes(60)),
        ("x.tar", bytes(257) + b"ustar" + bytes(250)),
    ]
    for name, data in cases:
        report = scan_bytes(name, data)
        assert report.verdict is Verdict.REVIEW, name
        assert "GH104" in {f.rule_id for f in report.sorted_findings()}, name
        assert report.coverage.skipped, name


def test_nesting_depth_cap_is_review() -> None:
    inner = b.make_zip({"a.txt": b"x"})
    mid = b.make_zip({"inner.zip": inner})
    outer = b.make_zip({"mid.zip": mid})
    report = scan_bytes("nested.zip", outer, Limits(max_depth=1))
    assert "GH105" in {f.rule_id for f in report.sorted_findings()}
    assert report.verdict is Verdict.REVIEW


# ---------------------------------------------------------------------------
# Guarantee 6: regex safety under pathological input
# ---------------------------------------------------------------------------


def _all_package_modules() -> list[ModuleType]:
    """Every module in the gifthorse package, imported, so no compiled pattern
    in any of them escapes the regex-safety test."""

    out: list[ModuleType] = []
    for info in pkgutil.iter_modules(gifthorse.__path__):
        out.append(importlib.import_module(f"gifthorse.{info.name}"))
    return out


def _patterns() -> list[re.Pattern[str]]:
    found: list[re.Pattern[str]] = []
    for module in _all_package_modules():
        for value in vars(module).values():
            if isinstance(value, re.Pattern):
                found.append(value)
            elif isinstance(value, tuple):
                found.extend(
                    item[0]
                    for item in value
                    if isinstance(item, tuple) and item and isinstance(item[0], re.Pattern)
                )
    return found


def test_the_safety_test_sees_every_compiled_pattern_in_the_package() -> None:
    # A rule that compiles a pattern inline, which this test would not time,
    # is caught here: the count must match a direct walk of the source.
    import ast

    compiled = 0
    for path in SRC_FILES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "compile"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
            ):
                compiled += 1
    assert len(_patterns()) == compiled, (
        "a pattern is compiled inline where the safety test cannot reach it; "
        "move it to module level"
    )


# Single characters, newline-heavy text (a pattern anchored at every line start
# that can swallow newlines rescans the rest of the input from each line), and
# the opening token of a pattern repeated, which offers a start at every copy.
_FILLERS = [
    "a",
    " ",
    "\t",
    "=",
    "x" * 2 + "\\",
    "\n",
    "\n\t",
    "\r\n",
    " \n",
    "a.",
    "a-",
    "-a.",
    "| ",
    "& ",
    "cu" + "rl ",
    "wr" + "ite ",
    "Func" + "tion(",
    "Buffer.fr" + "om(",
    "base" + "64 -d ",
    "no" + "de ",
    "requ" + "ire(",
    "fet" + "ch ",
    "certu" + "til -urlcache ",
]


def _search_time(pattern: re.Pattern[str], blob: str) -> float:
    start = time.perf_counter()
    pattern.search(blob)
    return time.perf_counter() - start


def growth(pattern: re.Pattern[str], small: str, large: str, floor: float) -> tuple[bool, float]:
    """Whether the time grows faster than the input, and the time on ``large``.

    Linear work grows by the size ratio (4x here); quadratic by its square.
    Only a timing above ``floor`` is compared, and each input takes the fastest
    of a few runs, so one scheduler pause on a fast pattern cannot fail the test.
    """

    big = min(_search_time(pattern, large) for _ in range(3))
    if big <= floor:
        return False, big
    fastest = min(_search_time(pattern, small) for _ in range(2))
    return big > 10 * fastest, big


@pytest.mark.parametrize("filler", _FILLERS)
def test_every_pattern_finishes_fast_on_pathological_input(filler: str) -> None:
    size = 1024 * 1024
    blob = (filler * (size // len(filler) + 1))[:size]
    patterns = _patterns()
    assert patterns
    total = 0.0
    superlinear: list[str] = []
    for pattern in patterns:
        # A small stage first, so a quadratic pattern fails in seconds instead
        # of running for hours on the full megabyte.
        if growth(pattern, blob[: 16 * 1024], blob[: 64 * 1024], 0.01)[0]:
            superlinear.append(pattern.pattern[:60])
            continue
        faster_than_linear, full = growth(pattern, blob[: size // 4], blob, 0.1)
        total += full
        if faster_than_linear:
            superlinear.append(pattern.pattern[:60])
    assert not superlinear, superlinear
    # About 0.7 s here on a laptop; the bound leaves room for a slow CI runner,
    # while a quadratic pattern takes minutes on a megabyte.
    assert total < 5.0, f"patterns took {total:.2f}s"


def test_the_growth_check_catches_a_quadratic_pattern() -> None:
    quadratic = re.compile(r"(?m)^\s*hookspath\s*=")  # the old git config pattern
    blob = "\n" * (32 * 1024)
    start = time.perf_counter()
    assert growth(quadratic, blob[: 8 * 1024], blob, 0.01)[0]
    assert time.perf_counter() - start < 60
    linear = re.compile(r"(?m)^[ \t]*hookspath[ \t]*=")
    assert not growth(linear, blob[: 8 * 1024], blob, 0.01)[0]


# ---------------------------------------------------------------------------
# Guarantee 7: never raises on malformed input
# ---------------------------------------------------------------------------


def _seed_corpus() -> list[tuple[str, bytes]]:
    zip_bytes = b.make_zip({"a.txt": b"hello", "b/c.js": b"console.log(1)"})
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("x.txt")
        payload = b"data"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb") as gz:
        gz.write(b"plain gzip body")
    rar_bytes = b.make_rar5({"n.txt": b"z"})
    jsonc = b.vscode_task_folder_open().encode()
    return [
        ("c.zip", zip_bytes),
        ("c.tar.gz", tar_buf.getvalue()),
        ("c.gz", gz_buf.getvalue()),
        ("c.rar", rar_bytes),
        (".vscode/tasks.json", jsonc),
    ]


def test_fuzzing_mutations_never_raise() -> None:
    rng = random.Random(1337)
    corpus = _seed_corpus()
    for _ in range(2000):
        name, base = rng.choice(corpus)
        data = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            if not data:
                break
            pos = rng.randrange(len(data))
            data[pos] = rng.randrange(256)
        if rng.random() < 0.2 and len(data) > 4:
            cut = rng.randrange(len(data))
            data = data[:cut]
        report = scan_bytes(name, bytes(data))
        assert report.verdict in (Verdict.BLOCK, Verdict.REVIEW, Verdict.NO_FINDINGS)


# ---------------------------------------------------------------------------
# Guarantee 8: a module run only proceeds with the current directory off the path
# ---------------------------------------------------------------------------


def _module_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    for key in ("NO_COLOR", "PYTHONSAFEPATH", "PYTHONDONTWRITEBYTECODE"):
        env.pop(key, None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _plant(folder: Path, names: tuple[str, ...]) -> None:
    """Drop canaries named like standard modules; each one writes a marker."""

    for name in names:
        stem = name[:-3]
        body = f"import pathlib\npathlib.Path({stem + '.marker'!r}).write_text('x')\n"
        (folder / name).write_text(body, encoding="utf-8")


def _markers(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.glob("*.marker"))


def _run_module(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=cwd,
        env=_module_env(),
        capture_output=True,
        text=True,
        check=False,
    )


_SHADOWS = ("json.py", "typing.py", "__future__.py", "socket.py", "argparse.py")


def test_plain_module_run_is_refused_and_imports_no_planted_module(tmp_path: Path) -> None:
    cwd = tmp_path / "received"
    cwd.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "readme.txt").write_text("hi\n", encoding="utf-8")
    _plant(cwd, _SHADOWS)
    for invocation in ([str(target)], ["."], ["--list-rules"], ["--explain", "GH201"], []):
        result = _run_module(cwd, "-m", "gifthorse", *invocation)
        assert result.returncode == 2, (invocation, result.stderr)
        assert "refusing to run" in result.stderr, invocation
        assert "-P" in result.stderr
        assert not _markers(cwd), f"a planted module ran for {invocation}"


def test_module_run_with_safe_path_ignores_planted_modules(tmp_path: Path) -> None:
    cwd = tmp_path / "received"
    cwd.mkdir()
    _plant(cwd, (*_SHADOWS, "importlib.py"))
    result = _run_module(cwd, "-P", "-m", "gifthorse", ".", "--quiet")
    assert result.returncode == 0, result.stderr
    assert "REVIEW" in result.stdout  # it ran, and GH405 noticed the planted files
    assert _markers(cwd) == []
    env_result = subprocess.run(
        [sys.executable, "-m", "gifthorse", ".", "--quiet"],
        cwd=cwd,
        env={**_module_env(), "PYTHONSAFEPATH": "1"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert env_result.returncode == 0, env_result.stderr
    assert _markers(cwd) == []


def test_a_planted_importlib_runs_before_any_guard_without_safe_path(tmp_path: Path) -> None:
    """The documented limit: the module runner imports importlib before this
    package's code exists, so only -P (or the installed command) protects."""

    cwd = tmp_path / "received"
    cwd.mkdir()
    _plant(cwd, ("importlib.py",))
    result = _run_module(cwd, "-m", "gifthorse", "--version")
    assert "gifthorse 0" not in result.stdout  # the package never got to run
    if not _markers(cwd):
        pytest.skip("importlib was loaded before the current directory joined the path")
    assert _markers(cwd) == ["importlib.marker"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "importlib.py" in readme  # the limit is stated where users read it


def test_running_from_outside_the_target_works(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "readme.txt").write_text("hi\n", encoding="utf-8")
    result = _run_module(ROOT, "-P", "-m", "gifthorse", str(pkg), "--quiet")
    assert result.returncode == 0, result.stderr
    assert "NO FINDINGS" in result.stdout


def test_gh405_flags_a_file_shadowing_a_standard_module(tmp_path: Path) -> None:
    (tmp_path / "json.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("y = 2\n", encoding="utf-8")
    report = scan_path(tmp_path)
    ids = {f.rule_id for f in report.sorted_findings()}
    assert "GH405" in ids
    assert report.verdict is Verdict.REVIEW
