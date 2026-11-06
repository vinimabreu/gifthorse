"""File kinds: which names the rules read, and which names could hold code.

One place for the extension sets, shared by the readers and the rules. The
readers use ``is_executable_capable`` to decide whether a skipped entry can
keep a report from saying NO FINDINGS: only an entry that a content rule would
have read, or whose name is an executable, script or archive type, counts. A
skipped C source file, a font or a NumPy array could not have produced a
finding, so skipping it does not weaken the verdict; it is still listed in the
coverage block.
"""

from __future__ import annotations

import re

# Types that stay BLOCK by name even inside a code project: no build or test
# tree has a reason to ship a screensaver, a shortcut, a script-host file, a
# shell link format that runs on open, or an add-in that loads into a host app.
STRONG_BY_NAME = frozenset(
    {
        ".scr",
        ".pif",
        ".lnk",
        ".hta",
        ".vbe",
        ".jse",
        ".wsf",
        ".wsh",
        ".cpl",
        ".url",
        ".library-ms",
        ".search-ms",
        ".settingcontent-ms",
        ".appref-ms",
        ".msc",
        ".xll",
    }
)

# Windows script-host and binary types, macOS and Linux launchers, disk images
# that mount with one click, and macro-enabled Office files. Each is BLOCK
# outside a code project and REVIEW inside the subtree of a project manifest.
WIN_SCRIPT_BINARY = STRONG_BY_NAME | frozenset(
    {
        ".vbs",
        ".exe",
        ".com",
        ".msi",
        ".reg",
        ".chm",
        ".command",
        ".pkg",
        ".scpt",
        ".terminal",
        ".desktop",
        ".appimage",
        ".app",
        ".iso",
        ".img",
        ".vhd",
        ".vhdx",
        ".one",
        ".docm",
        ".xlsm",
        ".pptm",
        ".dotm",
        ".xltm",
        ".xlam",
        ".ppam",
    }
)

# Binary programs and disk images among those. In the very folder of a
# project manifest one of these is BLOCK: a build or test tree keeps its
# launchers and fixtures below the manifest, not beside it.
BINARY_PROGRAMS = frozenset(
    {
        ".exe",
        ".com",
        ".msi",
        ".scr",
        ".pif",
        ".cpl",
        ".chm",
        ".appimage",
        ".app",
        ".pkg",
        ".iso",
        ".img",
        ".vhd",
        ".vhdx",
    }
)

# Windows script types the download-write-run rule (GH201) reads. Inside a code
# project one of these is let off by name only after its content was read and
# that rule found nothing; unread, it gets no shelter from the project.
CONTENT_CHECKED_SCRIPTS = frozenset({".vbs", ".bat", ".cmd", ".ps1", ".psm1"})
# JavaScript at the root of a package is treated the same way, since that is
# where a config or an entry point the toolchain runs sits.
ROOT_JS_EXTS = frozenset({".js", ".mjs", ".cjs"})

SCRIPT_EXTS = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".sh",
        ".bash",
        ".zsh",
        ".ksh",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".py",
        ".rb",
        ".pl",
        ".php",
        ".lua",
        ".jar",
        ".class",
        ".vb",
        ".ipynb",
    }
)

WIN_SCRIPT_EXTS = frozenset(
    {".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".jse", ".bat", ".cmd", ".ps1", ".psm1"}
)
JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"})
PY_EXTS = frozenset({".py"})
SHELL_EXTS = frozenset({".sh", ".bash", ".zsh", ".ksh"})
MD_EXTS = frozenset({".md", ".markdown"})
CODE_EXTS = JS_EXTS | PY_EXTS | SHELL_EXTS

# Archive types the engine opens (or reports as not inspectable). Disk images
# and system packages it never opens (.dmg, .iso, .deb, .rpm) are left out: a
# skipped one loses nothing a rule could have found.
ARCHIVE_EXTS = frozenset(
    {
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".tbz2",
        ".xz",
        ".txz",
        ".rar",
        ".7z",
        ".jar",
        ".war",
        ".ear",
        ".whl",
        ".egg",
        ".npz",
        ".apk",
        ".ipa",
        ".msix",
        ".appx",
    }
)

# Files that make a package look like paperwork.
DOCUMENTISH = frozenset(
    {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".rtf",
        ".csv",
        ".md",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".tiff",
        ".heic",
        ".odt",
        ".pages",
        ".key",
        ".numbers",
    }
)

# Manifests that make the directory holding them, and everything below it, a
# code project for the purpose of the by-name executable rule.
MANIFEST_NAMES = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pkg-info",
        "cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "composer.json",
        "gemfile",
    }
)
MANIFEST_SUFFIXES = (".csproj", ".sln")

# Names some content rule reads regardless of extension.
_READ_NAMES = frozenset(
    {
        "package.json",
        ".gitmodules",
        "makefile",
        "dockerfile",
        "tasks.json",
        "devcontainer.json",
        ".mcp.json",
        "mcp.json",
        "settings.json",
    }
)

_CONFIG_RE = re.compile(
    r"(?:^|/)(?:postcss|tailwind|vite|next|nuxt|webpack|rollup|babel|svelte|astro|"
    r"gulp|grunt|metro|jest|vitest|eslint|turbo|rspack)\.config\.(?:c|m)?[jt]s$",
    re.IGNORECASE,
)
_CONFIG_RC_RE = re.compile(r"(?:^|/)\.(?:babelrc|eslintrc)\.(?:c|m)?js$", re.IGNORECASE)


def ext_of(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    dot = base.rfind(".")
    return base[dot:].lower() if dot > 0 else ""


def basename(rel: str) -> str:
    tail = rel.rsplit("!/", 1)[-1]
    return tail.rsplit("/", 1)[-1]


def is_manifest(name: str) -> bool:
    low = name.lower()
    return low in MANIFEST_NAMES or low.endswith(MANIFEST_SUFFIXES)


def is_toolchain_config(rel: str) -> bool:
    flat = rel.replace("!/", "/")
    return bool(_CONFIG_RE.search(flat) or _CONFIG_RC_RE.search(flat))


# Folders a walk does not descend into. A shipped dependency folder or compiled
# cache can hold code that runs in place of what the manifest or the source says
# (``npm run dev`` uses the node_modules that came with the project, and Python
# can load a matching .pyc instead of the .py next to it), so skipping one is a
# capable skip, reported as GH109.
DEPENDENCY_DIRS = frozenset({"node_modules", ".venv", "venv", "__pycache__"})


def is_code_or_config_name(rel: str) -> bool:
    """A name some tool loads or runs as code: a script, a program, a config a
    content rule reads, or a git hook or config. Used to judge a file skipped
    for its size, by its own name."""

    flat = rel.replace("!/", "/")
    if "/.git/hooks/" in "/" + flat or flat.endswith(".git/config"):
        return True
    name = basename(rel)
    low = name.lower()
    ext = ext_of(name)
    if ext in WIN_SCRIPT_BINARY or ext in SCRIPT_EXTS or ext in CODE_EXTS:
        return True
    if ext in WIN_SCRIPT_EXTS:
        return True
    if low in _READ_NAMES or low.startswith("dockerfile"):
        return True
    return is_toolchain_config(rel)


# Skip reasons, shared by the readers and the engine.
NOT_REGULAR_SKIP = "not a regular file"
UNREADABLE_FILE_SKIP = "unreadable file"
UNREADABLE_FOLDER_SKIP = "unreadable folder"
LINK_SKIP = "symlink not followed"
DEPENDENCY_SKIP = "dependency folder not scanned"
GIT_STORE_SKIP = "git object store not scanned"
ENTRY_CAP_SKIP = "cap: too many entries"
STREAM_CAP_SKIP = "cap: too many compressed streams"

# Coverage is deny by default: every skip counts as one that could have held
# code, except for the reasons listed here, each with why it cannot hide one.
# A link is never on this list: its target is not followed, whatever it is.
NON_CAPABLE_REASONS = frozenset(
    {
        # git never runs what sits in its object, LFS or log stores; the files
        # they hold are read where they are checked out in the tree.
        GIT_STORE_SKIP,
    }
)
# Judged by the skipped file's type: a file of a type no content rule reads,
# whose name is not an executable, script or archive, could not have produced
# a finding even if read in full (C source over the size cap, an image, a
# NumPy array). The RAR5 case is the same judgment on names read from headers.
TYPE_JUDGED_REASONS = frozenset(
    {
        "cap: file larger than per-file limit",
        "cap: total bytes",
        "rar content not inspectable (names only)",
    }
)


def is_executable_capable(rel: str, reason: str) -> bool:
    """Whether a skipped entry could have held something a rule would flag."""

    if reason in NON_CAPABLE_REASONS:
        return False
    if reason in TYPE_JUDGED_REASONS:
        return type_could_hold_code(rel)
    return True


def type_could_hold_code(rel: str) -> bool:
    """A name a content rule reads, or an executable, script or archive name."""

    if rel.startswith("<"):
        return True  # a whole archive, or the rest of one
    name = basename(rel)
    ext = ext_of(name)
    if ext in ARCHIVE_EXTS or ext in MD_EXTS:
        return True
    return is_code_or_config_name(rel)
