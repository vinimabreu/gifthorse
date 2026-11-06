"""The rules. Each inspects names or already-read bytes and returns findings.

Every content rule is scoped to the file kinds it applies to, so scanning a
project's own documentation and tests does not trip the rule that only a script
or a build config should trip. No rule executes, imports or evaluates anything
it reads.
"""

from __future__ import annotations

import posixpath
import re
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass

from .defang import defang, escape_controls, extract_indicators
from .entries import (
    ARCHIVE_CONTAINERS,
    Entry,
    decode_text,
    is_macos_metadata,
    looks_binary,
    text_bom,
)
from .jsonc import JsonPath, key_lines, loads_jsonc
from .kinds import (
    BINARY_PROGRAMS,
    CODE_EXTS,
    CONTENT_CHECKED_SCRIPTS,
    DEPENDENCY_DIRS,
    DOCUMENTISH,
    JS_EXTS,
    MD_EXTS,
    PY_EXTS,
    ROOT_JS_EXTS,
    SCRIPT_EXTS,
    SHELL_EXTS,
    STRONG_BY_NAME,
    WIN_SCRIPT_BINARY,
    WIN_SCRIPT_EXTS,
    ext_of,
    is_manifest,
    is_toolchain_config,
)
from .markers import confirms, is_marker_name
from .model import Finding, Indicator, Severity

# ---------------------------------------------------------------------------
# Package context and file-kind helpers
# ---------------------------------------------------------------------------

# Path and name patterns, kept at module level so the regex-safety test sees
# every pattern the rules compile.
_DRIVE = re.compile(r"^[A-Za-z]:")
_HOOK_PATH = re.compile(r"(?:^|/)\.git/hooks/([^/]+)$")
_DEVCONTAINER_PATH = re.compile(r"(?:^|/)(?:\.devcontainer/)?devcontainer\.json$")
_VSCODE_TASKS_PATH = re.compile(r"(?:^|/)\.vscode/tasks\.json$")
_AGENT_CONFIG_PATH = re.compile(
    r"(?:^|/)(?:\.mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json|\.claude/settings\.json)$"
)
_COMMAND_SEPARATOR = re.compile(r"&&|;")

VENDORED = ("/dist/", "/build/", "/vendor/", "node_modules/", ".min.")


Scope = frozenset[tuple[str, str]]


@dataclass(frozen=True)
class PackageContext:
    """What the package is, computed once before the rules run.

    ``project_dirs`` and ``manifest_dirs`` hold ``(layer, directory)`` pairs: the
    directory, inside one archive layer, that holds a project marker or a
    manifest whose content confirms it. Nothing else makes a project: not a
    .git folder, not a .git file, not a src or .github folder. A file is in a
    project only when one of its own parent directories is listed, in the same
    layer, so a manifest never shields a file outside its own subtree or inside
    a nested archive.
    """

    has_git: bool
    git_root: str
    has_documents: bool
    # Every .git folder in the package.
    git_dirs: frozenset[str] = frozenset()
    # Every .git file that points git at a repository folder (``gitdir:``).
    # The folder it names is never followed.
    git_files: tuple[str, ...] = ()
    dep_dirs: tuple[str, ...] = ()
    project_dirs: Scope = frozenset()
    manifest_dirs: Scope = frozenset()
    # Per layer, the directory a user would start Python from: the layer root,
    # and its single top-level folder when every file sits under one.
    start_dirs: Scope = frozenset()
    # Every macOS application bundle (a ``Name.app`` folder holding
    # ``Contents/MacOS``), by its path in the package.
    app_bundles: tuple[str, ...] = ()

    @property
    def is_project(self) -> bool:
        return bool(self.project_dirs)

    @property
    def is_document_package(self) -> bool:
        return not self.is_project and self.has_documents

    def in_project(self, rel: str) -> bool:
        """In a project subtree, here or through the archive that holds it.

        A wheel or test archive shipped inside a project is part of that project
        for the paperwork check. The by-name check below does not inherit.
        """

        if _covered(self.project_dirs, rel):
            return True
        cut = rel.rfind("!/")
        return cut > 0 and self.in_project(rel[:cut])

    def in_own_project(self, rel: str) -> bool:
        """In a project marked in the file's own archive layer, not inherited
        from an archive that wraps it. The script shelter uses this, so an
        outer manifest never clears a script inside a nested archive."""

        return _covered(self.project_dirs, rel)

    def in_manifest_tree(self, rel: str) -> bool:
        return _covered(self.manifest_dirs, rel)

    def beside_manifest(self, rel: str) -> bool:
        """In the very folder of a confirmed manifest, not below it."""

        layer, inner = _split_layer(rel)
        return (layer, _parent(inner)) in self.manifest_dirs

    def hook_name(self, rel: str) -> str | None:
        """The hook a file is, when it sits in the hooks folder of a git dir."""

        cut = rel.rfind("/")
        folder, name = (rel[:cut], rel[cut + 1 :]) if cut >= 0 else ("", rel)
        if folder.endswith("/hooks") or folder == "hooks":
            gitdir = folder[: -len("hooks")].rstrip("/")
            if gitdir in self.git_dirs:
                return name
        return git_hook_path(rel)

    def is_git_config(self, rel: str) -> bool:
        cut = rel.rfind("/")
        folder, name = (rel[:cut], rel[cut + 1 :]) if cut >= 0 else ("", rel)
        return (name == "config" and folder in self.git_dirs) or _is_git_config(rel)


def _split_layer(rel: str) -> tuple[str, str]:
    """Split ``outer.zip!/inner/path`` into the layer prefix and the inner path."""

    cut = rel.rfind("!/")
    if cut < 0:
        return "", rel
    return rel[: cut + 2], rel[cut + 2 :]


def _parent(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _covered(dirs: Scope, rel: str) -> bool:
    if not dirs:
        return False
    layer, inner = _split_layer(rel)
    directory = _parent(inner)
    while True:
        if (layer, directory) in dirs:
            return True
        if not directory:
            return False
        directory = _parent(directory)


def build_context(entries: list[Entry]) -> PackageContext:
    git_dirs: set[str] = set()
    git_files: set[str] = set()
    git_root = ""
    has_documents = False
    dep_dirs: set[str] = set()
    project_dirs: set[tuple[str, str]] = set()
    manifest_dirs: set[tuple[str, str]] = set()
    app_bundles: set[str] = set()
    tops: dict[str, set[str]] = {}
    venvs = {
        e.rel[: -len("/pyvenv.cfg")]
        for e in entries
        if not e.is_dir and e.rel.endswith("/pyvenv.cfg")
    }
    for entry in entries:
        rel = entry.rel
        layer, inner = _split_layer(rel)
        segments = inner.split("/")
        bundle = _app_bundle(segments if entry.is_dir else segments[:-1])
        if bundle:
            app_bundles.add(layer + bundle)
        if entry.is_dir:
            continue
        if not is_macos_metadata(rel):
            tops.setdefault(layer, set()).add(segments[0] if len(segments) > 1 else "")
        if ".git" in segments[:-1]:
            idx = segments.index(".git")
            gitdir = layer + "/".join(segments[: idx + 1])
            git_dirs.add(gitdir)
            git_root = git_root or gitdir
        if is_gitfile(entry):
            git_files.add(rel)
        # Only a manifest or marker whose content confirms it makes a project.
        if is_marker_name(entry.name) and confirms(entry.name, entry.data):
            project_dirs.add((layer, _parent(inner)))
            if is_manifest(entry.name):
                manifest_dirs.add((layer, _parent(inner)))
        dep = _dependency_dir(segments[:-1], layer, venvs)
        if dep:
            dep_dirs.add(layer + dep)
        if not is_macos_metadata(rel) and ext_of(entry.name) in DOCUMENTISH:
            has_documents = True
    return PackageContext(
        has_git=bool(git_root),
        git_root=git_root,
        has_documents=has_documents,
        git_dirs=frozenset(git_dirs),
        git_files=tuple(sorted(git_files)),
        dep_dirs=tuple(sorted(dep_dirs)),
        project_dirs=frozenset(project_dirs),
        manifest_dirs=frozenset(manifest_dirs),
        start_dirs=frozenset(_start_dirs(tops)),
        app_bundles=tuple(sorted(app_bundles)),
    )


def is_gitfile(entry: Entry) -> bool:
    """A .git file that points git at a repository folder (``gitdir: <path>``).

    Git treats the folder holding it as a work tree of that repository. The
    path is never followed, inside the package or out of it.
    """

    if entry.is_dir or entry.name != ".git" or entry.data is None:
        return False
    return entry.data.startswith(b"gitdir:")


def _app_bundle(folders: list[str]) -> str:
    """The ``Name.app`` folder of a macOS application bundle, or "".

    ``folders`` are the folder names of one path, outermost first. A bundle is
    a folder whose name ends in .app and that holds ``Contents/MacOS``, where
    the program the bundle starts lives. macOS matches these names without
    regard to case.
    """

    for index in range(len(folders) - 2):
        name = folders[index]
        if (
            len(name) > len(".app")
            and name.lower().endswith(".app")
            and folders[index + 1].lower() == "contents"
            and folders[index + 2].lower() == "macos"
        ):
            return "/".join(folders[: index + 1])
    return ""


def _start_dirs(tops: dict[str, set[str]]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for layer, firsts in tops.items():
        out.add((layer, ""))
        if len(firsts) == 1:
            only = next(iter(firsts))
            if only:
                out.add((layer, only))
    return out


def _dependency_dir(parents: list[str], layer: str, venvs: set[str]) -> str:
    """The outermost shipped dependency or compiled-cache folder above a file.

    A folder named ``venv`` counts only when it holds ``pyvenv.cfg``: the same
    name is used for the type stubs of the standard ``venv`` module.
    """

    for index, part in enumerate(parents):
        folder = "/".join(parents[: index + 1])
        if part in DEPENDENCY_DIRS and (part != "venv" or layer + folder in venvs):
            return folder
    return ""


def is_exec_mode(mode: int) -> bool:
    """An exec bit on a regular file. Archive modes often carry no file type;
    a FIFO, socket or device with exec bits is not a program."""

    return bool(mode & 0o111) and stat.S_IFMT(mode) in (0, stat.S_IFREG)


def git_hook_path(rel: str) -> str | None:
    flat = rel.replace("!/", "/")
    match = _HOOK_PATH.search(flat)
    if match is None:
        return None
    return match.group(1)


# ---------------------------------------------------------------------------
# Name rules
# ---------------------------------------------------------------------------

# The decoy (inner) extension must be a document or media type: that is what
# the name pretends to be. A module named after an archive or data format
# (stream.zip.js) is not a disguise.
_DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|rtf|odt|txt|csv|jpe?g|png|gif|bmp|heic|mp3|mp4|mov|wav)\s*\."
    r"(?:vbs|vbe|wsf|wsh|hta|jse|js|bat|cmd|ps1|scr|exe|com|pif|msi|lnk|reg|cpl|chm|sh|command|pkg|"
    r"url|iso|img|vhdx?|one|docm|xlsm|pptm|xll|msc)$",
    re.IGNORECASE,
)
# A run of spaces embedded between real characters, used to push the real
# extension out of view. Gated by a non-space on each side so it stays linear
# on hostile input (no greedy run that can backtrack).
_WHITESPACE_RUN_RE = re.compile(r"\S\s{10,}\S")
# Built from code points so this source stays pure ASCII and does not itself
# carry the characters the rule looks for.
_INVISIBLE = frozenset(
    chr(code)
    for code in (
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0x200B,
        0x200C,
        0x200D,
        0x2060,
        0x200E,
        0x200F,
        0x00AD,
    )
)


def _gh101(
    entry: Entry, ctx: PackageContext, target: str, path: str, *, content_cleared: bool
) -> list[Finding]:
    """A program file where it does not belong.

    Outside a code project, a Windows program, script-host file, launcher,
    disk image or macro document is BLOCK by name, and in a package that looks
    like paperwork any script is BLOCK too. Inside the subtree of a confirmed
    manifest, a program or disk image one folder or more below the manifest is
    REVIEW, since installers and test fixtures ship that way; one in the very
    folder of the manifest is still BLOCK. The strongest types (screensavers,
    shortcuts, script-host files, shell link formats, consoles, add-ins) are
    BLOCK everywhere.

    A Windows script (.vbs .bat .cmd .ps1 .psm1) or JavaScript at the package
    root gets the project's allowance only when ``content_cleared``: its whole
    content was read and no dropper chain (GH201, or a GH202 block) was found
    in it. Unread (names only, encrypted, past a limit) or carrying a chain, it
    is judged as if the project markers were not there, so adding a
    package.json to a brief does not lower its verdict. A .vbs is never quiet:
    read and clean inside a project it is still a REVIEW. A link has nothing
    read behind it, since links are never followed; GH104 holds it at REVIEW.
    """

    name = entry.name
    ext = ext_of(name)
    script_type = ext in CONTENT_CHECKED_SCRIPTS or (
        ext in ROOT_JS_EXTS and "/" not in _split_layer(entry.rel)[1]
    )
    sheltered = content_cleared or not script_type
    in_project = ctx.in_project(entry.rel) and sheltered
    in_manifest = ctx.in_manifest_tree(entry.rel) and sheltered
    doc_context = ctx.has_documents and not in_project
    # An exec bit counts only on a non-document file: a FAT or exFAT volume
    # reports every file as executable, so a PDF from a USB stick must not fire.
    exec_bit = is_exec_mode(entry.mode) and ext not in DOCUMENTISH
    label = ext or "executable"
    # A link is not a program and its target is never followed: GH104 holds
    # every link at REVIEW.
    if entry.is_symlink:
        return []
    if ext == ".msc" and content_was_read(entry) and not _is_mmc_console(entry.data or b""):
        return []  # a makefile for nmake or a chart for mscgen, not a console file
    where = "a document package" if doc_context else "this package"

    def block(detail: str) -> list[Finding]:
        return [_mk("GH101", Severity.BLOCK, target, path, 0, detail, name)]

    # Shortcuts, screensavers and script-host files have no legitimate place.
    if ext in STRONG_BY_NAME:
        return block(f"A program file ({label}) is inside {where}.")
    # A script whose content a rule reads (GH201/GH202 report any chain in it)
    # is quiet once it was read inside a project and found boring, except a
    # .vbs, which stays a REVIEW; unread, in a document package, or outside a
    # project, it stays BLOCK.
    if script_type:
        if ctx.in_own_project(entry.rel) and content_cleared:
            if ext == ".vbs":
                return [
                    _mk(
                        "GH101",
                        Severity.REVIEW,
                        target,
                        path,
                        0,
                        "A VBScript file (.vbs) ships inside a code project. No download-and-run "
                        "chain was found in it, but it runs on double-click, so read it before "
                        "opening anything.",
                        name,
                    )
                ]
            return []
        return block(f"A program file ({label}) is inside {where}.")
    # A binary program or disk image, which no content rule reads: BLOCK in the
    # manifest's own folder, REVIEW below it (installers and fixtures ship
    # there), BLOCK outside a project.
    if ext in WIN_SCRIPT_BINARY:
        if ext in BINARY_PROGRAMS and ctx.beside_manifest(entry.rel):
            return block(
                f"A program file ({label}) is inside the folder of the project manifest, "
                "where no build step puts a program."
            )
        if in_manifest:
            return [
                _mk(
                    "GH101",
                    Severity.REVIEW,
                    target,
                    path,
                    0,
                    f"A Windows program file ({label}) ships inside a code project; it may be a "
                    "build or test file, so check it before opening anything.",
                    name,
                )
            ]
        return block(f"A program file ({label}) is inside {where}.")
    if doc_context and (ext in SCRIPT_EXTS or exec_bit):
        return block(f"A program file ({label}) is inside a document package.")
    return []


_MMC_MARKERS = (b"MMC_ConsoleFile", "MMC_ConsoleFile".encode("utf-16-le"))
_OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")


def _is_mmc_console(data: bytes) -> bool:
    """A management console file is XML naming MMC_ConsoleFile, or an older
    binary compound file. The same extension is used by nmake makefiles."""

    return data.startswith(_OLE_MAGIC) or any(marker in data for marker in _MMC_MARKERS)


def content_was_read(entry: Entry) -> bool:
    """Whether the content rules saw all of this entry as text.

    Text with a byte-order mark is read in its encoding, so its null bytes do
    not make it binary; but a null character left after decoding is not text
    any tool shows as written, so that entry counts as not read.
    """

    if entry.data is None or entry.truncated:
        return False
    if text_bom(entry.data) is not None:
        return "\x00" not in decode_text(entry.data)
    return not looks_binary(entry.data)


def rule_name(
    entry: Entry,
    ctx: PackageContext,
    target: str,
    target_kind: str,
    *,
    content_cleared: bool = False,
) -> list[Finding]:
    out: list[Finding] = []
    name = entry.name
    path = entry.display(target_kind)
    if entry.is_dir:
        return out

    out.extend(_gh101(entry, ctx, target, path, content_cleared=content_cleared))

    if _DOUBLE_EXT_RE.search(name) or _WHITESPACE_RUN_RE.search(name):
        out.append(
            _mk(
                "GH102",
                Severity.BLOCK,
                target,
                path,
                0,
                "The name hides its real extension behind a document-looking name or spaces.",
                name,
            )
        )
    invisible = sorted({c for c in name if c in _INVISIBLE})
    if invisible:
        codes = " ".join(f"U+{ord(c):04X}" for c in invisible)
        out.append(
            _mk(
                "GH102",
                Severity.BLOCK,
                target,
                path,
                0,
                "The name carries direction-changing or invisible characters that disguise it.",
                f"{name!r} contains {codes}",
            )
        )

    from_archive = entry.container in ARCHIVE_CONTAINERS
    if from_archive and _is_traversal(entry.rel):
        out.append(
            _mk(
                "GH103",
                Severity.BLOCK,
                target,
                path,
                0,
                "The member path climbs out of the folder or is absolute.",
                entry.rel,
            )
        )
    if entry.is_symlink and entry.container == "dir":
        tgt = entry.link_target or "(unknown)"
        if entry.link_escapes:
            out.append(
                _mk(
                    "GH103",
                    Severity.BLOCK,
                    target,
                    path,
                    0,
                    "The link points outside the folder, so opening it reads or writes a file "
                    "that was not part of the package.",
                    f"link -> {tgt}",
                )
            )
        else:
            out.append(
                _mk(
                    "GH103",
                    Severity.INFO,
                    target,
                    path,
                    0,
                    "The link points to another file inside the folder; it was not followed.",
                    f"link -> {tgt}",
                )
            )
    if entry.is_symlink and from_archive:
        tgt = entry.link_target or "(unknown)"
        kind = "hard link" if entry.link_hard else "link"
        if link_escapes(entry.rel, entry.link_target, hard=entry.link_hard):
            out.append(
                _mk(
                    "GH103",
                    Severity.BLOCK,
                    target,
                    path,
                    0,
                    f"The member is a {kind} whose target is absolute or climbs out of the "
                    "archive, so unpacking it can reach files outside the folder.",
                    f"{kind} -> {tgt}",
                )
            )
        else:
            out.append(
                _mk(
                    "GH103",
                    Severity.INFO,
                    target,
                    path,
                    0,
                    f"The member is a {kind} to another file inside the archive; it was not "
                    "followed.",
                    f"{kind} -> {tgt}",
                )
            )
    return out


def link_escapes(rel: str, link_target: str, *, hard: bool) -> bool:
    """Whether a link member's target is absolute or leaves the archive root.

    Resolved lexically, never on disk. A symbolic link is relative to its own
    directory; a tar hard link names a member from the archive root. A hard link
    is treated as escaping if it escapes under either reading, so the safer
    answer always wins. An unknown target counts as escaping.
    """

    raw = link_target.replace("\\", "/")
    if not raw:
        return True
    if raw.startswith("/") or _DRIVE.match(raw):
        return True
    _layer, inner = _split_layer(rel)
    candidates = [posixpath.normpath(posixpath.join(_parent(inner), raw))]
    if hard:
        candidates.append(posixpath.normpath(raw))
    return any(c == ".." or c.startswith("../") for c in candidates)


def _is_traversal(rel: str) -> bool:
    inner = rel.split("!/")[-1]
    if inner.startswith(("/", "\\")):
        return True
    if "\\" in inner:
        return True
    if _DRIVE.match(inner):
        return True
    return ".." in inner.split("/")


# ---------------------------------------------------------------------------
# Content rules
# ---------------------------------------------------------------------------

# Windows dropper primitives (GH201)
_WIN_DOWNLOAD = re.compile(
    r"winhttp|xmlhttp|serverxmlhttp|msxml2|winhttprequest|invoke-webrequest|iwr\b|"
    r"net\.webclient|downloadfile|downloadstring|downloaddata|bitstransfer|start-bitstransfer|"
    r"certutil|\bmshta\b|\bcurl\b|\bwget\b",
    re.IGNORECASE,
)
_WIN_WRITE = re.compile(
    r"adodb\.stream|savetofile|filesystemobject|createtextfile|out-file|set-content|"
    r"\bwrite\b(?:(?!\bwrite\b).)*?\.(?:bat|exe|vbs|cmd|ps1)|>>?\s*[\"']?%(?:temp|programdata|appdata)",
    re.IGNORECASE,
)
_WIN_EXEC = re.compile(
    r"shell\.application|wscript\.shell|\.run\b|\.exec\b|shellexecute|start-process|"
    r"invoke-expression|\biex\b|\bcmd\b\s*/c|\bcmd\b\s+start|rundll32|regsvr32",
    re.IGNORECASE,
)

# GH201 also covers Windows Script Host code in a JavaScript file. Node and
# browsers have no WScript object and cannot create these objects; only the
# script host that runs a double-clicked .js on Windows can. Internet Explorer
# era fallbacks (an XMLHTTP or htmlfile ActiveXObject) are browser code and
# are not on this list.
WSH_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".jse", ".wsf", ".hta"})
_WSH_SIGNAL = re.compile(
    r"\bWScript\.(?:Shell|CreateObject|Echo|Arguments|Sleep|Quit|ScriptFullName|ScriptName|"
    r"StdOut|StdIn|Network)\b|"
    r"\bActiveXObject\s*\(\s*[\"'](?:WScript\.Shell|WScript\.Network|Scripting\.FileSystemObject|"
    r"ADODB\.Stream|Shell\.Application)[\"']|"
    r"\bGetObject\s*\(\s*[\"']script:",
    re.IGNORECASE,
)

# GH202 one-step and in-memory primitives in a Windows script. Each list is
# what the step is, not a guess at intent: a single step is a REVIEW, and a
# download together with an in-memory run, a script-host helper or an encoded
# command is the in-memory download cradle.
_STEP_NETWORK = re.compile(
    r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer|bitsadmin)\b|"
    r"net\.webclient|\bdownload(?:string|file|data)\b|msxml2\.(?:server)?xmlhttp|"
    r"microsoft\.xmlhttp|winhttp|serverxmlhttp|\bcurl(?:\.exe)?\b|\bwget(?:\.exe)?\b|"
    r"\bcertutil(?:\.exe)?\b(?:(?!\bcertutil\b)[^\n])*?-urlcache",
    re.IGNORECASE,
)
_STEP_RUN_IN_MEMORY = re.compile(r"\b(?:iex|invoke-expression)\b", re.IGNORECASE)
_STEP_VBS_EXECUTE = re.compile(r"\bexecute(?:global)?\b", re.IGNORECASE)
_STEP_JS_EVAL = re.compile(r"\beval\s*\(")
_STEP_ENCODED = re.compile(
    r"(?<![\w-])-(?:enc(?:odedcommand)?|ec)\b|(?<![\w-])-e[a-z]*[ \t]+[A-Za-z0-9+/]{20,}={0,2}",
    re.IGNORECASE,
)
_STEP_HIDDEN = re.compile(r"(?<![\w-])-w(?:indowstyle)?[ \t]+h(?:idden)?\b", re.IGNORECASE)
_STEP_HELPER = re.compile(
    r"\b(?:mshta|rundll32|regsvr32)(?:\.exe)?\b|"
    r"\b(?:cscript|wscript)(?:\.exe)?\b(?:(?!\b(?:cscript|wscript)\b)[^\n])*?"
    r"\.(?:vbs|vbe|js|jse|wsf|wsh)\b",
    re.IGNORECASE,
)
_STEP_DECODE = re.compile(
    r"frombase64string|\bcertutil(?:\.exe)?[ \t]+-decode|\bbase64[ \t]+-d\b",
    re.IGNORECASE,
)
_VBS_FAMILY = frozenset({".vbs", ".vbe", ".wsf", ".wsh", ".hta"})
# eval counts as an in-memory run only in script-host JScript; in a Node file
# at the package root it is judged by GH602 instead.
_JSCRIPT_FAMILY = frozenset({".jse", ".wsf", ".hta"})

# GH602 dynamic execution of a decoded or built string
_JS_EXEC = re.compile(
    r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\((?:(?!\bFunction\b)[^)])*+\)\s*\(|"
    r"\bvm\.run\w*\s*\(|setTimeout\s*\(\s*[\"'`]"
)
_JS_DECODE = re.compile(
    r"\batob\s*\(|Buffer\.from\s*\((?:(?!Buffer\.from)[^)])*?,\s*[\"']base64[\"']|"
    r"fromCharCode|\bunescape\s*\(|(?:\\x[0-9a-f]{2}){6,}",
    re.IGNORECASE,
)
# Match the builtins, not a method such as re.compile( or obj.eval(, so the
# tool's own source (full of re.compile) does not trip this rule.
_PY_EXEC = re.compile(r"(?<![\w.])(?<!def )(?:exec|eval|compile)\s*\(")
# How far from the evaluator, in lines, a decode primitive may sit.
# How close, in lines, a decode primitive must sit to the evaluator to be a
# block rather than a review.
_DECODE_REACH = 5
_PY_DECODE = re.compile(
    r"b64decode|base64\.b64|codecs\.decode|marshal\.loads|zlib\.decompress|bytes\.fromhex"
)

# GH606 blockchain-as-config
_ETH_RPC = re.compile(
    r"eth_call|eth_getTransactionByHash|eth_getLogs|eth_getStorageAt|eth_sendRawTransaction"
)

# GH407 download piped into a shell + persistence
# A fetch word, then everything up to the first single pipe on the line, then a
# shell. The run after the fetch word never crosses another fetch word, so each
# character is scanned from one start only and the match stays linear on a line
# that repeats the word.
_FETCH_WORD = r"(?:curl|wget|fetch|invoke-webrequest|iwr)\b"
_PIPE_SHELL = re.compile(
    _FETCH_WORD + r"(?:(?!" + _FETCH_WORD + r")[^\n|])*+\|(?!\|)[ \t]*(?:sudo[ \t]+)?"
    r"(?:bash|sh|zsh|ksh|iex|invoke-expression|python3?|node)\b",
    re.IGNORECASE,
)
_BASE64_PIPE_SHELL = re.compile(
    r"base64[ \t]+-d(?:(?!base64[ \t])[^\n|])*+\|(?!\|)[ \t]*(?:bash|sh|zsh)\b", re.IGNORECASE
)
_PERSISTENCE = re.compile(
    r"launchagents|launchdaemons|launchctl\s+(?:load|bootstrap|enable)|"
    r"systemctl\s+enable|crontab|/etc/cron|login\s*items|\.plist\b|schtasks",
    re.IGNORECASE,
)

# Shell/background signals for git hooks
_NET = re.compile(r"\bcurl\b|\bwget\b|\bnc\b|https?://|invoke-webrequest|\biwr\b", re.IGNORECASE)
# A single pipe into a shell or interpreter; "||" (or) never counts as a pipe.
_PIPE_TO_SHELL = re.compile(
    r"(?<!\|)\|(?!\|)\s*(?:bash|sh|zsh|cmd(?:\.exe)?|iex|invoke-expression|python3?|node)\b",
    re.IGNORECASE,
)
_BACKGROUND = re.compile(r"&\s*$|nohup\b|disown\b|start-job|&\s*\n")
_ENCODED = re.compile(r"base64\s+-d|-encodedcommand|frombase64string|atob\s*\(", re.IGNORECASE)
_HIDDEN_FILE = re.compile(
    r"(?:^|[\s/])\.[A-Za-z0-9][^\s/]*|-windowstyle\s+hidden|-w\s+hidden",
    re.IGNORECASE,
)


def content_findings(
    entry: Entry, ctx: PackageContext, target: str, target_kind: str, max_line: int
) -> list[Finding]:
    if entry.data is None or entry.is_dir:
        return []
    if is_macos_metadata(entry.rel):
        return []
    rel = entry.rel
    name = entry.name
    path = entry.display(target_kind)
    ext = ext_of(name)
    # A UTF-16 or UTF-32 script carries null bytes and would read as binary, so
    # a text BOM overrides the binary check: the dropper rule must still see it.
    is_binary = looks_binary(entry.data) and text_bom(entry.data) is None

    out: list[Finding] = []
    git_hook = ctx.hook_name(rel)

    # The whole member is decoded. GH601 is a manual scan over full lines; the
    # regex rules read bounded segments that together cover every character,
    # so a payload past the visible edge of a long line is still read.
    text = decode_text(entry.data)
    lines = text.split("\n")
    scan_601 = (ext in CODE_EXTS or is_toolchain_config(rel)) and not _vendored(rel)
    if scan_601:
        for lineno, line in enumerate(lines, 1):
            for start in _offscreen_starts(line, 100):
                out.append(
                    _mk(
                        "GH601",
                        Severity.BLOCK,
                        target,
                        path,
                        lineno,
                        "Code resumes far to the right of a long run of spaces, out of view.",
                        line[start : start + 120].strip(),
                    )
                )

    segments = line_segments(enumerate(lines, 1), max_line)

    lower = name.lower()
    is_shellish = (
        ext in SHELL_EXTS or lower in ("makefile", "dockerfile") or lower.startswith("dockerfile")
    )
    toolchain = is_toolchain_config(rel)

    at_root = "/" not in _split_layer(rel)[1]
    if ext in WIN_SCRIPT_EXTS and not is_binary:
        out.extend(_gh201(segments, target, path))
    if ext in WSH_JS_EXTS and not is_binary and not any(f.rule_id == "GH201" for f in out):
        out.extend(_gh201_wsh(segments, target, path))
    gh202_scope = ext in WIN_SCRIPT_EXTS or (ext in ROOT_JS_EXTS and at_root)
    if gh202_scope and not is_binary and not any(f.rule_id == "GH201" for f in out):
        out.extend(_gh202(segments, ext, target, path))
    if ext in JS_EXTS and not is_binary:
        out.extend(_gh602_js(segments, target, path))
    if ext in PY_EXTS and not is_binary:
        out.extend(_gh602_py(segments, target, path))
    if is_shellish and not is_binary:
        out.extend(_gh407(segments, target, path))
    if (ext in JS_EXTS or toolchain or is_shellish) and not is_binary:
        out.extend(_gh606(segments, target, path))
    if toolchain and not is_binary:
        out.extend(_gh403(segments, target, path))
    if ext in MD_EXTS and not is_binary:
        out.extend(_gh407(line_segments(_fenced_only(lines), max_line), target, path))
    if git_hook is not None and not git_hook.endswith(".sample"):
        out.extend(_gh301(segments, target, path))
    if is_vscode_tasks(rel) and not is_binary:
        out.extend(_gh501(text, target, path))
    if lower == "package.json" and not is_binary:
        out.extend(_gh401(text, target, path))
    if ctx.is_git_config(rel) and not is_binary:
        out.extend(_gh302(text, segments, target, path))
    if lower == ".gitmodules" and not is_binary:
        out.extend(_gh304(text, target, path))
    if (ext in CODE_EXTS or toolchain) and not is_binary and not _vendored(rel):
        out.extend(_gh603(text, target, path))
    if (ext in JS_EXTS or ext in SHELL_EXTS or ext in WIN_SCRIPT_EXTS) and not is_binary:
        out.extend(_gh605(segments, target, path))
    if is_agent_config(rel) and not is_binary:
        out.extend(_gh504(text, target, path))
    if is_devcontainer(rel) and not is_binary:
        out.extend(_gh503(text, segments, target, path))

    return out


# GH403 ----------------------------------------------------------------------

# A build config has no reason to start a process, open a socket or fetch from
# the network while it loads. These are the Node modules and globals for that.
_REACH_MODULES = r"(?:node:)?(?:child_process|net|http|https|dgram|worker_threads|vm)"
_TOOLCHAIN_REACH = re.compile(
    r"\brequire\s*\(\s*['\"`]" + _REACH_MODULES + r"['\"`]\s*\)"
    r"|\bfrom\s*['\"]" + _REACH_MODULES + r"['\"]"
    r"|\bimport\s*\(\s*['\"`]" + _REACH_MODULES + r"['\"`]\s*\)"
    r"|\bimport\s+['\"]" + _REACH_MODULES + r"['\"]"
    r"|\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b"
)


def _gh403(segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    for lineno, seg in segments:
        found = _TOOLCHAIN_REACH.search(seg)
        if found is not None:
            return [
                _mk(
                    "GH403",
                    Severity.REVIEW,
                    target,
                    path,
                    lineno,
                    "A build config that runs on load starts a process or reaches the "
                    f"network ({found.group(0).strip()}).",
                    _snippet(seg, found.start()),
                    indicators=extract_indicators(seg),
                )
            ]
    return []


# GH603 ----------------------------------------------------------------------

# Characters flagged wherever they appear, strings and comments included: the
# bidirectional embedding, override and isolate controls (the reordering trick
# works inside a string or a comment), the tag characters (text hidden inside a
# string), and the Hangul fillers (invisible yet valid in an identifier, the
# invisible-identifier backdoor).
_ALWAYS_HIDDEN = frozenset(
    chr(code)
    for code in (
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0x3164,
        0xFFA0,
        0x115F,
        0x1160,
        0xE0001,
    )
) | frozenset(chr(code) for code in range(0xE0020, 0xE0080))
# Zero-width non-joiner and joiner and the left-to-right and right-to-left marks
# are ordinary text in Persian, Kurdish, Sinhala and other scripts, and are
# punctuation in an entity table. They are flagged only when both neighbors are
# ASCII identifier characters, where one can split or disguise an ASCII name.
# U+200B, U+2060 and the soft hyphen are not flagged: no language accepts them
# in an identifier, so they cannot hide code.
_BETWEEN_IDENT = frozenset(chr(code) for code in (0x200C, 0x200D, 0x200E, 0x200F))
_ASCII_IDENT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")


def _hidden_in_line(line: str) -> set[str]:
    found = {c for c in line if c in _ALWAYS_HIDDEN}
    for index, char in enumerate(line):
        if char not in _BETWEEN_IDENT:
            continue
        before = line[index - 1] if index > 0 else ""
        after = line[index + 1] if index + 1 < len(line) else ""
        if before in _ASCII_IDENT and after in _ASCII_IDENT:
            found.add(char)
    return found


def _gh603(text: str, target: str, path: str) -> list[Finding]:
    for lineno, line in enumerate(text.split("\n"), 1):
        hits = sorted(_hidden_in_line(line))
        if hits:
            codes = " ".join(f"U+{ord(c):04X}" for c in hits)
            return [
                _mk(
                    "GH603",
                    Severity.REVIEW,
                    target,
                    path,
                    lineno,
                    "The line carries invisible or direction-changing characters.",
                    f"hidden: {codes}",
                )
            ]
    return []


# GH605 ----------------------------------------------------------------------

# High-precision signals for secret theft. A browser name is required next to a
# password or cookie store so ordinary cookie handling is not flagged, and the
# ssh match is a private key, not the .ssh folder in general.
_KEYCHAIN = re.compile(r"find-generic-password\b", re.IGNORECASE)
_SAFE_STORAGE = re.compile(r"\bSafe[\\\s]+Storage\b")
_BROWSER_STORE = re.compile(
    r"(?:Chrome|Chromium|Brave|Edge|Opera|Vivaldi|Yandex)[^\n]{0,60}"
    r"(?:Login[\\\s]*Data|Web[\\\s]*Data|\bCookies\b|Local[\\\s]*State)",
)
_SSH_KEY = re.compile(r"\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b")


def _gh605(segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    for lineno, seg in segments:
        for pattern, what in (
            (_KEYCHAIN, "the keychain password-encryption key"),
            (_SAFE_STORAGE, "the browser safe-storage secret"),
            (_BROWSER_STORE, "a browser saved-password or cookie store"),
            (_SSH_KEY, "a private ssh key"),
        ):
            found = pattern.search(seg)
            if found is not None:
                return [
                    _mk(
                        "GH605",
                        Severity.BLOCK,
                        target,
                        path,
                        lineno,
                        f"The code reaches for {what}.",
                        _snippet(seg, found.start()),
                        indicators=extract_indicators(seg),
                    )
                ]
    return []


# GH504 ----------------------------------------------------------------------


def is_agent_config(rel: str) -> bool:
    flat = rel.replace("!/", "/")
    return bool(_AGENT_CONFIG_PATH.search(flat))


def _gh504(text: str, target: str, path: str) -> list[Finding]:
    parsed = loads_jsonc(text)
    if not isinstance(parsed, dict):
        return []
    found: list[tuple[JsonPath, str]] = []
    _collect_commands(parsed, (), found)
    if not found:
        return []
    commands = [value for _path, value in found]
    joined = " ".join(commands)
    first_command = next((p for p, _v in found if p and p[-1] == "command"), found[0][0])
    line = key_lines(text).get(first_command, 1)
    dangerous = (
        _PIPE_SHELL.search(joined)
        or _PIPE_TO_SHELL.search(joined)
        or _NET.search(joined)
        or _ENCODED.search(joined)
    )
    severity = Severity.BLOCK if dangerous else Severity.REVIEW
    msg = "A coding-agent or editor config starts a process"
    msg += " that reaches the network or a shell." if dangerous else " when the project opens."
    return [
        _mk(
            "GH504",
            severity,
            target,
            path,
            line,
            msg,
            joined[:120],
            indicators=extract_indicators(joined),
        )
    ]


def _collect_commands(
    obj: object, path: JsonPath, found: list[tuple[JsonPath, str]], depth: int = 0
) -> None:
    """Every ``command`` string and ``args`` item, with the path it sits at."""

    if depth > 64:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            here = (*path, str(key))
            if key == "command" and isinstance(value, str):
                found.append((here, value))
            elif key == "args" and isinstance(value, list):
                found.extend((here, str(a)) for a in value if isinstance(a, (str, int, float)))
            else:
                _collect_commands(value, here, found, depth + 1)
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            _collect_commands(item, (*path, index), found, depth + 1)


# GH503 ----------------------------------------------------------------------


def is_devcontainer(rel: str) -> bool:
    flat = rel.replace("!/", "/")
    return bool(_DEVCONTAINER_PATH.search(flat))


_DEVCONTAINER_HOST = ("initializeCommand",)
_DEVCONTAINER_ANY = (
    "initializeCommand",
    "onCreateCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
    "updateContentCommand",
)


def _gh503(text: str, segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    parsed = loads_jsonc(text)
    if not isinstance(parsed, dict):
        return []
    on_host = any(key in parsed for key in _DEVCONTAINER_HOST)
    any_cmd = next((key for key in _DEVCONTAINER_ANY if key in parsed), None)
    if any_cmd is None:
        return []
    severity = Severity.REVIEW
    where = "on the host" if on_host else "in the container"
    msg = f"A devcontainer lifecycle command ({any_cmd}) runs {where}."
    return [
        _mk(
            "GH503",
            severity,
            target,
            path,
            key_lines(text).get((any_cmd,), 1),
            msg,
            any_cmd,
            indicators=_segment_indicators(segments),
        )
    ]


def _is_git_config(rel: str) -> bool:
    flat = rel.replace("!/", "/")
    return flat.endswith(".git/config")


# GH401 ----------------------------------------------------------------------

# The scripts npm runs on a local install (``npm install`` in the project or as
# a dependency). Publish and version scripts are not here: they run only when
# the maintainer publishes, so calling them "runs on install" would be wrong.
_NPM_LIFECYCLE = (
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
    "dependencies",
)
# Only git hook installers count as routine, alone or chained with each other.
_HOOK_INSTALLERS = frozenset({"husky", "husky install", "lefthook install", "simple-git-hooks"})
_INLINE_CODE = re.compile(r"\b(?:node|bun|deno)\b\s+(?:-e|--eval|-p)\b|\bpython3?\b\s+-c\b")
_INLINE_NET = re.compile(
    r"\bfetch\s*\(|require\(\s*['\"](?:node:)?(?:https?|net|dns|dgram|tls)['\"]|"
    r"\burllib\b|\brequests\.|\bsocket\b|XMLHttpRequest",
)


def _is_hook_installer(command: str) -> bool:
    parts = [part.strip() for part in _COMMAND_SEPARATOR.split(command)]
    return all(part in _HOOK_INSTALLERS for part in parts) and any(parts)


def _install_script_is_dangerous(command: str) -> bool:
    if (
        _PIPE_SHELL.search(command)
        or _BASE64_PIPE_SHELL.search(command)
        or _PIPE_TO_SHELL.search(command)
        or _NET.search(command)
        or _ENCODED.search(command)
    ):
        return True
    if _INLINE_CODE.search(command):
        return bool(
            _INLINE_NET.search(command) or _JS_DECODE.search(command) or _PY_DECODE.search(command)
        )
    return False


def _gh401(text: str, target: str, path: str) -> list[Finding]:
    parsed = loads_jsonc(text)
    if not isinstance(parsed, dict):
        return []
    scripts = parsed.get("scripts")
    if not isinstance(scripts, dict):
        return []
    lines = key_lines(text)
    out: list[Finding] = []
    for key in _NPM_LIFECYCLE:
        command = scripts.get(key)
        if not isinstance(command, str) or not command.strip():
            continue
        if _is_hook_installer(command):
            continue
        dangerous = _install_script_is_dangerous(command)
        severity = Severity.BLOCK if dangerous else Severity.REVIEW
        msg = f"The '{key}' script runs on npm install"
        if dangerous:
            msg += " and reaches the network, pipes into a shell, or decodes a payload."
        else:
            msg += " and runs code beyond a git hook installer."
        line = lines.get(("scripts", key), 1)
        out.append(
            _mk(
                "GH401",
                severity,
                target,
                path,
                line,
                msg,
                command[:120],
                indicators=extract_indicators(command),
            )
        )
    return out


# GH302 ----------------------------------------------------------------------

# git config keys whose value git runs as a command or a program, as
# (section, key) with both lowercased, checked against ``git help config``. A
# subsection (the "name" in [diff "name"]) is ignored for the match, so
# diff.<any>.command counts. Every key in the ``pager`` section names a command
# too (pager.<cmd> = <command>). Keys marked below run something only for some
# values; ``_runs_command`` holds those conditions.
_GIT_COMMAND_KEYS = frozenset(
    {
        ("core", "editor"),
        ("core", "pager"),
        ("core", "sshcommand"),
        ("core", "askpass"),
        ("core", "fsmonitor"),  # a string value is a command; a boolean is not
        ("core", "hookspath"),
        ("core", "gitproxy"),
        ("core", "alternaterefscommand"),
        ("sequence", "editor"),
        ("diff", "external"),
        ("diff", "command"),
        ("diff", "textconv"),
        ("difftool", "cmd"),
        ("difftool", "path"),
        ("merge", "driver"),
        ("mergetool", "cmd"),
        ("mergetool", "path"),
        ("filter", "clean"),
        ("filter", "smudge"),
        ("filter", "process"),
        ("gpg", "program"),
        ("gpg", "defaultkeycommand"),
        ("credential", "helper"),
        ("interactive", "difffilter"),
        ("remote", "uploadpack"),
        ("remote", "receivepack"),
        ("remote", "vcs"),
        ("uploadpack", "packobjectshook"),
        ("gc", "recentobjectshook"),
        ("hook", "command"),
        ("sendemail", "sendmailcmd"),
        ("sendemail", "smtpserver"),  # a full path is a program; a host name is not
        ("sendemail", "tocmd"),
        ("sendemail", "cccmd"),
        ("sendemail", "headercmd"),
        ("imap", "tunnel"),
        ("tar", "command"),
        ("trailer", "command"),
        ("trailer", "cmd"),
        ("browser", "cmd"),
        ("browser", "path"),
        ("man", "cmd"),
        ("man", "path"),
        ("guitool", "cmd"),
        ("instaweb", "httpd"),
    }
)
# The values git reads as a boolean for a key that is either a boolean or a
# command (core.fsmonitor, pager.<cmd>).
_GIT_BOOLEANS = frozenset({"true", "false", "yes", "no", "on", "off", "1", "0", ""})
_EXT_TRANSPORT = re.compile(r"(?:ext|fd)::")
_GITCFG_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
_GITCFG_SECTION_NAME = re.compile(r"[A-Za-z0-9.-]*")
_GITCFG_BLANK = re.compile(r"[ \t\r\f\v]+")
_GITCFG_NEWLINES = re.compile(r"\n+")
# Characters that end a plain run inside a value.
_GITCFG_VALUE_STOP = re.compile(r'[\\"#;\n \t]')
_GITCFG_ESCAPES = {"n": "\n", "t": "\t", "b": "\b", "\\": "\\", '"': '"'}


def _line_end(text: str, index: int) -> int:
    end = text.find("\n", index)
    return len(text) if end < 0 else end


def _git_section_header(text: str, index: int) -> tuple[str, str, int] | None:
    """Read a section header from just after its ``[``.

    Returns the section (lowercased), the subsection and the index just past
    the closing ``]``, or None for a header git would reject. ``[section
    "subsection"]`` keeps the subsection's case and reads ``\\"`` and ``\\\\``
    inside it; the older ``[section.subsection]`` is lowercased whole.
    """

    n = len(text)
    name = _GITCFG_SECTION_NAME.match(text, index)
    raw = name.group(0).lower() if name is not None else ""
    pos = name.end() if name is not None else index
    if not raw:
        return None
    section, _, dotted = raw.partition(".")
    if pos < n and text[pos] == "]":
        return section, dotted, pos + 1
    blank = _GITCFG_BLANK.match(text, pos)
    if blank is None:
        return None
    pos = blank.end()
    if pos >= n or text[pos] != '"':
        return None
    pos += 1
    chars: list[str] = []
    while pos < n and text[pos] != '"':
        char = text[pos]
        if char == "\n":
            return None
        if char == "\\":
            if pos + 1 >= n or text[pos + 1] == "\n":
                return None
            char = text[pos + 1]
            pos += 1
        chars.append(char)
        pos += 1
    if pos + 1 >= n or text[pos + 1] != "]":
        return None
    quoted = "".join(chars)
    return section, (f"{dotted}.{quoted}" if dotted else quoted), pos + 2


def _git_config_value(text: str, index: int, line: int) -> tuple[str, int, int]:
    """Read one value from just after its ``=``, the way git reads it.

    Quotes are removed and keep what is inside them as written; a backslash
    escape is decoded; a backslash at the end of a line continues the value on
    the next line; ``#`` or ``;`` outside quotes starts a comment; blanks at the
    start and the end are dropped. Returns the value, the index where it ends
    (a newline or the end of the text) and the line number reached.
    """

    n = len(text)
    parts: list[str] = []
    quoted = False
    space = ""
    while index < n:
        stop = _GITCFG_VALUE_STOP.search(text, index)
        end = n if stop is None else stop.start()
        if end > index:
            if space:
                parts.append(space)
                space = ""
            parts.append(text[index:end])
            index = end
            if stop is None:
                break
        char = text[index]
        if char == "\n":
            break
        if char in " \t":
            if quoted:
                parts.append(char)
            elif parts:
                space += char
            index += 1
            continue
        if char in "#;":
            if quoted:
                parts.append(char)
                index += 1
                continue
            index = _line_end(text, index)
            break
        if space:
            parts.append(space)
            space = ""
        if char == '"':
            quoted = not quoted
            index += 1
            continue
        following = text[index + 1] if index + 1 < n else ""
        if following == "\n":
            line += 1
        else:
            parts.append(_GITCFG_ESCAPES.get(following, following))
        index += 2
    return "".join(parts), index, line


def _git_config_entries(text: str) -> list[tuple[str, str, str, str, int]]:
    """Each assignment as (section, subsection, key, value, line number).

    Read the way git reads a config (see ``_git_section_header`` and
    ``_git_config_value``). A key with no ``=`` is a boolean and is not listed;
    neither is a key before the first section. A line git would reject is
    skipped and the rest of the file is still read. One pass over the text.
    """

    text = text.replace("\r\n", "\n")
    entries: list[tuple[str, str, str, str, int]] = []
    section = subsection = ""
    n = len(text)
    index = 0
    line = 1
    while index < n:
        char = text[index]
        if char == "\n":
            run = _GITCFG_NEWLINES.match(text, index)
            end = run.end() if run is not None else index + 1
            line += end - index
            index = end
            continue
        blank = _GITCFG_BLANK.match(text, index)
        if blank is not None:
            index = blank.end()
            continue
        if char in "#;":
            index = _line_end(text, index)
            continue
        if char == "[":
            header = _git_section_header(text, index + 1)
            if header is None:
                index = _line_end(text, index)
                continue
            section, subsection, index = header
            continue
        key = _GITCFG_KEY.match(text, index)
        if key is None:
            index = _line_end(text, index)
            continue
        start = line
        index = key.end()
        blank = _GITCFG_BLANK.match(text, index)
        if blank is not None:
            index = blank.end()
        if index < n and text[index] == "=":
            value, index, line = _git_config_value(text, index + 1, line)
            if section:
                entries.append((section, subsection, key.group(0).lower(), value, start))
        else:
            index = _line_end(text, index)
    return entries


def _runs_command(section: str, key: str, value: str) -> bool:
    """Whether git runs this key's value as a command or a program."""

    plain = value.strip().lower()
    if section == "pager":
        return plain not in _GIT_BOOLEANS
    if (section, key) not in _GIT_COMMAND_KEYS:
        return False
    if (section, key) == ("core", "fsmonitor"):
        return plain not in _GIT_BOOLEANS
    if (section, key) == ("sendemail", "smtpserver"):
        return plain.startswith(("/", "~", "."))
    return True


def _gh302_findings(text: str, target: str, path: str) -> list[Finding]:
    """The assignments in one git config file that run a command or reach
    beyond the file. An include is never followed: it is a REVIEW, since what
    the included file sets was not read."""

    out: list[Finding] = []
    for section, sub, key, value, lineno in _git_config_entries(text):
        severity = Severity.BLOCK
        if section in ("include", "includeif") and key == "path":
            severity = Severity.REVIEW
            message = (
                "A git config includes another config file; it is not followed, so what "
                "that file sets was not read."
            )
        elif section == "protocol" and key == "allow" and value.strip().lower() == "always":
            severity = Severity.REVIEW
            message = (
                "A git config always allows a transport, which lifts git's default refusal "
                "of command transports."
            )
        elif _runs_command(section, key, value):
            message = (
                f"A git config key sets a command in {section}.{key} that runs on a git action."
            )
        elif value.lstrip().startswith("!"):
            message = "A git config key sets a shell alias or helper that runs on a git action."
        elif _EXT_TRANSPORT.search(value) or (section == "url" and _EXT_TRANSPORT.search(sub)):
            message = "A git config key sets a command transport that runs on a git action."
        else:
            continue
        name = f"{section}.{sub}.{key}" if sub else f"{section}.{key}"
        out.append(
            _mk(
                "GH302",
                severity,
                target,
                path,
                lineno,
                message,
                f"{name} = {value}"[:120],
                indicators=extract_indicators(value),
            )
        )
    return out


def _gh302(text: str, segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    """The most severe GH302 finding in the file, the first one among equals."""

    found = _gh302_findings(text, target, path)
    if not found:
        return []
    return [max(found, key=lambda finding: finding.severity.rank)]


# GH304 ----------------------------------------------------------------------

_GITMOD_DANGER = (
    (re.compile(r"(?im)^[ \t]*update[ \t]*=[ \t]*!"), "runs a command on update"),
    (
        re.compile(r"(?im)^[ \t]*url[ \t]*=[ \t]*(?:ext::|fd::|file://)"),
        "points at a local or command source",
    ),
)


def _gh304(text: str, target: str, path: str) -> list[Finding]:
    for pattern, what in _GITMOD_DANGER:
        match = pattern.search(text)
        if match is not None:
            line = text[: match.start()].count("\n") + 1
            return [
                _mk(
                    "GH304",
                    Severity.BLOCK,
                    target,
                    path,
                    line,
                    f"A submodule entry {what}.",
                    match.group(0).strip()[:120],
                )
            ]
    return []


def is_vscode_tasks(rel: str) -> bool:
    flat = rel.replace("!/", "/")
    return bool(_VSCODE_TASKS_PATH.search(flat))


def _gh501(text: str, target: str, path: str) -> list[Finding]:
    parsed = loads_jsonc(text)
    if not isinstance(parsed, dict):
        return []
    tasks = parsed.get("tasks")
    if not isinstance(tasks, list):
        return []
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            continue
        run_options = task.get("runOptions")
        if not isinstance(run_options, dict):
            continue
        if run_options.get("runOn") != "folderOpen":
            continue
        command = _task_command_text(task)
        net = _NET.search(command) is not None
        pipe = _PIPE_TO_SHELL.search(command) is not None
        hidden = _HIDDEN_FILE.search(command) is not None
        dangerous = net or pipe or hidden
        severity = Severity.BLOCK if dangerous else Severity.REVIEW
        msg = "An editor task runs by itself when the folder is opened"
        msg += " and reaches the network or a shell." if dangerous else "."
        line = key_lines(text).get(("tasks", index, "runOptions", "runOn"), 1)
        return [
            _mk(
                "GH501",
                severity,
                target,
                path,
                line,
                msg,
                command[:120],
                indicators=extract_indicators(command),
            )
        ]
    return []


def _task_command_text(task: dict[str, object]) -> str:
    parts: list[str] = []
    command = task.get("command")
    if isinstance(command, str):
        parts.append(command)
    args = task.get("args")
    if isinstance(args, list):
        parts.extend(str(a) for a in args if isinstance(a, (str, int, float)))
    return " ".join(parts)


def _gh201(segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    dl = wr = ex = None
    indicators: dict[tuple[str, str], Indicator] = {}
    for lineno, seg in segments:
        for ind in extract_indicators(seg):
            indicators[(ind.kind, ind.value)] = ind
        if dl is None and _WIN_DOWNLOAD.search(seg):
            dl = lineno
        if wr is None and _WIN_WRITE.search(seg):
            wr = lineno
        if ex is None and _WIN_EXEC.search(seg):
            ex = lineno
    if dl is not None and wr is not None and ex is not None:
        line = min(dl, wr, ex)
        return [
            _mk(
                "GH201",
                Severity.BLOCK,
                target,
                path,
                line,
                "The script downloads a file, saves it, then runs it.",
                f"download line {dl}, write line {wr}, run line {ex}",
                indicators=tuple(indicators.values()),
            )
        ]
    return []


def _gh201_wsh(segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    for lineno, seg in segments:
        found = _WSH_SIGNAL.search(seg)
        if found is not None:
            return [
                _mk(
                    "GH201",
                    Severity.BLOCK,
                    target,
                    path,
                    lineno,
                    "The JavaScript uses Windows Script Host objects, which only a "
                    "double-click on Windows runs.",
                    _snippet(seg, found.start()),
                    indicators=_segment_indicators(segments),
                )
            ]
    return []


def _gh202(segments: list[tuple[int, str]], ext: str, target: str, path: str) -> list[Finding]:
    """Grade a Windows script by the download and run steps it contains."""

    first: dict[str, int] = {}

    def seen(step: str, lineno: int) -> None:
        first.setdefault(step, lineno)

    write = run = decode = None
    for lineno, seg in segments:
        if _STEP_NETWORK.search(seg):
            seen("a download", lineno)
        if _STEP_RUN_IN_MEMORY.search(seg):
            seen("an in-memory run", lineno)
        if ext in _VBS_FAMILY and _STEP_VBS_EXECUTE.search(seg):
            seen("an in-memory run", lineno)
        if ext in _JSCRIPT_FAMILY and _STEP_JS_EVAL.search(seg):
            seen("an in-memory run", lineno)
        if _STEP_ENCODED.search(seg):
            seen("an encoded command", lineno)
        if _STEP_HIDDEN.search(seg):
            seen("a hidden window", lineno)
        if _STEP_HELPER.search(seg):
            seen("a script-host helper", lineno)
        if write is None and _WIN_WRITE.search(seg):
            write = lineno
        if run is None and _WIN_EXEC.search(seg):
            run = lineno
        if decode is None and _STEP_DECODE.search(seg):
            decode = lineno
    if write is not None and run is not None:
        seen("a write then a run", min(write, run))
    if decode is not None and run is not None:
        seen("a decode then a run", min(decode, run))
    if not first:
        return []
    steps = sorted(first, key=lambda step: (first[step], step))
    cradle = "a download" in first and bool(
        {"an in-memory run", "a script-host helper", "an encoded command"} & set(first)
    )
    line = min(first.values())
    evidence = ", ".join(f"{step} line {first[step]}" for step in steps)
    if cradle:
        return [
            _mk(
                "GH202",
                Severity.BLOCK,
                target,
                path,
                line,
                "The script downloads code and runs it in memory, without saving a file "
                "you could inspect.",
                evidence,
                indicators=_segment_indicators(segments),
            )
        ]
    return [
        _mk(
            "GH202",
            Severity.REVIEW,
            target,
            path,
            line,
            f"The script contains {_join_steps(steps)}, one step of a download-and-run chain.",
            evidence,
            indicators=_segment_indicators(segments),
        )
    ]


def _join_steps(steps: list[str]) -> str:
    if len(steps) == 1:
        return steps[0]
    return ", ".join(steps[:-1]) + " and " + steps[-1]


def _gh602_js(segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    """eval, Function or vm.run* fed by a decode or assemble primitive.

    Both must sit in the same line or off-screen segment: an evaluator in a
    test harness and an unrelated atob elsewhere in the file are not a decoded
    string run as code. Measuring a file-wide window turned minified bundles
    (next, nx, aiohttp and more) into false positives, so the window is one
    segment.
    """

    for lineno, seg in segments:
        found = _JS_EXEC.search(seg)
        if found is not None and _JS_DECODE.search(seg):
            return [
                _mk(
                    "GH602",
                    Severity.BLOCK,
                    target,
                    path,
                    lineno,
                    "A decoded or assembled string is run as code.",
                    _snippet(seg, found.start()),
                )
            ]
    return []


def _gh602_py(segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    """exec, eval or compile with a decode primitive within five lines.

    A definition named eval is not a call, which the leading negative lookbehind
    rules out, and a decode far away in a large module is not feeding it.
    """

    decode_lines = {lineno for lineno, seg in segments if _PY_DECODE.search(seg)}
    if not decode_lines:
        return []
    for lineno, seg in segments:
        found = _PY_EXEC.search(seg)
        if found is None:
            continue
        if any(abs(lineno - d) <= _DECODE_REACH for d in decode_lines):
            return [
                _mk(
                    "GH602",
                    Severity.BLOCK,
                    target,
                    path,
                    lineno,
                    "A decoded or assembled string is run as code.",
                    _snippet(seg, found.start()),
                )
            ]
    return []


def _gh606(segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    for lineno, seg in segments:
        found = _ETH_RPC.search(seg)
        if found is not None:
            return [
                _mk(
                    "GH606",
                    Severity.REVIEW,
                    target,
                    path,
                    lineno,
                    "A blockchain remote call sits in a config or script, where it does not fit.",
                    _snippet(seg, found.start()),
                    indicators=extract_indicators(seg),
                )
            ]
    return []


def _gh407(segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    pipe_line = None
    evidence = ""
    indicators: list[Indicator] = []
    persistence = False
    for lineno, seg in segments:
        found = (
            (_PIPE_SHELL.search(seg) or _BASE64_PIPE_SHELL.search(seg))
            if pipe_line is None
            else None
        )
        if found is not None:
            pipe_line = lineno
            evidence = _snippet(seg, found.start())
            indicators.extend(extract_indicators(seg))
        if _PERSISTENCE.search(seg):
            persistence = True
    if pipe_line is None:
        return []
    severity = Severity.BLOCK if persistence else Severity.REVIEW
    msg = "A remote script is fetched and run through a shell"
    msg += " and a persistence step is installed." if persistence else "."
    return [
        _mk("GH407", severity, target, path, pipe_line, msg, evidence, indicators=tuple(indicators))
    ]


def _gh301(segments: list[tuple[int, str]], target: str, path: str) -> list[Finding]:
    net = any(_NET.search(seg) for _line, seg in segments)
    pipe = any(_PIPE_TO_SHELL.search(seg) for _line, seg in segments)
    background = any(_BACKGROUND.search(seg) for _line, seg in segments)
    encoded = any(_ENCODED.search(seg) for _line, seg in segments)
    dangerous = net or pipe or background or encoded
    severity = Severity.BLOCK if dangerous else Severity.REVIEW
    line = 1
    for lineno, seg in segments:
        if _NET.search(seg) or _PIPE_TO_SHELL.search(seg) or _ENCODED.search(seg):
            line = lineno
            break
    signals = []
    if net:
        signals.append("network")
    if pipe:
        signals.append("pipe into a shell")
    if background:
        signals.append("background run")
    if encoded:
        signals.append("encoded payload")
    detail = ", ".join(signals) if signals else "runs on a git action"
    msg = "A git hook runs automatically on a git action"
    msg += f" and reaches the {detail}." if dangerous else "."
    indicators = _segment_indicators(segments)
    return [_mk("GH301", severity, target, path, line, msg, detail, indicators=indicators)]


def _fenced_only(lines: list[str]) -> list[tuple[int, str]]:
    """Markdown GH407 only looks inside fenced code blocks and at shell-prompt lines."""

    out: list[tuple[int, str]] = []
    fenced = False
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced or stripped.startswith("$ "):
            out.append((lineno, line))
    return out


# Long lines are read in windows of ``max_line`` characters that overlap by this
# much, so a match that straddles a window edge is still seen whole.
WINDOW_OVERLAP = 256


def line_segments(lines: Iterable[tuple[int, str]], max_line: int) -> list[tuple[int, str]]:
    """Cut numbered lines into bounded segments that together cover every character.

    A line within ``max_line`` is one segment. A longer line becomes overlapping
    windows that all carry its line number, so a regex rule never runs on more
    than ``max_line`` characters at once and never misses the end of a line.
    """

    width = max(1, max_line)
    step = max(1, width - min(WINDOW_OVERLAP, width // 4))
    out: list[tuple[int, str]] = []
    for lineno, line in lines:
        if len(line) <= width:
            out.append((lineno, line))
            continue
        start = 0
        while True:
            out.append((lineno, line[start : start + width]))
            if start + width >= len(line):
                break
            start += step
    return out


def _segment_indicators(segments: list[tuple[int, str]]) -> tuple[Indicator, ...]:
    """Indicators from every segment, de-duplicated, in first-seen order."""

    found: dict[tuple[str, str], Indicator] = {}
    for _lineno, seg in segments:
        for ind in extract_indicators(seg):
            found.setdefault((ind.kind, ind.value), ind)
    return tuple(found.values())


def _snippet(seg: str, pos: int) -> str:
    """Evidence text around ``pos``: the segment start, or the match when it sits far in."""

    if pos <= 100:
        return seg.strip()[:120]
    return seg[pos - 20 : pos + 100].strip()


def _offscreen_starts(line: str, threshold: int) -> list[int]:
    starts: list[int] = []
    n = len(line)
    i = 0
    code_before = False
    while i < n:
        char = line[i]
        if char in " \t":
            j = i
            while j < n and line[j] in " \t":
                j += 1
            if (j - i) >= threshold and code_before and j < n:
                starts.append(j)
            i = j
        else:
            code_before = True
            i += 1
    return starts


def _vendored(rel: str) -> bool:
    low = rel.lower()
    return any(marker in low for marker in VENDORED)


# ---------------------------------------------------------------------------
# Package-level and standard-library-shadow rules
# ---------------------------------------------------------------------------

_STDLIB = frozenset(sys.stdlib_module_names)


def rule_shadow(entry: Entry, ctx: PackageContext, target: str, target_kind: str) -> list[Finding]:
    """A standard-module name where Python would be started: the root of a
    layer, or the single folder a zip usually wraps everything in."""

    if entry.is_dir:
        return []
    name = entry.name
    if not name.endswith(".py"):
        return []
    stem = name[:-3]
    layer, inner = _split_layer(entry.rel)
    if stem in _STDLIB and (layer, _parent(inner)) in ctx.start_dirs:
        path = entry.display(target_kind)
        return [
            _mk(
                "GH405",
                Severity.REVIEW,
                target,
                path,
                0,
                f"A file named like the standard module '{stem}' is imported before the real one.",
                name,
            )
        ]
    return []


def dependency_message(folder: str) -> str:
    """What a shipped dependency or compiled-cache folder does, in one sentence."""

    name = folder.replace("!/", "/").rstrip("/").rsplit("/", 1)[-1]
    if name == "node_modules":
        return (
            "The package ships its installed JavaScript dependencies (node_modules); "
            "npm run and the build use these copies, not fresh ones from the registry."
        )
    if name == "__pycache__":
        return (
            "The package ships compiled Python files (__pycache__); Python can load them "
            "instead of the source files next to them."
        )
    return (
        f"The package ships a Python environment ({name}); anything run from it uses "
        "whatever was installed in it, not what the manifest asks for."
    )


def rule_dependency_folders(ctx: PackageContext, target: str, target_kind: str) -> list[Finding]:
    out: list[Finding] = []
    for folder in ctx.dep_dirs:
        path = Entry(rel=folder).display(target_kind)
        out.append(
            _mk(
                "GH109",
                Severity.REVIEW,
                target,
                path,
                0,
                dependency_message(folder),
                folder.replace("!/", "/").rsplit("/", 1)[-1],
            )
        )
    return out


def rule_git_present(ctx: PackageContext, target: str, target_kind: str) -> list[Finding]:
    """A .git folder is noted; a .git file that points git at a repository
    folder is a REVIEW, since that folder is never followed."""

    out: list[Finding] = []
    if ctx.has_git:
        path = Entry(rel=ctx.git_root).display(target_kind) if target_kind != "file" else ".git"
        out.append(
            _mk(
                "GH108",
                Severity.INFO,
                target,
                path,
                0,
                "The package is a git repository, so git commands in it can run its hooks "
                "and config.",
                ".git",
            )
        )
    for rel in ctx.git_files:
        out.append(
            _mk(
                "GH108",
                Severity.REVIEW,
                target,
                Entry(rel=rel).display(target_kind),
                0,
                "A .git file points git at a repository folder (gitdir); that folder is not "
                "followed, so its hooks and config were not read.",
                ".git",
            )
        )
    return out


def rule_app_bundles(ctx: PackageContext, target: str, target_kind: str) -> list[Finding]:
    """A macOS application bundle anywhere in the package is BLOCK, once per bundle."""

    out: list[Finding] = []
    for bundle in ctx.app_bundles:
        name = bundle.rsplit("!/", 1)[-1].rsplit("/", 1)[-1]
        out.append(
            _mk(
                "GH101",
                Severity.BLOCK,
                target,
                Entry(rel=bundle).display(target_kind),
                0,
                "A macOS application bundle (.app) is inside this package; it runs on "
                "double-click.",
                name,
            )
        )
    return out


def _mk(
    rule_id: str,
    severity: Severity,
    target: str,
    path: str,
    line: int,
    message: str,
    evidence: str,
    *,
    indicators: tuple[Indicator, ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        target=target,
        path=path,
        line=line,
        message=message,
        evidence=escape_controls(defang(evidence)),
        indicators=indicators,
    )
