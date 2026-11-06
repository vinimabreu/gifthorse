"""The one place every rule's metadata lives.

``docs/RULES.md`` is generated from this tuple and a test fails if the file and
the tuple disagree. Ids are stable and never reused. ``trigger`` and
``next_step`` are written for a reader with no security background: the first
names the everyday action that would set the rule off, the second says what to
do instead. Nothing here is a working command; the text is description, not a
sample.
"""

from __future__ import annotations

from .model import Rule, Severity

B = Severity.BLOCK
R = Severity.REVIEW
INFO = Severity.INFO

RULES: tuple[Rule, ...] = (
    Rule(
        id="GH101",
        title="Executable or script inside a package",
        family="package",
        severity=B,
        means=(
            "A file that runs or mounts on open sits inside a package: a Windows "
            "program or script, a macOS or Linux launcher, a disk image, or a "
            "macro-enabled Office file, or a macOS application bundle (a Name.app "
            "folder holding Contents/MacOS). In a plain document package any script "
            "or executable is out of place. Under a confirmed code-project "
            "manifest, a binary program or disk image one folder or more below it "
            "is a REVIEW, since installers and test fixtures ship that way, and one "
            "in the manifest's own folder stays BLOCK; another launcher (.reg, "
            ".command, .scpt, .terminal, .desktop), a OneNote file or a "
            "macro-enabled Office file anywhere under it is a REVIEW. A Windows "
            "script (.bat, .cmd, .ps1) "
            "or JavaScript at the package root is quiet there only when its content "
            "was read and holds no download-write-run chain; a .vbs read that way is "
            "still a REVIEW; unread (names only, encrypted, past a limit) either "
            "stays BLOCK. Only a manifest whose content confirms it makes a code "
            "project: a .git, src or .github folder does not. Application bundles, "
            "shortcuts, "
            "screensavers, script-host files, shell link formats (.url, "
            ".library-ms, .search-ms, .settingcontent-ms, .appref-ms), management "
            "consoles (.msc) and Excel add-ins (.xll) are BLOCK everywhere."
        ),
        why=(
            "A brief or a set of screenshots has no reason to carry a program. "
            "This is how a download-and-run payload travels disguised as paperwork."
        ),
        trigger="when you double-click the file or open it on Windows",
        next_step="do not open it; ask the sender for a PDF or plain text",
        also=(R,),
        when=(
            "for a binary program or a disk image one folder or more below a "
            "confirmed project manifest, another launcher, a OneNote file or a "
            "macro-enabled Office file anywhere under one, or a .vbs read in full "
            "with no chain inside a confirmed project"
        ),
    ),
    Rule(
        id="GH102",
        title="Misleading file name",
        family="name",
        severity=B,
        means=(
            "A name that hides what the file is: a second real extension after "
            "a document one, a long run of spaces before the extension, or a "
            "direction-changing or invisible character in the name."
        ),
        why=(
            "The eye reads the name as a document while the system runs the real "
            "extension. The spacing and the hidden characters exist only to fool you."
        ),
        trigger="when you double-click what looks like a document",
        next_step="do not open it; judge the file by its last real extension",
    ),
    Rule(
        id="GH103",
        title="Path escape or link member",
        family="name",
        severity=B,
        means=(
            "An archive member whose path climbs out of the folder, is absolute or "
            "names a drive letter, or a link whose target does. A link to another "
            "file inside the archive is noted as info and not followed."
        ),
        why=(
            "Unpacking it can drop a file outside the folder you chose, over a "
            "file you already trust, or make a link that later reads somewhere else."
        ),
        trigger="when you extract the archive",
        next_step="do not extract it; ask the sender for a flat archive",
        also=(INFO,),
        when=("for a link to another file inside the package"),
    ),
    Rule(
        id="GH104",
        title="Content could not be inspected",
        family="archive",
        severity=R,
        means=(
            "Something present could not be read as a regular file: an encrypted "
            "member, an archive or payload in a format this tool does not read for "
            "content, a FIFO, socket or device, an unreadable folder or file, or a "
            "link. A link is never followed, whatever it points at, so every link "
            "in the package is a REVIEW. The name is known, the content is not."
        ),
        why=(
            "An encrypted or unreadable member can carry anything. A clean result "
            "on the rest of the package does not clear what could not be read."
        ),
        trigger="when you open or extract the part that could not be read",
        next_step=(
            "ask the sender for a plain zip or tar with no password and no links, "
            "then scan it again"
        ),
    ),
    Rule(
        id="GH105",
        title="Resource limit reached",
        family="limits",
        severity=R,
        means=(
            "The package hit a built-in limit: too many entries, too many bytes, "
            "too deeply nested, a single member larger than the per-file limit, or "
            "a compressed file made of more streams than the stream limit. "
            "Names past the entry limit are still checked; their content is not read."
        ),
        why=(
            "Past the limit the tool stopped to stay safe and fast, so part of the "
            "package was not inspected. A huge or deeply nested package is itself a sign."
        ),
        trigger="when you unpack the whole package",
        next_step="do not rely on this result; open it only in a disposable virtual machine",
    ),
    Rule(
        id="GH108",
        title="Package contains a git repository",
        family="git",
        severity=INFO,
        means=(
            "The package carries a .git folder, so it is a repository, not just "
            "files. A .git file that points git at a repository folder (gitdir) is "
            "a REVIEW: that folder is not followed, so its hooks and config were "
            "not read."
        ),
        why=(
            "A repository can run code the moment you check out a branch or make a "
            "commit, through its hooks and config, with no install step."
        ),
        trigger="when you run git checkout or git commit inside it",
        next_step="read the git hooks and config before you run any git command in it",
        also=(R,),
        when=("for a .git file that points git at a repository folder, which is not followed"),
    ),
    Rule(
        id="GH201",
        title="Download, write and run chain in a Windows script",
        family="windows-script",
        severity=B,
        means=(
            "A Windows script fetches a file from the network, saves it to disk, "
            "and then runs it. All three steps in one file."
        ),
        why=(
            "This is the core of a dropper: it pulls the real payload after you "
            "open the harmless-looking script, so the package itself looks clean."
        ),
        trigger="when you double-click the script on Windows",
        next_step="report it; use the --iocs block for the hosts it would contact",
    ),
    Rule(
        id="GH202",
        title="Downloads and runs code in memory",
        family="windows-script",
        severity=B,
        means=(
            "A Windows script (.bat, .cmd, .ps1, .psm1, .vbs, .vbe, .wsf, .wsh, .hta, "
            ".jse) or a JavaScript file at the package root that fetches code from "
            "the network and runs it without saving a file: a download (Invoke-"
            "WebRequest, iwr, Invoke-RestMethod, Net.WebClient, DownloadString or "
            "DownloadFile, Start-BitsTransfer, bitsadmin, certutil -urlcache, curl, "
            "wget, an XMLHTTP or WinHttp object) together with an in-memory run "
            "(IEX, Invoke-Expression, VBScript Execute or ExecuteGlobal, JScript "
            "eval), an encoded command, or a script-host helper (mshta, rundll32, "
            "regsvr32, cscript or wscript running another script)."
        ),
        why=(
            "This is the download cradle: nothing is written for you to inspect, "
            "and what runs is whatever the server sends at that moment. A single "
            "step on its own is not always hostile, but a script that came with a "
            "package has to be read before anything runs it."
        ),
        trigger="when you double-click the script or run it on Windows",
        next_step="do not run it; read the whole script, and report it with the --iocs block",
        also=(R,),
        when=(
            "for one step on its own: a download, an in-memory run, an encoded "
            "command, a hidden window, a script-host helper, or a decode or a write "
            "followed by a run"
        ),
    ),
    Rule(
        id="GH301",
        title="Active git hook",
        family="git",
        severity=B,
        means=(
            "A git hook that is not a disabled sample. It runs on a git action. "
            "A hook that reaches the network, pipes into a shell, runs in the "
            "background or carries an encoded payload is the dangerous kind."
        ),
        why=(
            "Hooks run automatically on checkout, commit and other git actions, "
            "with no install and no warning. Reading the README and checking out "
            "the branch it tells you to is enough to run it."
        ),
        trigger="when you run git checkout or git commit",
        next_step=(
            "do not run any git command; open the repository only in a disposable virtual machine"
        ),
        also=(R,),
        when=("for a hook with no network, shell pipe, background run or encoded payload"),
    ),
    Rule(
        id="GH403",
        title="Toolchain config that runs on load",
        family="toolchain",
        severity=B,
        means=(
            "A build or lint config (postcss, tailwind, vite, next, webpack, babel, "
            "eslint, jest and the like) that is loaded and run by the toolchain. "
            "It is BLOCK when the config also carries code pushed off-screen, a "
            "decoded string run as code, or a blockchain lookup (GH601, GH602, "
            "GH606). It is REVIEW when the config requires or imports a process or "
            "network module (child_process, net, http, https, dgram, "
            "worker_threads, vm) or calls fetch, XMLHttpRequest or WebSocket."
        ),
        why=(
            "These files are imported and run the first time you start the dev "
            "server or the build, before any of your own code runs."
        ),
        trigger="when you run the dev server or the build (for example npm run dev)",
        next_step=(
            "do not start the project; open the config and read the whole line, "
            "including far to the right"
        ),
        also=(R,),
        when=(
            "when it only imports a process or network module or calls the "
            "network, with no hidden or self-decoding code"
        ),
    ),
    Rule(
        id="GH405",
        title="File shadows a standard-library module",
        family="python",
        severity=R,
        means=(
            "A file is named like a standard Python module (for example json.py) "
            "and sits where Python would import it first: at the root of the "
            "package, or in the single folder a zip usually wraps everything in."
        ),
        why=(
            "Running any Python from this folder can import this file instead of "
            "the real module, so code runs that you never called."
        ),
        trigger="when Python is started from this folder",
        next_step="do not run Python here; open the file and see what it does on import",
    ),
    Rule(
        id="GH407",
        title="Download piped into a shell",
        family="install",
        severity=R,
        means=(
            "An instruction that fetches a remote script and runs it straight away "
            "through a shell, with nothing checked in between. With a persistence "
            "step (a login agent, a service, a scheduled task) it is worse."
        ),
        why=(
            "You run whatever the server sends at that moment, unreviewed, and a "
            "persistence step makes it survive a reboot and keep running."
        ),
        trigger="when you copy the install line from the README and run it",
        next_step="do not run it; download the script, read it, and decide after that",
        also=(B,),
        when=("together with a persistence step"),
    ),
    Rule(
        id="GH501",
        title="Editor task that runs on folder open",
        family="editor-task",
        severity=B,
        means=(
            "An editor task set to start by itself when the folder is opened. One "
            "that reaches the network, pipes into a shell or runs a hidden file is "
            "the dangerous kind."
        ),
        why=(
            "Just opening the folder in the editor runs it. You never pressed a "
            "button; opening the project was enough."
        ),
        trigger="as soon as you open the folder in the editor",
        next_step=(
            "do not open the folder in the editor; read the task file first in a plain text viewer"
        ),
        also=(R,),
        when=("for a task with no network, shell pipe or hidden file"),
    ),
    Rule(
        id="GH601",
        title="Code pushed off-screen",
        family="obfuscation",
        severity=B,
        means=(
            "On a single line, code resumes after a long run of spaces or tabs, so "
            "it sits far to the right of the real content and stays out of view."
        ),
        why=(
            "The editor shows the harmless left side and hides the payload past the "
            "edge of the window. The spacing has no other purpose."
        ),
        trigger="when the file is loaded by the tool that reads it",
        next_step="do not run the project; read the full line with wrapping on",
    ),
    Rule(
        id="GH602",
        title="Runs a decoded or built string",
        family="obfuscation",
        severity=B,
        means=(
            "Code that decodes or assembles a string and then runs it as a program, "
            "so what runs is not visible in the file as written. In JavaScript the "
            "evaluator and the decode sit on the same line; in Python the exec, eval "
            "or compile call has a decode primitive within five lines. A decode "
            "piped into a shell is caught by GH407 instead."
        ),
        why=(
            "The real instructions are hidden inside an encoded blob and only appear "
            "at run time, which is how a payload avoids a reader's eye and a scanner."
        ),
        trigger="when the file runs, through the build, a script or an import",
        next_step="do not run it; treat a self-decoding file as hostile",
    ),
    Rule(
        id="GH606",
        title="Blockchain lookup used as a config channel",
        family="obfuscation",
        severity=R,
        means=(
            "A build config or install script makes an Ethereum-style remote call "
            "or names a public blockchain node, where a plain project never would."
        ),
        why=(
            "A blockchain record is used as a dead drop for the next address to "
            "contact, so the real server can change without touching the file and "
            "without hitting a blocklist."
        ),
        trigger="when the config or script runs",
        next_step="do not run it; report it with the --iocs block",
        also=(B,),
        when=("when a decoded string is run as code in the same file (GH602)"),
    ),
    Rule(
        id="GH401",
        title="Package install script",
        family="package",
        severity=R,
        means=(
            "A package.json script that npm runs on a local install (preinstall, "
            "install, postinstall, prepublish, prepare and their kin) and that does "
            "more than install git hooks. One that reaches the network, pipes into "
            "a shell or decodes a payload is the dangerous kind."
        ),
        why=(
            "These scripts run automatically during install, before any of your own "
            "code, so a line here runs the moment you set the project up."
        ),
        trigger="when you run npm install or yarn install",
        next_step="do not install it; read the install and prepare scripts first",
        also=(B,),
        when=("when the script reaches the network, pipes into a shell or decodes a payload"),
    ),
    Rule(
        id="GH302",
        title="Git config key that runs a command",
        family="git",
        severity=B,
        means=(
            "A .git/config key whose value git runs as a command or a program on a "
            "git action: a hooks path, an ssh, editor, pager, askpass, gpg, proxy or "
            "credential-helper command, a file monitor, a filter, diff or merge "
            "driver, a diff or merge tool, an upload-pack or receive-pack program, a "
            "send-email, tunnel, archive or trailer command, a shell alias (a value "
            "starting with !), or an ext:: or fd:: transport, in a value or in a url "
            "rewrite. The file is read the way git reads it: quotes, escapes, line "
            "continuations and comments. An include or includeIf is never followed: "
            "it is a REVIEW, and so is a protocol allowed always."
        ),
        why=(
            "These keys turn an ordinary git command into code execution, with no "
            "hook file and no install step to notice."
        ),
        trigger="when you run almost any git command in the repository",
        next_step="do not run git here; read .git/config before you touch it",
        also=(R,),
        when=("for an include or includeIf, which is not followed, or a protocol set to always"),
    ),
    Rule(
        id="GH304",
        title="Submodule that runs a command",
        family="git",
        severity=B,
        means=(
            "A .gitmodules entry that runs a command on update, or points at a "
            "submodule through a local file or a command transport."
        ),
        why=(
            "Updating submodules then runs the command or pulls from a source you "
            "did not expect, during an ordinary checkout step."
        ),
        trigger="when you run git submodule update or a recursive checkout",
        next_step="do not update submodules; read .gitmodules first",
    ),
    Rule(
        id="GH109",
        title="Package ships installed dependencies or compiled files",
        family="package",
        severity=R,
        means=(
            "The package carries a node_modules folder, a Python environment (.venv "
            "or venv) or compiled Python files (__pycache__). In a folder these are "
            "not read, only flagged; in an archive their files are also read."
        ),
        why=(
            "The project runs these copies instead of what its manifest or source "
            "says: npm run dev uses the node_modules that came with it, and Python "
            "can load a shipped .pyc in place of the .py beside it. One modified "
            "file among thousands is easy to miss."
        ),
        trigger="when you run, build or test the project with the files it came with",
        next_step=(
            "delete the shipped dependency folder and reinstall from the official "
            "registry; never run the project with the copy that came with it"
        ),
    ),
    Rule(
        id="GH504",
        title="Coding-agent or editor config that starts a process",
        family="editor-task",
        severity=R,
        means=(
            "A coding-agent or editor config (an MCP server list, or an agent hook "
            "file such as .claude/settings.json) that starts a program. One that "
            "fetches and runs remote code is the dangerous kind."
        ),
        why=(
            "The editor or the agent starts the program for you when the project is "
            "opened or a tool is used, so a server defined here runs without a prompt."
        ),
        trigger="when you open the project in the editor or agent",
        next_step="do not open it there yet; read the server and hook commands first",
        also=(B,),
        when=("when the command reaches the network, pipes into a shell or decodes a payload"),
    ),
    Rule(
        id="GH503",
        title="Devcontainer command that runs on the host",
        family="editor-task",
        severity=R,
        means=(
            "A devcontainer config with a lifecycle command. The initialize command "
            "runs on your machine, not inside the container, before any isolation."
        ),
        why=(
            "Opening the folder in a container-aware editor runs the initialize "
            "command on the host, so the sandbox you expected is not there yet."
        ),
        trigger="when you reopen the folder in a container",
        next_step="do not reopen in a container; read the lifecycle commands first",
    ),
    Rule(
        id="GH603",
        title="Invisible or direction-changing characters in source",
        family="obfuscation",
        severity=R,
        means=(
            "Source code that contains bidirectional embedding, override or isolate "
            "controls, tag characters, or an invisible filler character that is "
            "valid in a name (the Hangul fillers) anywhere, strings and comments "
            "included; or a zero-width joiner or non-joiner or a direction mark "
            "between two ASCII name characters. Each changes what the code reads "
            "as without showing on screen."
        ),
        why=(
            "The code you read and the code that runs can differ when hidden "
            "characters reorder or mask part of a line."
        ),
        trigger="when the file is compiled or run",
        next_step="do not run it; view the file with invisible characters revealed",
    ),
    Rule(
        id="GH605",
        title="Credential or browser-store access",
        family="secrets",
        severity=B,
        means=(
            "Code that reaches for stored secrets: the keychain entry a browser "
            "uses to encrypt saved passwords, a browser's saved-password or cookie "
            "database, or a private ssh key."
        ),
        why=(
            "A task from a stranger has no reason to read your saved passwords, "
            "cookies or keys. This is the step that turns a foothold into stolen "
            "accounts."
        ),
        trigger="when the file runs",
        next_step="do not run it; report it with the --iocs block",
    ),
)

_INDEX = {rule.id: rule for rule in RULES}


def get(rule_id: str) -> Rule:
    return _INDEX[rule_id]


def all_rules() -> tuple[Rule, ...]:
    return RULES
