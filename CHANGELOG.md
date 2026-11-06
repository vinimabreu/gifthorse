# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog, and the project aims to follow semantic versioning once a
release is tagged.

## [Unreleased]

### Added

- Static triage engine that inspects a file, folder or archive without running
  it and returns BLOCK, REVIEW or NO FINDINGS with file, line and defanged
  indicators.
- Archive readers for zip (found from its central directory even with bytes in
  front), tar and its gzip, bzip2 and xz forms (old tars without the ustar
  magic included), single gzip, bzip2 and xz files, and RAR5 names from the
  header format; 7z and RAR4 report as not inspectable.
- Rules GH101, GH102, GH103, GH104, GH105, GH108, GH201, GH202, GH301, GH403,
  GH405, GH407, GH501, GH601, GH602 and GH606, each with a plain-language
  trigger and next step.
- Rules GH109 (shipped dependencies or compiled files), GH302 (git config key
  that runs a command), GH304 (submodule that runs a command), GH401 (package
  install script), GH503 (devcontainer lifecycle command), GH504 (coding-agent
  or editor config that starts a process), GH603 (invisible or
  direction-changing characters in source) and GH605 (credential or
  browser-store access).
- Coverage accounting in every report; a scan that skipped content that could
  hold code can never return NO FINDINGS, and the suite checks that on every
  scan it runs.
- Every rule declares the severities it can emit and when; `docs/RULES.md` and
  `--list-rules` show the range, and the suite checks each finding against it.
- Command line with text and JSON output (schema `gifthorse.report/1`), an
  indicators block, rule listing and per-rule explanation; a typed library API
  (`scan_bytes`, `scan_path`).
- Guarantees with tests: no execution, no disk writes, no symlink following, no
  network, bounded work on hostile input, regex safety with a growth check,
  fuzz tolerance, and a module entry point that refuses to run unless the
  current directory is off the import path (`python -P -m gifthorse`).
- A baseline test that runs a naive extension filter next to gifthorse on the
  synthetic acceptance shapes; the README quotes the measured table.
- `tools/mutation_check.py`, which turns each rule off in turn through a
  test-only seam and fails if the suite does not notice.
- `benchmark/`: the pinned list of 218 popular npm and PyPI packages, the
  scripts that fetch and scan them, and the result per package without any
  text from the packages.

### Changed

Tuned against the 218 packages in `benchmark/`, which first produced 11 BLOCK
false positives:

- GH101: a Windows program file or disk image inside the subtree of a
  code-project manifest is REVIEW instead of BLOCK. A manifest covers only its
  own folder and below, in the same archive layer. A Windows script (.vbs, .bat,
  .cmd, .ps1) or JavaScript at the package root gets that allowance only when
  its content was read and holds no download-write-run chain; names only,
  encrypted or past a limit, it is judged as if the project were not there.
  Shortcuts, screensavers, script-host files (.vbe, .jse, .wsf, .wsh, .hta),
  shell link formats, management consoles and Excel add-ins stay BLOCK
  everywhere.
- GH401: covers only the scripts a local install runs (preinstall, install,
  postinstall, prepublish, preprepare, prepare, postprepare, dependencies).
  `||` is never read as a pipe. Inline node or python code is REVIEW unless it
  reaches the network or decodes a payload. Only git hook installers are routine.
- GH103: link targets are resolved lexically; a link to another member is info,
  and only an absolute or escaping target is BLOCK.
- GH602: in JavaScript, the decode or assemble primitive must sit on the same
  line as eval, Function or vm.run*; in Python, the exec, eval or compile call
  needs a decode primitive within five lines.
- GH603: bidirectional controls and tag characters are flagged everywhere;
  Hangul fillers, direction marks and zero-width joiners only in code outside
  strings and comments, a joiner only inside an ASCII name; U+200B, U+2060 and
  the soft hyphen are not flagged.
- GH102: the decoy extension must be a document or media type.
- Coverage: a skipped entry holds the verdict at REVIEW only when a rule would
  have read its type or its name is an executable, script or archive. Skips
  inside nested archives carry their full path, a single compressed file is
  named after its archive, and a nested 7z or RAR4 is reported as a skip.

### Fixed

From an adversarial review of the first complete build:

- Content rules read only the first 16 KB of each file while counting it as
  inspected. Whole files are now read up to the per-file cap, long lines in
  overlapping windows, and one invalid UTF-8 byte no longer changes how the
  rest of the file decodes.
- The GH302 and GH304 patterns were quadratic on blank lines, and the host,
  download-pipe, write, Function and Buffer.from patterns on repeated tokens.
  All are linear now, and the regex-safety test measures growth on
  newline-heavy and token-heavy input.
- `python -m gifthorse` claimed a file planted in the working directory was
  never imported, which was false. The module now refuses to run without
  `-P`, `PYTHONSAFEPATH=1` or `-I`, and the README states the limit that
  remains (a planted `importlib.py` runs before any package code).
- Coverage holes that could end in NO FINDINGS: a folder walk skipped
  `node_modules`, virtualenvs and `__pycache__` without counting them (now
  GH109 REVIEW, the same verdict as an archive of the same tree); a link was
  never judged at all (now GH104, and GH103 when a folder link leaves the
  root); a zip with bytes in front read
  as one opaque file; a file named like an archive that no reader opens read as
  a plain file (now GH104); a truncated compressed payload, a tar or RAR5 that
  breaks part way, and a nested 7z or RAR4 under a data name were dropped. Any
  capable skip with an unlisted reason falls back to GH104.
- GH403 promised a REVIEW for a process or network call from a toolchain
  config and had none; it now flags child_process, net, http, https, dgram,
  worker_threads, vm, fetch, XMLHttpRequest and WebSocket. On the benchmark
  corpus it fired on nothing.
- A RAR5 of a brief with a package.json added came back REVIEW, which exits 0
  by default. It is BLOCK again (see GH101 above).
- GH101 missed .url, .library-ms, .search-ms, .settingcontent-ms, .appref-ms,
  .msc and .xll (BLOCK everywhere) and .iso, .img, .vhd, .vhdx, .one and the
  macro-enabled Office types; GH405 now also checks the single top-level
  folder; a Dockerfile or compose file marks a project.
- Defanging missed a scheme-less host after a download command; the arguments
  of curl, wget, fetch, Invoke-WebRequest, iwr, certutil -urlcache and
  bitsadmin /transfer are now indicators. Text output escapes control and
  direction-changing characters in evidence, locations and target names.
- GH401, GH501, GH503 and GH504 pointed at the first line containing the key
  name anywhere; they now point at the key inside the object they read.
- A file over the total-bytes limit was truncated and reported as a corrupt
  archive; it is now a GH105 cap finding located at the target.
- Smaller items: `--explain` with an unknown id exits 2; negative limits are a
  usage error; JSON `targets` lists every path given and `unreadable` names the
  ones that could not be read; the GH108 path inside a nested archive; "1
  finding" in the singular.

From a second adversarial review:

- Coverage now denies by default: anything not read as a regular file is a
  skip that holds the verdict at REVIEW, except a short, commented list (git's
  object store and the type-judged caps). A FIFO,
  socket or device is never opened, as a member or as the target; files are
  opened read-only, non-blocking and without following a final link, then
  checked again with fstat. An unreadable folder or file is a skip, not a
  silent return. A folder named like a cache or an egg-info is read like any
  other. A bzip2 or xz file of several concatenated streams is read across all
  of them. A zip member is no longer skipped for its compression ratio, so a
  small dropper that compresses well is read. Names past the entry limit are
  checked and counted as one aggregated skip.
- A project marker counts only when its content confirms it (a package.json
  with name or scripts, a pyproject with a real section, a Dockerfile with
  FROM), so an empty `{}` or a prose
  requirements.txt no longer shelters a script. A build tree (autotools, meson,
  cmake) counts as a project.
- GH202 (new): a Windows script or root JavaScript that downloads code and runs
  it in memory is BLOCK, a single download-or-run step is REVIEW. GH201 now also
  flags Windows Script Host objects in a .js file. A script in a project is
  quiet only when its content was read with no chain in it, judged in its own
  archive layer. A binary program in the manifest's own folder is BLOCK, one
  below it REVIEW.
- GH302 reads every key git runs as a command (core.editor, core.pager,
  sshCommand, askpass, sequence.editor, diff and merge drivers, filter
  clean/smudge/process, gpg.program, credential.helper, pager.<cmd>, a `!`
  alias, an ext:: or fd:: transport). An include or includeIf is a REVIEW and
  is never followed (see the third review below).
- GH603 drops the string and comment mask: bidirectional controls, tag
  characters and Hangul fillers are flagged wherever they appear; a zero-width
  joiner or a direction mark only between two identifier characters.
- A file-wide GH602 window was measured on the benchmark and reverted: it
  turned minified bundles (next, nx, aiohttp and more) into false positives, so
  the decode and the evaluator share a line, within five lines in Python.
- Control and direction-changing characters are escaped at the render layer, in
  every line of the text and indicator output and the error line, not field by
  field.
- The regex-safety test walks every module in the package, and a companion test
  counts the inline `re.compile` calls so none escapes it.

From a third review, deny by default. NO FINDINGS means nothing was found,
never that a package is safe; what was not read, not followed or not judged by
its type is a REVIEW. The shortcuts that let files pass quietly were removed
rather than patched:

- Links are never followed. Every link inside the package is GH104 REVIEW,
  including a RAR5 link with a plain name; only a path named on the command
  line is resolved, once (it used to fail when it was a link).
- A git config include or includeIf is GH302 REVIEW and is not followed. A
  `.git` file (`gitdir:`) is GH108 REVIEW and the folder it names is not
  followed, inside the package or out of it.
- A code project comes only from a manifest or marker whose content confirms
  it. A `.git` folder, a `.git` file, a `src` folder and a `.github` folder no
  longer make one.
- A `.vbs` inside a project is never quiet: read and clean, it is GH101
  REVIEW; unread, it stays BLOCK.
- A macOS application bundle (a `Name.app` folder holding `Contents/MacOS`)
  is GH101 BLOCK anywhere, even as an empty folder.
- A bzip2 or xz file of many streams is read in linear time, and past 256
  streams the file is a GH105 REVIEW. A zip holding a bzip2 file of 300,000
  empty streams took 18.6 s before and takes 0.5 s now.
- The git config is read the way git reads it: quotes, escapes, line
  continuations, comments only outside quotes, escaped subsections and the
  older `[section.subsection]` form. GH302 now also covers core.gitProxy,
  core.alternateRefsCommand, diff and merge tool commands and paths,
  gpg.<format>.program and defaultKeyCommand, interactive.diffFilter,
  remote upload-pack, receive-pack and vcs, uploadpack.packObjectsHook,
  gc.recentObjectsHook, hook.<name>.command, the send-email commands and a
  send-email server given as a path, imap.tunnel, tar, trailer, browser, man
  and guitool commands, instaweb.httpd and an ext:: or fd:: url rewrite; a
  protocol allowed always is a REVIEW; a boolean pager or fsmonitor value is
  not a command. The most severe finding in a file is the one reported.
- GH104 told the reader to ask for the archive password for every part it
  could not read, links included; its trigger and next step now fit every case.
- UTF-32 text with a byte-order mark is decoded. A null character left after
  decoding marked text means the file was not read as text, so it gets no
  shelter from a project.

After the first CI run on Windows: a manifest saved with Windows line endings
(CRLF), which a git checkout on Windows writes, did not confirm a project, so
the Python files of a Windows checkout came back BLOCK. Marker text is now read
with its line endings normalized; the benchmark result did not change.

Measured after the third review: the 218 benchmark packages come back 169 NO
FINDINGS, 49 REVIEW and 0 BLOCK (176, 42, 0 before the first review; 174, 44, 0
after it; 173, 45, 0 after the second). No package is a BLOCK. The REVIEW
results include install scripts that run code on `npm install`, Windows install
scripts with a download step, devcontainer commands, shipped `__pycache__`
folders, one Hangul filler in a test string (idna), links that are not
followed (pyparsing, referencing, tenacity) and git submodule pointers that are
not followed (aiohttp, referencing, tomlkit).
