# gifthorse

[![ci](https://github.com/vinimabreu/gifthorse/actions/workflows/ci.yml/badge.svg)](https://github.com/vinimabreu/gifthorse/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![tests](https://img.shields.io/badge/tests-376%20passing-brightgreen)
![typing](https://img.shields.io/badge/typing-strict-informational)

**Look a gift in the mouth before you let it in.**

![gifthorse reads a zip that looks like paperwork and answers BLOCK, then a coding assignment with one linked file and answers REVIEW](docs/media/gifthorse.gif)

Both cases are real runs: the first is the package from `python examples/demo.py`, the second a small zip whose `README.md` is a link. Every line of tool output on screen (verdict, messages, evidence, indicator, summary) is copied from the captured output; the command lines and exit codes show what `gifthorse` does with the same packages. [MP4 version](docs/media/gifthorse.mp4).

The Trojan horse was a gift. Someone sends you a zip of "requirements", a repository for a "coding assignment", or a folder to "just review", and the moment you open it or run it, it is already too late. `gifthorse` reads what a stranger sent you without running any of it, and answers in one word: **BLOCK**, **REVIEW**, or **NO FINDINGS**, with the file, the line, and the hosts it would have contacted, defanged and ready to paste into a report.

It is a single command with no runtime dependencies. It never executes, imports, extracts or writes the thing it is looking at. The same engine is a typed library a platform can call on every attachment server-side.

```text
gifthorse ./the-thing-they-sent
```

## The problem

A file does not have to be opened by you to run. A `postcss.config.js` runs when you start the dev server. A git hook runs when you check out the branch the README tells you to. A `.vscode/tasks.json` can run the moment you open the folder in the editor. A `.vbs` named `Project Requirements and Budget.vbs` runs when you double-click what looks like a document. In every case the payload is a second stage pulled from the network, so the package you received looks empty.

These are not hypotheticals. A public incident report traces a $6.34 billion theft on 29 October 2026 to the compromise of an employee who was contacted through a job platform, invited to fake interviews, and downloaded a coding assignment from a code repository; the malware replaced the pyenv executable under the Homebrew install directory and endpoint protection did not catch it. Source: [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/binance-says-fake-job-interview-led-to-63-billion-crypto-heist/).

`gifthorse` is for the moment before that, when the file is still just sitting in your downloads.

## Quickstart

```text
pipx install "git+https://github.com/vinimabreu/gifthorse@9be244fecb79eca25e296e6540db5777de6313fa"
gifthorse ./suspicious-folder-or-archive.zip
```

There is no PyPI release yet; install from a pinned git commit. On a zip that looks like paperwork but hides a script that downloads, saves and runs a second stage, the result is:

<!-- hero:start -->
```text
brief.zip: BLOCK
Do not open or run anything from this package.

  [block] GH101 Executable or script inside a package
    at brief.zip!/Project Requirements and Budget.vbs
    A program file (.vbs) is inside a document package.
    evidence: Project Requirements and Budget.vbs
    trigger: when you double-click the file or open it on Windows
    next: do not open it; ask the sender for a PDF or plain text

  [block] GH201 Download, write and run chain in a Windows script
    at brief.zip!/Project Requirements and Budget.vbs:1
    The script downloads a file, saves it, then runs it.
    evidence: download line 1, write line 4, run line 6
    trigger: when you double-click the script on Windows
    next: report it; use the --iocs block for the hosts it would contact

inspected 3 of 3 files
2 findings: 2 block, 0 review, 0 info

Indicators (defanged, for an abuse report):
  url      hxxp[://]stage[.]cdn[.]example[.]invalid/payload
```
<!-- hero:end -->

Every finding says, in plain words, the everyday action that would set it off and what to do instead. That output is `python examples/demo.py`, offline, with no network and nothing written to disk. The test suite compares the block above with the demo output byte for byte.

## Verdicts and exit codes

| Verdict | Meaning | Exit |
|---|---|---|
| `BLOCK` | At least one finding is a block. Do not open or run anything in it. | 1 |
| `REVIEW` | Something needs a human look or a safer copy: an encrypted member, a cap reached, a single risky step. | 1 with `--fail-on review`, else 0 |
| `NO FINDINGS` | No block and no review. **This is not a clearance.** Static analysis can be evaded. | 0 |

Exit code is `0` below the `--fail-on` threshold, `1` at or above it, and `2` for a usage error or a target that cannot be read. When several paths are given and one cannot be read, a `1` from another path takes precedence over the `2`. The default threshold is `block`, so the tool drops into a hook or a CI step as a gate. Findings are deterministic and sorted by target, path, line and rule id.

```text
gifthorse PATH [PATH ...]
  --format {text,json}     default text
  --iocs                   print the defanged indicators block after the report
  --fail-on {block,review,never}
  --verbose                also show info findings
  --quiet                  only the verdict line per target
  --no-color               color is used only on a terminal and never when NO_COLOR is set
  --max-entries / --max-total-bytes / --max-file-bytes / --max-depth
  --list-rules             table of rules
  --explain GH201          what a rule means, why it matters, and what to do
  --version
```

## What it checks

Rules have stable ids and a family. Full text is in [docs/RULES.md](docs/RULES.md), generated from the one registry in the code; `gifthorse --explain GH201` prints the same for one rule.

<!-- families:start -->
| Family | Rules | What it catches |
|---|---|---|
| package | GH101, GH109, GH401 | a program file, disk image or macro document where paperwork is expected; a shipped node_modules, virtualenv or compiled cache; an install script that is not routine |
| name | GH102, GH103 | a name that hides its real extension; a member, or a link whose target, leaves the folder |
| archive | GH104 | content that could not be inspected |
| limits | GH105 | a cap reached, so part was not read |
| git | GH108, GH301, GH302, GH304 | a git repository in the package; an active hook; a config key or submodule that runs a command on a git action |
| windows-script | GH201, GH202 | the download, write and run chain in a Windows script, or Windows Script Host code in a JavaScript file; a download run in memory, or a single step of one |
| toolchain | GH403 | a build config that runs on load and carries hidden code or reaches for a process or the network |
| python | GH405 | a file shadowing a standard module |
| install | GH407 | a download piped into a shell, worse with a persistence step |
| editor-task | GH501, GH503, GH504 | an editor task, devcontainer command, or agent config that starts a process |
| obfuscation | GH601, GH602, GH603, GH606 | code pushed off-screen; a decoded string run as code; invisible characters in source; a blockchain lookup used as a channel |
| secrets | GH605 | access to saved passwords, cookies or keys |
<!-- families:end -->

The engine inspects zip (found from its directory even with bytes in front), tar and its gzip, bzip2 and xz forms (old tars without the ustar magic included), and a single gzip, bzip2 or xz file, read into memory under caps and never extracted. Content rules read every byte of a file up to the per-file cap. RAR5 is read for member names only, from the published header format; 7z and RAR4 are reported as not inspectable rather than guessed.

## Why not just block risky extensions?

A naive extension filter flags an archive when a member ends in `.exe`, `.scr`, `.bat`, `.cmd`, `.vbs`, `.ps1`, `.msi`, `.lnk`, `.hta` or `.jar`, or is a `.js` file at the archive root. Measured on the fourteen acceptance shapes, which are synthetic fixtures built for this tool and contain no real sample, by `tests/test_baseline.py`, which checks this table against its own output:

<!-- baseline:start -->
| Shape | What it is | Naive extension filter | gifthorse |
|---|---|---|---|
| S1 | zip of screenshots plus a .vbs dropper | flagged (Project Requirements and Budget.vbs) | BLOCK |
| S2 | the same in a RAR5 | flagged (Project Requirements and Budget.vbs) | BLOCK |
| S3 | postcss.config.js with an off-screen payload | flagged (postcss.config.js) | BLOCK |
| S4 | git repository with active hooks | not flagged | BLOCK |
| S5 | install.sh that pipes a download to a shell | not flagged | BLOCK |
| S6 | .vscode/tasks.json that runs on folder open | not flagged | BLOCK |
| B1 | create-next-app style project | not flagged | NO FINDINGS |
| B2 | Vite and React template | not flagged | NO FINDINGS |
| B3 | husky prepare script and pre-commit | not flagged | NO FINDINGS |
| B4 | plain setuptools package | not flagged | NO FINDINGS |
| B5 | git repository with sample hooks only | not flagged | NO FINDINGS |
| B6 | images, a PDF and macOS metadata | not flagged | NO FINDINGS |
| B7 | editor build task without runOn | not flagged | NO FINDINGS |
| B8 | Gradle project with the wrapper jar | flagged (gradlew.bat, gradle-wrapper.jar) | NO FINDINGS |
<!-- baseline:end -->

## Use in CI

```yaml
name: gifthorse
on:
  pull_request:
permissions:
  contents: read
jobs:
  gifthorse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.13"
      - run: pip install "git+https://github.com/vinimabreu/gifthorse@9be244fecb79eca25e296e6540db5777de6313fa"
      - run: gifthorse .
```

The job needs nothing beyond `contents: read`, and the actions are pinned by full commit SHA. The command exits 1 on a block, which fails the step; add `--fail-on review` to fail on a review as well. Run it before any step that runs Python in the checkout, since a `__pycache__` folder left in the tree is itself a review.

## Use as a library

For a platform that receives files from strangers, the engine is a typed call that takes bytes and returns a report. There is no global state and no I/O beyond the bytes you pass, so it is safe to call from a request handler and simple to put behind `POST /v1/scan` later.

```python
from gifthorse import scan_bytes, Limits

report = scan_bytes("upload.zip", data, Limits(max_total_bytes=64 * 1024 * 1024))
if report.verdict.value != "NO FINDINGS":
    reject(report.to_dict())  # the same JSON the CLI prints, schema gifthorse.report/1
```

Every report accounts for how much it inspected. A report can never say NO FINDINGS while a member that could hold code was skipped; that case is at least REVIEW. The JSON shape is documented in [docs/JSON.md](docs/JSON.md).

## Guarantees

Each of these has a test, and the suite runs with no network and no key.

- **It never executes, imports, evaluates or compiles what it scans.** A build-time scan of the source fails if it reaches for `exec`, `eval`, `compile`, `subprocess`, `pickle` and the like.
- **It never extracts or writes to disk.** Archive members are read in memory under per-entry, total and nesting caps; a traversal archive scanned from any directory leaves the filesystem unchanged.
- **It never follows a link inside the package** and never reads outside the target root. Every link is a review, whatever it points at, and one pointing outside the folder is a block. Only a path named on the command line is resolved, once, if it is itself a link.
- **No network.** The test suite runs with sockets disabled in its own process.
- **Bounded work on hostile input.** Hitting a cap is a REVIEW finding, never a crash or a silent stop. Long lines are read in overlapping windows, so no pattern runs on more than a few kilobytes at once. Every registered pattern is timed on a megabyte of pathological input (single characters, newline-heavy text, its own opening token repeated) and must finish fast and grow linearly, and thousands of fuzzed inputs return a report instead of raising.
- **`python -m gifthorse` refuses to run unless the current directory is off the import path.** Plain `python -m` puts the current directory on the import path before any of this package's code runs, so a `json.py` or `importlib.py` in that directory runs in place of the real module. The guard cannot stop a planted `importlib.py`, which the interpreter imports before the guard exists, so never run Python from inside a received folder. Use the installed `gifthorse` command (its first path entry is the scripts directory) or `python -P -m gifthorse`; with `-P`, `PYTHONSAFEPATH=1` or `-I` nothing from the current directory is imported, and without one of them the module refuses before loading its command line.

## Limits, stated plainly

- **NO FINDINGS is not safe.** Static analysis is evadable by design; a determined payload can hide from any static check. Treat NO FINDINGS as "nothing obvious", not "cleared".
- **Some things are REVIEW by design.** A link inside the package is never followed, so every link is a REVIEW. A git config `include` or `includeIf` is never followed, and neither is a `.git` file that points git at a repository folder (`gitdir:`, as a git submodule has); each is a REVIEW. Only a manifest whose content confirms it (a package.json with a name, scripts or dependencies, a pyproject with a real section, a Dockerfile with FROM) makes a folder a code project; a `.git`, `src` or `.github` folder does not. A `.vbs` inside a project stays a REVIEW even when it was read and found clean.
- **A limit can be reached on purpose.** The entry, byte, depth and per-file caps exist so a hostile package cannot exhaust the machine; a package built to hit one is itself a sign. Reaching a cap is a REVIEW, never a silent stop. A **REVIEW** on a file a stranger sent means do not open it or run it yet: a member could not be read, a cap was reached, or one risky step is present. The default verdict that fails a gate is `block`; add `--fail-on review` to stop on a received file that is not clearly safe.
- **RAR5 is names only.** 7z and RAR4 are reported as not inspectable. Ask the sender for a plain zip.
- **It does not replace a disposable virtual machine.** For anything you must actually run, run it somewhere throwaway, offline, with no credentials in the environment.
- Heuristics for JavaScript, Python, shell and documents are pattern matches, not full parsers, and say so. They can miss a renamed primitive and can over-flag; read the line the finding points at. In JavaScript a decode and the evaluator must share a line, and in Python they must sit within five lines, so a payload decoded in one place and run far away is missed.
- **Content rules pick files by name or extension.** Code stored under a non-code extension and loaded by a config is not read as code.
- **Not covered yet:** Python install hooks (`setup.py` cmdclass, `.pth` files, `sitecustomize`), prebuilt binaries in a source tree, JavaScript inside a PDF, macros in an OOXML `vbaProject.bin`, and data after an image's end marker.
- **It does not analyze C, C++, Rust or Go source, or the contents of compiled binaries.** A skipped file of a type no rule reads (C source over the size cap, an image, a NumPy array) is listed in the coverage block but does not hold the verdict at REVIEW; a skipped script, executable or archive does.
- In a folder, a shipped `node_modules`, virtualenv or `__pycache__` is flagged but not read; in an archive its files are read as well.

## False positives, measured

`benchmark/` holds the list of 218 popular npm and PyPI packages, their pinned versions and hashes, the scripts that fetch and scan them, and the result per package. Measured on 6 November 2026, the published files came back <!-- bench:start -->169 NO FINDINGS, 49 REVIEW and 0 BLOCK<!-- bench:end -->. Every REVIEW is listed in `benchmark/results.json` with its rule and path; most are install scripts that run code on `npm install`, and some are links or git submodule pointers that are not followed. See [benchmark/README.md](benchmark/README.md) to reproduce it.

## Contributing

A rule is one registry entry, a positive and a negative test, and a fixture builder that assembles the shape in memory. No real malware sample ever enters the repository. See [CONTRIBUTING.md](CONTRIBUTING.md). Report a bypass or a false negative privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).

Vinicius Pereira<br>
[vinimabreu.dev](https://vinimabreu.dev) · [github.com/vinimabreu](https://github.com/vinimabreu)
