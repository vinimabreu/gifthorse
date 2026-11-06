# Benchmark

The false-positive benchmark behind the numbers in the README and the CHANGELOG. It scans popular packages exactly as their registries publish them. A good result is NO FINDINGS, or a REVIEW that names a real reason; a BLOCK on any of them is a bug to fix.

## What is here

| File | What it holds |
|---|---|
| `lists.json` | the package names: the 100 most depended-on npm packages (npm-high-impact), 25 npm packages picked by hand because they ship install scripts or native builds, and the 100 most downloaded PyPI projects (top-pypi-packages), as ranked when the corpus was fetched; seven npm names are on both npm lists, so 218 files in all |
| `manifest.json` | the exact 218 files measured: ecosystem, name, version, registry URL and SHA-256 |
| `fetch_corpus.py` | downloads those files from the official registries and checks each hash; nothing is extracted, installed or run |
| `run_bench.py` | scans each file with gifthorse, in memory, and writes `results.json` |
| `results.json` | per package, the verdict and every finding above info by rule, severity and member path; no text from the packages |

The tarballs are never committed. They go to `benchmark/corpus/`, which git ignores.

## Reproduce

From the repository root, with Python 3.11 or newer and access to registry.npmjs.org and files.pythonhosted.org:

```text
python -I benchmark/fetch_corpus.py pinned benchmark/manifest.json benchmark/corpus
python -I benchmark/run_bench.py src benchmark/manifest.json benchmark/corpus benchmark/results.json
```

`-I` keeps Python from importing anything from the current directory or the environment; the runner imports gifthorse from the `src` folder it is given. The first command skips a file that is already present with the right hash, and rejects any file whose hash does not match.

The run recorded in `results.json` (6 November 2026, Apple M5 Max) took about 40 seconds: 169 NO FINDINGS, 49 REVIEW, 0 BLOCK.

## What the REVIEW results are

| Rule | Findings | Packages | Why |
|---|---|---|---|
| GH401 | 34 | 33 | an install, prepare or postinstall script that runs code on `npm install` |
| GH101 | 17 | nodemon, pip, pygments, setuptools | a Windows program file one folder below a project manifest: launcher executables, and an example `.reg` and `.vbs` file in a syntax highlighter's tests |
| GH407 | 5 | dotenv, numpy, ruff, typing-inspection | a download piped into a shell, in a script or in README install instructions |
| GH202 | 3 | numpy, scipy | a Windows install script with one download step (`install_windows.bat`, `run.ps1`) |
| GH503 | 2 | numpy, scipy | a devcontainer lifecycle command |
| GH109 | 2 | importlib-metadata, pyyaml | a shipped `__pycache__` folder, in an sdist and inside a test egg |
| GH104 | 5 | numpy, pyparsing, referencing, tenacity | two 6-byte placeholder files named like archives in a build tool's test cases, and three links (a README, a changelog, a contributing guide) that are not followed |
| GH108 | 3 | aiohttp, referencing, tomlkit | the `.git` file of a git submodule, which points git at a repository folder that is not followed |
| GH603 | 1 | idna | a Hangul filler character inside a test string |
| GH105 | 1 | numpy | a disk image inside a gzip, larger than the per-file limit |

## A newer corpus

```text
python -I benchmark/fetch_corpus.py latest benchmark/lists.json benchmark/manifest.json benchmark/corpus
```

resolves the latest version of every name in freshly fetched rankings, downloads it, and rewrites `lists.json` and `manifest.json`. That measures a different corpus, so commit the new manifest and results together.
