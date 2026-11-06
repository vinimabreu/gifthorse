"""Download the false-positive benchmark corpus as plain data.

Nothing is extracted, installed, imported or run. Every file comes from the
official registry (registry.npmjs.org, files.pythonhosted.org) and is checked
against a published hash before it is kept. Run it with ``python -I`` from
outside the corpus folder. Not part of the package; standard library only.

    python -I benchmark/fetch_corpus.py pinned benchmark/manifest.json benchmark/corpus

downloads exactly the files in the manifest and checks each SHA-256, which is
how the published numbers are reproduced.

    python -I benchmark/fetch_corpus.py latest benchmark/lists.json \\
        benchmark/manifest.json benchmark/corpus

resolves the latest version of every name in the lists, downloads it, and
rewrites the manifest. The lists come from two public rankings fetched at that
moment, so this mode gives a newer corpus, not the same one.
"""

from __future__ import annotations

import base64
import concurrent.futures as cf
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, TypedDict, cast

HEADERS = {"User-Agent": "gifthorse-benchmark/0.1"}
MAX_BYTES = 60 * 1024 * 1024
TOP_N = 100
NPM_REGISTRY = "https://registry.npmjs.org/"
PYPI_FILES = "https://files.pythonhosted.org/"
NPM_RANKING = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top-dependent.js"
PYPI_RANKING = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"

# Packages with install scripts, native builds or large toolchains, added by
# hand because they are where a false positive is most likely.
HARD_NPM = [
    "esbuild",
    "@swc/core",
    "sharp",
    "puppeteer",
    "playwright",
    "core-js",
    "node-gyp",
    "bcrypt",
    "sqlite3",
    "electron",
    "prisma",
    "@prisma/client",
    "cypress",
    "husky",
    "nodemon",
    "next",
    "vite",
    "webpack",
    "typescript",
    "@babel/core",
    "eslint",
    "tailwindcss",
    "postcss",
    "jest",
    "nx",
]


class Record(TypedDict):
    """One corpus file: what it is, where it came from, and its SHA-256."""

    ecosystem: str
    name: str
    version: str
    url: str
    sha256: str


def corpus_file(corpus: Path, record: Record) -> Path:
    if record["ecosystem"] == "npm":
        return corpus / "npm" / f"{record['name'].replace('/', '__')}-{record['version']}.tgz"
    return corpus / "pypi" / record["url"].rsplit("/", 1)[-1]


def get(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body: bytes = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"{url} is over {MAX_BYTES} bytes")
    return body


def fetch_pinned(record: Record, corpus: Path) -> str:
    if not record["url"].startswith((NPM_REGISTRY, PYPI_FILES)):
        return "skipped: url outside the registries"
    path = corpus_file(corpus, record)
    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]:
        return "ok (already present)"
    data = get(record["url"], timeout=180)
    if hashlib.sha256(data).hexdigest() != record["sha256"]:
        return "rejected: sha256 mismatch"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return "ok"


def ranked_lists() -> dict[str, list[str]]:
    script = get(NPM_RANKING).decode("utf-8")
    npm = re.findall(r"^\s*'([^']+)',?\s*$", script, re.MULTILINE)[:TOP_N]
    pypi = json.loads(get(PYPI_RANKING))
    return {
        "npm_top_dependent": npm,
        "npm_hard_set": HARD_NPM,
        "pypi_top_downloads": [row["project"] for row in pypi["rows"][:TOP_N]],
    }


def resolve_npm(name: str) -> Record | None:
    meta = json.loads(get(f"{NPM_REGISTRY}{urllib.parse.quote(name, safe='@')}/latest"))
    url = meta["dist"]["tarball"]
    if not url.startswith(NPM_REGISTRY):
        return None
    data = get(url, timeout=180)
    integrity = meta["dist"].get("integrity", "")
    if integrity.startswith("sha512-"):
        valid = base64.b64encode(hashlib.sha512(data).digest()).decode() == integrity[7:]
    else:
        valid = hashlib.sha1(data).hexdigest() == meta["dist"].get("shasum")
    if not valid:
        return None
    return Record(
        ecosystem="npm",
        name=name,
        version=meta["version"],
        url=url,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def resolve_pypi(name: str) -> Record | None:
    meta = json.loads(get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"))
    files: list[dict[str, Any]] = meta.get("urls", [])
    pick = next((f for f in files if f["packagetype"] == "sdist"), None)
    if pick is None:
        pick = next((f for f in files if f["filename"].endswith("-py3-none-any.whl")), None)
    if pick is None and files:
        pick = files[0]
    if pick is None or not str(pick["url"]).startswith(PYPI_FILES):
        return None
    return Record(
        ecosystem="pypi",
        name=name,
        version=meta["info"]["version"],
        url=pick["url"],
        sha256=pick["digests"]["sha256"],
    )


def latest(lists_path: Path, manifest_path: Path, corpus: Path) -> None:
    lists = ranked_lists()
    lists_path.write_text(json.dumps(lists, indent=2) + "\n", encoding="utf-8")
    jobs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for set_name, names in lists.items():
        ecosystem = "npm" if set_name.startswith("npm") else "pypi"
        for name in names:
            if (ecosystem, name) not in seen:
                seen.add((ecosystem, name))
                jobs.append((ecosystem, name))

    def resolve(job: tuple[str, str]) -> Record | None:
        ecosystem, name = job
        try:
            return resolve_npm(name) if ecosystem == "npm" else resolve_pypi(name)
        except Exception as exc:  # a registry or network error is reported, never fatal
            print(f"error {ecosystem} {name}: {type(exc).__name__}", flush=True)
            return None

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        records = [r for r in pool.map(resolve, jobs) if r is not None]
    manifest_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    pinned(manifest_path, corpus)


def pinned(manifest_path: Path, corpus: Path) -> None:
    records = cast(list[Record], json.loads(manifest_path.read_text(encoding="utf-8")))

    def run(record: Record) -> str:
        try:
            return fetch_pinned(record, corpus)
        except Exception as exc:  # a registry or network error is reported, never fatal
            return f"error: {type(exc).__name__}"

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(run, records))
    for record, status in zip(records, statuses, strict=True):
        print(f"{status:28} {record['ecosystem']:5} {record['name']}", flush=True)
    kept = sum(status.startswith("ok") for status in statuses)
    print(f"\n{kept} of {len(records)} files present and verified")


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "pinned":
        pinned(Path(argv[1]), Path(argv[2]))
        return 0
    if len(argv) == 4 and argv[0] == "latest":
        latest(Path(argv[1]), Path(argv[2]), Path(argv[3]))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
