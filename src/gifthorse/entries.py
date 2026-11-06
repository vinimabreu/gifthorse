"""Entries and the budget that bounds how much of a target is read.

An ``Entry`` is one member of a target: a file in a directory, a member of an
archive, or a single file given on the command line. Content is read into
memory under a byte budget and never written to disk. Directories are walked
without following symlinks and without leaving the root. Every directory entry
is examined with ``lstat`` first: only a regular file is ever opened, and it is
opened read-only, non-blocking and without following a link, so a FIFO, a
device or a socket can never stall the scan. Anything that is not read as a
regular file is recorded as a skip.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .kinds import (
    DEPENDENCY_DIRS,
    DEPENDENCY_SKIP,
    ENTRY_CAP_SKIP,
    GIT_STORE_SKIP,
    LINK_SKIP,
    NOT_REGULAR_SKIP,
    UNREADABLE_FILE_SKIP,
    UNREADABLE_FOLDER_SKIP,
    is_executable_capable,
)
from .model import Coverage, Limits, Skipped

# Containers whose inner path is joined with the archive separator "!/".
ARCHIVE_CONTAINERS = frozenset({"zip", "tar", "gzip", "rar5", "rar4", "7z", "xz", "bz2"})

# Git's object, LFS and log stores are not walked: content-addressed blobs that
# git never runs and that would only exhaust the entry budget. Each one is
# still counted and listed as a skip.
PRUNED_DIRS = frozenset({"objects", "lfs", "logs"})  # under .git

# Read-only, never blocking on a FIFO, never following a link at the last step.
_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_BINARY", 0)
)
_CHUNK = 1 << 20


@dataclass
class Entry:
    """One member of a target. ``rel`` is the in-target path (``!/`` between
    archive layers, ``/`` inside one layer)."""

    rel: str
    data: bytes | None = None
    size: int = 0
    mode: int = 0
    is_dir: bool = False
    is_symlink: bool = False
    link_target: str = ""
    link_hard: bool = False
    # For a link found in a folder walk: whether its target lies outside the
    # root, and otherwise the target's path inside it.
    link_escapes: bool = False
    link_resolved: str = ""
    container: str = "file"
    truncated: bool = False

    @property
    def name(self) -> str:
        tail = self.rel.rsplit("!/", 1)[-1]
        return tail.rsplit("/", 1)[-1]

    def display(self, target_kind: str) -> str:
        if target_kind == "file" or not self.rel:
            return ""
        if target_kind in ARCHIVE_CONTAINERS:
            return "!/" + self.rel
        if target_kind == "dir":
            return "/" + self.rel
        return self.rel


@dataclass
class Budget:
    """Shared caps across one target. Hitting a cap records a skip, never raises."""

    limits: Limits
    coverage: Coverage = field(default_factory=Coverage)
    total_read: int = 0
    entry_count: int = 0
    # Entries past the entry cap: still present and still name-checked, but
    # their content is not read. They are listed as one skip, not one each.
    over_cap: int = 0

    def count_entry(self) -> bool:
        self.entry_count += 1
        return self.entry_count <= self.limits.max_entries

    def past_entry_cap(self) -> None:
        self.present()
        self.over_cap += 1

    def finish(self) -> None:
        """Record the one skip that stands for every entry past the cap."""

        if self.over_cap:
            noun = "entry" if self.over_cap == 1 else "entries"
            label = f"<{self.over_cap} {noun} past the entry limit>"
            self.coverage.skipped.append(Skipped(label, ENTRY_CAP_SKIP, True))
            self.over_cap = 0

    def present(self) -> None:
        self.coverage.present += 1

    def inspected(self) -> None:
        self.coverage.inspected += 1

    def skip(self, rel: str, reason: str, *, executable_capable: bool | None = None) -> None:
        """Record a skipped entry. It counts as one that could hold code unless
        its reason is on the short list in ``kinds``, or the caller says so."""

        capable = (
            is_executable_capable(rel, reason) if executable_capable is None else executable_capable
        )
        self.coverage.skipped.append(Skipped(rel, reason, capable))

    def prefix_skips_since(self, mark: int, parent: str) -> None:
        """Give skips recorded inside a nested archive their full path."""

        skipped = self.coverage.skipped
        for index in range(mark, len(skipped)):
            item = skipped[index]
            skipped[index] = Skipped(f"{parent}!/{item.path}", item.reason, item.executable_capable)

    def take(self, want: int) -> int:
        """Bytes this read may consume without passing the total budget."""

        room = self.limits.max_total_bytes - self.total_read
        grant = max(0, min(want, room))
        self.total_read += grant
        return grant


def is_within(root: Path, candidate: Path) -> bool:
    """True when ``candidate`` resolves at or under ``root`` (symlinks resolved)."""

    try:
        root_real = root.resolve()
        cand_real = candidate.resolve()
    except (OSError, RuntimeError):
        return False
    return cand_real == root_real or root_real in cand_real.parents


def walk_directory(root: Path, budget: Budget) -> list[Entry]:
    """Walk ``root`` with ``os.scandir``; never follow symlinks or leave the root."""

    entries: list[Entry] = []
    _walk(root, root, "", budget, entries)
    entries.sort(key=lambda e: e.rel)
    return entries


def _walk(root: Path, current: Path, rel_dir: str, budget: Budget, out: list[Entry]) -> None:
    try:
        with os.scandir(current) as listing:
            items = sorted(listing, key=lambda d: d.name)
    except OSError:
        budget.present()
        budget.skip(rel_dir or "<folder>", UNREADABLE_FOLDER_SKIP)
        return
    for item in items:
        rel = f"{rel_dir}/{item.name}" if rel_dir else item.name
        try:
            info = item.stat(follow_symlinks=False)
        except OSError:
            budget.present()
            budget.skip(rel, UNREADABLE_FILE_SKIP)
            out.append(Entry(rel=rel, container="dir"))
            continue
        mode = info.st_mode
        if stat.S_ISLNK(mode):
            budget.present()
            budget.skip(rel, LINK_SKIP)
            target = _readlink(Path(item.path))
            inside = link_target_in_root(root, rel, target)
            out.append(
                Entry(
                    rel=rel,
                    is_symlink=True,
                    link_target=target,
                    mode=mode,
                    link_escapes=inside is None,
                    link_resolved=inside or "",
                    container="dir",
                )
            )
        elif stat.S_ISDIR(mode):
            _enter_dir(root, Path(item.path), rel, item.name, budget, out)
        elif stat.S_ISREG(mode):
            _read_file(Path(item.path), rel, info, budget, out)
        else:
            # A FIFO, a socket or a device: never opened. Opening a FIFO for
            # reading would wait for a writer forever.
            budget.present()
            budget.skip(rel, NOT_REGULAR_SKIP)
            out.append(Entry(rel=rel, mode=mode, container="dir"))


def _enter_dir(
    root: Path, path: Path, rel: str, name: str, budget: Budget, out: list[Entry]
) -> None:
    if path.parent.name == ".git" and name in PRUNED_DIRS:
        budget.present()
        budget.skip(rel, GIT_STORE_SKIP)
        return
    if name in DEPENDENCY_DIRS and (name != "venv" or _is_regular(path / "pyvenv.cfg")):
        budget.present()
        budget.skip(rel, DEPENDENCY_SKIP)
        return
    out.append(Entry(rel=rel, is_dir=True, container="dir"))
    _walk(root, path, rel, budget, out)


def _is_regular(path: Path) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def link_target_in_root(root: Path, rel: str, target: str) -> str | None:
    """A folder link's target as a path inside ``root``, or None outside it.

    Lexical, like the archive readers: the target is never resolved on disk,
    so a link loop cannot stall the walk. An absolute target inside the root
    counts as inside. An unreadable target counts as outside.
    """

    raw = target.replace("\\", "/")
    if not raw:
        return None
    if os.path.isabs(target) or raw.startswith("/"):
        norm = os.path.normpath(target).replace("\\", "/")
        for base in {os.path.abspath(root), os.path.realpath(root)}:
            prefix = base.replace("\\", "/").rstrip("/") + "/"
            if (norm + "/").startswith(prefix):
                return norm[len(prefix) :] or "."
        return None
    parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
    joined = os.path.normpath(os.path.join(parent, raw)).replace("\\", "/")
    if joined == ".." or joined.startswith("../"):
        return None
    return joined


def _read_file(
    path: Path, rel: str, info: os.stat_result, budget: Budget, out: list[Entry]
) -> None:
    mode = info.st_mode
    size = info.st_size
    if not budget.count_entry():
        budget.past_entry_cap()
        out.append(Entry(rel=rel, size=size, mode=mode, container="dir"))
        return
    budget.present()
    want = min(size, budget.limits.max_file_bytes)
    grant = budget.take(want)
    if grant < want:
        budget.skip(rel, "cap: total bytes")
        out.append(Entry(rel=rel, size=size, mode=mode, container="dir"))
        return
    data, problem = read_regular_file(path, grant)
    if data is None:
        budget.skip(rel, problem)
        out.append(Entry(rel=rel, size=size, mode=mode, container="dir"))
        return
    if size > budget.limits.max_file_bytes:
        budget.skip(rel, "cap: file larger than per-file limit")
        out.append(Entry(rel=rel, data=data, size=size, mode=mode, container="dir", truncated=True))
        return
    budget.inspected()
    out.append(Entry(rel=rel, data=data, size=size, mode=mode, container="dir"))


def read_regular_file(path: Path, count: int) -> tuple[bytes | None, str]:
    """Up to ``count`` bytes of a regular file, or None and the reason.

    The file is opened read-only, non-blocking and without following a final
    link, then checked again with ``fstat``: something swapped in between the
    walk and the open is refused, not read.
    """

    try:
        fd = os.open(path, _READ_FLAGS)
    except OSError:
        return None, UNREADABLE_FILE_SKIP
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, NOT_REGULAR_SKIP
        chunks: list[bytes] = []
        remaining = count
        while remaining > 0:
            chunk = os.read(fd, min(remaining, _CHUNK))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks), ""
    except OSError:
        return None, UNREADABLE_FILE_SKIP
    finally:
        os.close(fd)


def _readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def is_macos_metadata(rel: str) -> bool:
    tail = rel.rsplit("!/", 1)[-1]
    parts = tail.split("/")
    if parts and parts[0] == "__MACOSX":
        return True
    base = parts[-1] if parts else ""
    return base.startswith("._") or base == ".DS_Store"


def looks_binary(data: bytes) -> bool:
    head = data[:8192]
    if b"\x00" in head:
        return True
    if not head:
        return False
    control = sum(1 for b in head if b < 9 or (13 < b < 32))
    return control / len(head) > 0.1


# Byte-order marks, longest first: the UTF-32 LE mark begins with the UTF-16
# LE one, so it has to be tried before it.
_TEXT_BOMS = (
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
    (b"\xef\xbb\xbf", "utf-8"),
)


def text_bom(data: bytes) -> tuple[bytes, str] | None:
    """The byte-order mark a member starts with and its encoding, or None."""

    for mark, encoding in _TEXT_BOMS:
        if data.startswith(mark):
            return mark, encoding
    return None


def decode_text(data: bytes) -> str:
    """Decode a whole text member for the content rules, honoring a byte-order mark.

    Every byte is decoded: the member is already bounded by the per-file cap,
    so no rule is blind to the end of a file. UTF-8, UTF-16 and UTF-32 marks
    are honored. Text without a mark is read as UTF-8, and an invalid byte
    becomes U+FFFD on its own, so one stray byte leaves the rest of the text
    exact instead of changing how all of it reads.
    """

    bom = text_bom(data)
    if bom is not None:
        mark, encoding = bom
        return data[len(mark) :].decode(encoding, errors="replace")
    return data.decode("utf-8", errors="replace")
