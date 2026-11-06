"""Read archive members into memory under caps. Never extract, never write.

zip and tar (plain or gzip, bzip2, xz compressed) are read for content with
the standard library. A single gzip, bzip2 or xz file is decompressed under the
cap. RAR5 is read for names only, from the header format (see ``rar5``). 7z and
RAR4 are reported as not inspectable. A zip member that fails to decode becomes
a skip and the other members are still read. A tar is read header by header, so
a broken header ends the walk there: the members before it are kept and the
rest of the archive is recorded as one skip that holds the verdict at REVIEW.
"""

from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import stat
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from typing import Protocol

from .entries import Budget, Entry
from .kinds import LINK_SKIP, NOT_REGULAR_SKIP, STREAM_CAP_SKIP
from .rar5 import RAR4_SIGNATURE, RAR5_SIGNATURE, read_rar5_names

try:  # some Python builds ship without the lzma module
    import lzma
except ImportError:  # pragma: no cover - depends on the interpreter build
    lzma = None  # type: ignore[assignment]

# Any member of any archive may be structurally broken or deliberately hostile.
# Reading it must degrade to a skip, never crash, so one bad member does not
# hide the rest of the package.
READ_ERRORS = (
    OSError,
    EOFError,
    ValueError,
    zlib.error,
    tarfile.TarError,
    zipfile.BadZipFile,
    RecursionError,
    NotImplementedError,
)

ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
GZIP_SIGNATURE = b"\x1f\x8b"
XZ_SIGNATURE = b"\xfd7zXZ\x00"
BZ2_SIGNATURE = b"BZh"
SEVENZIP_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
TAR_MAGIC_OFFSET = 257


def detect_kind(data: bytes) -> str | None:
    """Name the archive format from magic bytes, or None if it is not an archive."""

    if data.startswith(ZIP_SIGNATURES):
        return "zip"
    if data.startswith(RAR5_SIGNATURE):
        return "rar5"
    if data.startswith(RAR4_SIGNATURE):
        return "rar4"
    if data.startswith(SEVENZIP_SIGNATURE):
        return "7z"
    if data.startswith(GZIP_SIGNATURE):
        return "gzip"
    if data.startswith(XZ_SIGNATURE):
        return "xz"
    if data.startswith(BZ2_SIGNATURE):
        return "bz2"
    tail = data[TAR_MAGIC_OFFSET : TAR_MAGIC_OFFSET + 5]
    if tail == b"ustar" or _is_v7_tar(data):
        return "tar"
    if _has_zip_directory(data):
        return "zip"
    return None


def _is_v7_tar(data: bytes) -> bool:
    """An old tar has no magic, but its first header carries a checksum."""

    if len(data) < 512 or data[0] == 0:
        return False
    field = data[148:156].split(b"\x00", 1)[0].strip()
    if not field or any(c not in b"01234567" for c in field):
        return False
    header = data[:148] + b" " * 8 + data[156:512]
    return int(field, 8) == sum(header)


_EOCD = b"PK\x05\x06"
# The end-of-central-directory record sits in the last 22 bytes plus a comment
# of at most 65,535 bytes.
_EOCD_WINDOW = 22 + 65_535


def _has_zip_directory(data: bytes) -> bool:
    """A zip whose magic is not at byte 0 (bytes prepended, a script or image in
    front) is still a zip to unzip, bsdtar and zipfile, which find it from the
    directory at the end. Treat it as one when that directory reads."""

    if len(data) < 22 or data.rfind(_EOCD, max(0, len(data) - _EOCD_WINDOW)) < 0:
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return bool(archive.infolist())
    except READ_ERRORS:
        return False


def read_archive(kind: str, data: bytes, budget: Budget, name_hint: str = "") -> list[Entry]:
    """Return the members of an archive of the given kind.

    ``name_hint`` is the archive's own file name, used to name the single member
    of a plain compressed file (``data.npy.gz`` holds ``data.npy``).
    """

    if kind == "zip":
        return _read_zip(data, budget)
    if kind in ("tar", "gzip", "xz", "bz2"):
        return _read_tar_or_compressed(kind, data, budget, name_hint)
    if kind == "rar5":
        return _read_rar5(data, budget)
    return []


def _read_zip(data: bytes, budget: Budget) -> list[Entry]:
    out: list[Entry] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except READ_ERRORS:
        budget.present()
        budget.skip("<zip archive>", "unreadable format")
        return out
    for info in infos:
        rel = info.filename
        if info.is_dir():
            out.append(Entry(rel=rel.rstrip("/"), is_dir=True, container="zip"))
            continue
        mode = (info.external_attr >> 16) & 0xFFFF
        if not budget.count_entry():
            # Past the entry cap the content is not read, but the name still
            # goes through the name rules.
            budget.past_entry_cap()
            out.append(Entry(rel=rel, mode=mode, size=info.file_size, container="zip"))
            continue
        budget.present()
        if stat.S_ISLNK(mode):
            budget.skip(rel, LINK_SKIP)
            target = _zip_link_target(archive, info)
            out.append(
                Entry(rel=rel, is_symlink=True, link_target=target, mode=mode, container="zip")
            )
            continue
        if (info.flag_bits & 0x1) or info.compress_type == 99:
            budget.skip(rel, "encrypted")
            out.append(Entry(rel=rel, mode=mode, size=info.file_size, container="zip"))
            continue
        # No member is skipped for its compression ratio: every read is already
        # bounded by the per-file and total limits, so a small dropper that
        # compresses well is read like any other member.
        entry = _read_member(archive, info, rel, mode, budget)
        out.append(entry)
    return out


def _read_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, rel: str, mode: int, budget: Budget
) -> Entry:
    size = info.file_size
    truncated = size > budget.limits.max_file_bytes
    want = min(size, budget.limits.max_file_bytes)
    grant = budget.take(want)
    if grant < want:
        budget.skip(rel, "cap: total bytes")
        return Entry(rel=rel, mode=mode, size=size, container="zip")
    try:
        with archive.open(info) as handle:
            data = handle.read(grant + 1)
    except READ_ERRORS:
        budget.skip(rel, "unreadable format")
        return Entry(rel=rel, mode=mode, size=size, container="zip")
    if truncated:
        budget.skip(rel, "cap: file larger than per-file limit")
        return Entry(
            rel=rel, data=data[:grant], size=size, mode=mode, container="zip", truncated=True
        )
    budget.inspected()
    return Entry(rel=rel, data=data[:grant], size=size, mode=mode, container="zip")


def _read_tar_or_compressed(
    kind: str, data: bytes, budget: Budget, name_hint: str = ""
) -> list[Entry]:
    out: list[Entry] = []
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")  # noqa: SIM115
    except READ_ERRORS:
        # Opening reads the first header. A compressed file that is not a tar
        # is a single compressed file; a plain tar that fails here is broken.
        if kind in ("gzip", "xz", "bz2"):
            return _read_single_compressed(kind, data, budget, name_hint)
        budget.present()
        budget.skip("<tar archive>", "unreadable format")
        return out
    try:
        _read_tar_members(archive, budget, out)
    finally:
        with contextlib.suppress(*READ_ERRORS):
            archive.close()
    return out


def _read_tar_members(archive: tarfile.TarFile, budget: Budget, out: list[Entry]) -> None:
    while True:
        try:
            member = archive.next()
        except READ_ERRORS:
            member = None
            stopped_early = True
        else:
            stopped_early = member is None and _bytes_after_last_header(archive)
        if stopped_early:
            # A broken header ends a tar: nothing after it can be found again.
            budget.present()
            budget.skip("<rest of tar archive>", "unreadable format")
            return
        if member is None:
            return
        rel = member.name
        if member.isdir():
            out.append(Entry(rel=rel, is_dir=True, container="tar"))
            continue
        if not budget.count_entry():
            budget.past_entry_cap()
            out.append(Entry(rel=rel, mode=member.mode, size=member.size, container="tar"))
            continue
        budget.present()
        if member.issym() or member.islnk():
            budget.skip(rel, LINK_SKIP)
            out.append(
                Entry(
                    rel=rel,
                    is_symlink=True,
                    link_target=member.linkname,
                    link_hard=member.islnk(),
                    mode=member.mode,
                    container="tar",
                )
            )
            continue
        if not member.isfile():
            budget.skip(rel, NOT_REGULAR_SKIP)  # a FIFO or device member
            out.append(Entry(rel=rel, mode=member.mode, container="tar"))
            continue
        out.append(_read_tar_member(archive, member, rel, budget))


def _bytes_after_last_header(archive: tarfile.TarFile) -> bool:
    """Whether data follows the point where the tar reader stopped.

    The standard reader treats a header that fails its checksum after the first
    member as the end of the archive, silently. A real end is followed only by
    zero blocks, so anything else there means members were not listed.
    """

    try:
        handle = archive.fileobj
        if handle is None:
            return False
        handle.seek(archive.offset)
        rest = handle.read(64 * 1024)
    except READ_ERRORS:
        return True
    return any(rest)


def _read_tar_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, rel: str, budget: Budget
) -> Entry:
    size = member.size
    truncated = size > budget.limits.max_file_bytes
    want = min(size, budget.limits.max_file_bytes)
    grant = budget.take(want)
    if grant < want:
        budget.skip(rel, "cap: total bytes")
        return Entry(rel=rel, mode=member.mode, size=size, container="tar")
    try:
        handle = archive.extractfile(member)
        data = handle.read(grant) if handle is not None else b""
    except READ_ERRORS:
        budget.skip(rel, "unreadable format")
        return Entry(rel=rel, mode=member.mode, size=size, container="tar")
    if truncated:
        budget.skip(rel, "cap: file larger than per-file limit")
        return Entry(
            rel=rel, data=data, size=size, mode=member.mode, container="tar", truncated=True
        )
    budget.inspected()
    return Entry(rel=rel, data=data, size=size, mode=member.mode, container="tar")


def _read_single_compressed(
    kind: str, data: bytes, budget: Budget, name_hint: str = ""
) -> list[Entry]:
    rel = _inner_name(name_hint)
    if not budget.count_entry():
        budget.present()
        budget.skip(rel, "cap: too many entries")
        return []
    budget.present()
    grant = budget.take(budget.limits.max_file_bytes)
    try:
        inner = _decompress(kind, data, grant + 1)
    except StreamCapError:
        budget.skip(rel, STREAM_CAP_SKIP, executable_capable=True)
        return [Entry(rel=rel, container=kind)]
    except READ_ERRORS:
        inner = None
    if inner is None:
        # The magic confirmed a compressed file, so whatever it holds is unknown.
        budget.skip(rel, "unreadable format", executable_capable=True)
        return [Entry(rel=rel, container=kind)]
    truncated = len(inner) > grant
    if truncated:
        budget.skip(rel, "cap: file larger than per-file limit", executable_capable=True)
        return [Entry(rel=rel, data=inner[:grant], size=len(inner), container=kind, truncated=True)]
    budget.inspected()
    return [Entry(rel=rel, data=inner, size=len(inner), container=kind)]


def _decompress(kind: str, data: bytes, count: int) -> bytes | None:
    """At most ``count`` bytes of a single compressed stream, or None."""

    if kind == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            return handle.read(count)
    if kind == "bz2":
        return _drain(bz2.BZ2Decompressor, data, count)
    if kind == "xz" and lzma is not None:
        return _drain(lzma.LZMADecompressor, data, count)
    return None


class _Decompressor(Protocol):
    @property
    def eof(self) -> bool: ...

    @property
    def unused_data(self) -> bytes: ...

    @property
    def needs_input(self) -> bool: ...

    def decompress(self, data: bytes, max_length: int = ...) -> bytes: ...


class StreamCapError(Exception):
    """A compressed file holds more streams than the stream cap."""


# A compressed file with more streams than this is not decoded further; the
# file becomes a capable skip, so it holds the verdict at REVIEW.
MAX_STREAMS = 256
# Compressed input is handed to a decompressor this many bytes at a time, so
# what one stream leaves over is never more than one piece.
_FEED = 64 * 1024


def _drain(make: Callable[[], _Decompressor], data: bytes, count: int) -> bytes | None:
    """Decompress up to ``count`` bytes across every concatenated stream.

    ``bunzip2`` and ``xz -d`` decode a file of several streams back to back, so
    a payload in the second stream is part of the file. Each stream gets a
    fresh decompressor, fed in pieces from an offset into ``data``, under one
    byte budget; nothing past the current piece is copied, so the cost grows
    with the input, not with the input times the number of streams. A stream
    that ends early is unreadable; padding of zero bytes after the last stream
    is allowed, as xz allows it. More than ``MAX_STREAMS`` streams raises
    ``StreamCapError``.
    """

    view = memoryview(data)
    total = len(data)
    out = bytearray()
    pos = 0
    streams = 0
    while pos < total and len(out) < count:
        streams += 1
        if streams > MAX_STREAMS:
            raise StreamCapError
        decompressor = make()
        while not decompressor.eof and len(out) < count:
            if decompressor.needs_input:
                if pos >= total:
                    break
                piece = bytes(view[pos : pos + _FEED])
                pos += len(piece)
            else:
                piece = b""
            out += decompressor.decompress(piece, max_length=count - len(out))
        if not decompressor.eof:
            return bytes(out) if len(out) >= count else None
        # The stream ended inside the last piece: step back over what it left.
        pos -= len(decompressor.unused_data)
        # Zero padding to the end is allowed. Only a zero right here costs a
        # scan of the rest, and it happens once: anything else after the
        # zeros fails as the next stream.
        if pos < total and data[pos] == 0 and data.count(b"\x00", pos) == total - pos:
            break
    return bytes(out)


def _read_rar5(data: bytes, budget: Budget) -> list[Entry]:
    out: list[Entry] = []
    result = read_rar5_names(data)
    if result.encrypted:
        budget.present()
        budget.skip("<rar headers>", "encrypted")
        return out
    if result.error and not result.rows:
        budget.present()
        budget.skip("<rar archive>", "unreadable format")
        return out
    if result.error:
        # Names were read up to a broken header; whatever follows is unknown.
        budget.present()
        budget.skip("<rest of rar archive>", "unreadable format")
    for name, is_dir, is_link in result.rows:
        target, hard = result.links.get(name, ("", False))
        if is_dir:
            out.append(Entry(rel=name, is_dir=True, container="rar5"))
            continue
        if not budget.count_entry():
            budget.past_entry_cap()
            out.append(
                Entry(
                    rel=name,
                    is_symlink=is_link,
                    link_target=target,
                    link_hard=hard,
                    container="rar5",
                )
            )
            continue
        budget.present()
        # A link is a skip of its own whatever its name: its target is not followed.
        budget.skip(name, LINK_SKIP if is_link else "rar content not inspectable (names only)")
        out.append(
            Entry(
                rel=name, is_symlink=is_link, link_target=target, link_hard=hard, container="rar5"
            )
        )
    return out


_COMPRESSED_SUFFIXES = (".gz", ".gzip", ".xz", ".bz2")


def _inner_name(name_hint: str) -> str:
    """Name the single member of a plain compressed file after the file."""

    base = name_hint.replace("\\", "/").rsplit("/", 1)[-1]
    low = base.lower()
    if low.endswith(".tgz"):
        return base[:-4] + ".tar"
    for suffix in _COMPRESSED_SUFFIXES:
        if low.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)]
    return "payload"


def _zip_link_target(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    """A zip symlink stores its target as the member data; read a bounded amount."""

    if info.file_size > 4096 or (info.flag_bits & 0x1):
        return ""
    try:
        with archive.open(info) as handle:
            return handle.read(4096).decode("utf-8", errors="replace")
    except READ_ERRORS:
        return ""
