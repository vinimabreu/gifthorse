"""Read RAR5 member names from the header format, without decompression.

Only the structure needed to list names and mark directories, links and
encrypted headers is parsed, following the published RAR 5.0 technote. No file
data is ever decompressed and no RAR code is used. On any malformed input the
reader returns what it has read so far rather than raising.
"""

from __future__ import annotations

RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"

_HEAD_FLAG_EXTRA = 0x0001
_HEAD_FLAG_DATA = 0x0002

_TYPE_MAIN = 1
_TYPE_FILE = 2
_TYPE_SERVICE = 3
_TYPE_ENCRYPTION = 4
_TYPE_END = 5

_FILE_FLAG_DIR = 0x0001
_FILE_FLAG_MTIME = 0x0002
_FILE_FLAG_CRC = 0x0004

_EXTRA_REDIRECTION = 0x05

NameRow = tuple[str, bool, bool]


class Rar5Result:
    """Rows read, whether headers were encrypted, and whether parsing broke."""

    __slots__ = ("rows", "encrypted", "error", "links")

    def __init__(
        self,
        rows: list[NameRow],
        encrypted: bool,
        error: bool,
        links: dict[str, tuple[str, bool]] | None = None,
    ) -> None:
        self.rows = rows
        self.encrypted = encrypted
        self.error = error
        # name -> (link target, is a hard link or file copy)
        self.links = links if links is not None else {}


def _read_vint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
        if shift > 70:
            break
    raise ValueError("truncated vint")


def read_rar5_names(data: bytes) -> Rar5Result:
    """Read member names from a RAR5 archive.

    Each row is ``(name, is_dir, is_link)``. ``encrypted`` is True when the
    archive uses encrypted headers, in which case names are not available.
    ``error`` is True when the structure is malformed, so a corrupt archive is
    distinguishable from a genuinely empty one.
    """

    rows: list[NameRow] = []
    links: dict[str, tuple[str, bool]] = {}
    if not data.startswith(RAR5_SIGNATURE):
        return Rar5Result(rows, False, True, links)
    pos = len(RAR5_SIGNATURE)
    try:
        while pos + 4 <= len(data):
            pos += 4  # header CRC32
            header_size, pos = _read_vint(data, pos)
            body_start = pos
            body_end = body_start + header_size
            if body_end > len(data) or header_size <= 0:
                return Rar5Result(rows, False, True, links)
            htype, hpos = _read_vint(data, body_start)
            hflags, hpos = _read_vint(data, hpos)
            extra_size = 0
            data_size = 0
            if hflags & _HEAD_FLAG_EXTRA:
                extra_size, hpos = _read_vint(data, hpos)
            if hflags & _HEAD_FLAG_DATA:
                data_size, hpos = _read_vint(data, hpos)
            if htype == _TYPE_ENCRYPTION:
                return Rar5Result(rows, True, False, links)
            if htype == _TYPE_END:
                return Rar5Result(rows, False, False, links)
            if htype in (_TYPE_FILE, _TYPE_SERVICE):
                row = _parse_file_header(data, hpos, body_end, extra_size, htype, links)
                if row is not None:
                    rows.append(row)
            pos = body_end + data_size
    except (ValueError, IndexError):
        return Rar5Result(rows, False, True, links)
    # Ran out of data without an end-of-archive header.
    return Rar5Result(rows, False, True, links)


def _parse_file_header(
    data: bytes,
    pos: int,
    body_end: int,
    extra_size: int,
    htype: int,
    links: dict[str, tuple[str, bool]],
) -> NameRow | None:
    file_flags, pos = _read_vint(data, pos)
    _unpacked, pos = _read_vint(data, pos)  # unpacked size
    _attr, pos = _read_vint(data, pos)  # attributes
    if file_flags & _FILE_FLAG_MTIME:
        pos += 4
    if file_flags & _FILE_FLAG_CRC:
        pos += 4
    _comp, pos = _read_vint(data, pos)  # compression information
    _host, pos = _read_vint(data, pos)  # host OS
    name_len, pos = _read_vint(data, pos)
    name_bytes = data[pos : pos + name_len]
    if len(name_bytes) != name_len:
        return None
    name = name_bytes.decode("utf-8", errors="replace")
    pos += name_len
    is_dir = bool(file_flags & _FILE_FLAG_DIR)
    if htype == _TYPE_SERVICE:
        return None
    redirect = _redirection(data, pos, pos + extra_size) if extra_size else None
    if redirect is not None:
        links[name] = redirect
    return (name, is_dir, redirect is not None)


# Redirection types 4 (hard link) and 5 (file copy) name another member from the
# archive root; types 1 to 3 are symbolic links and junctions.
_REDIRECT_ROOT_RELATIVE = (4, 5)


def _redirection(data: bytes, pos: int, end: int) -> tuple[str, bool] | None:
    """Return ``(target, root_relative)`` from a redirection record, if any."""

    while pos < end:
        try:
            rec_size, after_size = _read_vint(data, pos)
            rec_type, body = _read_vint(data, after_size)
        except ValueError:
            return None
        if rec_type == _EXTRA_REDIRECTION:
            try:
                redirect_type, body = _read_vint(data, body)
                _flags, body = _read_vint(data, body)
                name_len, body = _read_vint(data, body)
            except ValueError:
                return ("", False)
            target = data[body : body + name_len].decode("utf-8", errors="replace")
            return (target, redirect_type in _REDIRECT_ROOT_RELATIVE)
        if rec_size <= 0:
            break
        pos = after_size + rec_size
    return None
