"""The RAR5 header reader: names, directories, encrypted headers, bad input."""

from __future__ import annotations

from gifthorse.rar5 import read_rar5_names

from . import builders as b


def test_names_round_trip_through_the_reader() -> None:
    data = b.make_rar5({"a.txt": b"one", "docs/b.md": b"two", "shot.png": b.PNG})
    result = read_rar5_names(data)
    names = [name for name, _is_dir, _is_link in result.rows]
    assert names == ["a.txt", "docs/b.md", "shot.png"]
    assert result.encrypted is False
    assert result.error is False


def test_directory_entry_is_marked() -> None:
    data = b.make_rar5({"folder/": b"", "folder/file.txt": b"x"})
    result = read_rar5_names(data)
    marks = {name: is_dir for name, is_dir, _is_link in result.rows}
    assert marks["folder/"] is True
    assert marks["folder/file.txt"] is False


def test_encrypted_headers_report_no_names() -> None:
    data = b.make_rar5_encrypted_headers()
    result = read_rar5_names(data)
    assert result.encrypted is True
    assert result.rows == []


def test_not_a_rar5_reports_an_error() -> None:
    result = read_rar5_names(b"not a rar archive at all")
    assert result.rows == []
    assert result.encrypted is False
    assert result.error is True


def test_truncated_archive_does_not_raise() -> None:
    data = b.make_rar5({"a.txt": b"hello world", "b.txt": b"more"})
    for cut in range(len(data)):
        result = read_rar5_names(data[:cut])
        assert isinstance(result.rows, list)
        assert isinstance(result.encrypted, bool)
        assert isinstance(result.error, bool)
