"""A small tolerant reader for JSON with comments and trailing commas (JSONC).

Editor task files allow ``//`` and ``/* */`` comments and a trailing comma,
which the standard JSON reader rejects. This normalizes those away, honoring
string literals so a comment marker inside a string is left alone, and then
reads the result as plain JSON. Reading never executes anything and never
raises: malformed input returns None.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


def strip_jsonc(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    quote = ""
    while i < n:
        char = text[i]
        if in_string:
            out.append(char)
            if char == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if char == quote:
                in_string = False
            i += 1
            continue
        if char in ('"', "'"):
            in_string = True
            quote = char
            out.append(char)
            i += 1
            continue
        if char == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if char == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(char)
        i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    result: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    quote = ""
    while i < n:
        char = text[i]
        if in_string:
            result.append(char)
            if char == "\\" and i + 1 < n:
                result.append(text[i + 1])
                i += 2
                continue
            if char == quote:
                in_string = False
            i += 1
            continue
        if char in ('"', "'"):
            in_string = True
            quote = char
            result.append(char)
            i += 1
            continue
        if char == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        result.append(char)
        i += 1
    return "".join(result)


def loads_jsonc(text: str) -> Any:
    try:
        return json.loads(strip_jsonc(text))
    except (ValueError, RecursionError):
        return None


JsonPath = tuple[str | int, ...]


@dataclass
class _Frame:
    """One open object or array: its current key or index, and whether the
    next string in an object is a key."""

    is_object: bool
    key: str | int | None
    expecting_key: bool


def key_lines(text: str) -> dict[JsonPath, int]:
    """The line of every object key, by its path of keys and array indexes.

    A tolerant single pass over the text, with comments skipped and line
    numbers kept, so a finding can point at the key it is about rather than at
    the first place the same word appears. A key repeated in one object keeps
    its last line, matching the JSON reader, which keeps the last value.
    Malformed input yields whatever was read; this never raises.
    """

    out: dict[JsonPath, int] = {}
    stack: list[_Frame] = []
    line = 1
    i = 0
    n = len(text)
    while i < n:
        char = text[i]
        if char == "\n":
            line += 1
            i += 1
        elif char == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif char == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            line += text.count("\n", i, end)
            i = end
        elif char in "{[":
            is_object = char == "{"
            stack.append(_Frame(is_object, None if is_object else 0, is_object))
            i += 1
        elif char in "}]":
            if stack:
                stack.pop()
            i += 1
        elif char == ",":
            if stack:
                frame = stack[-1]
                if frame.is_object:
                    frame.expecting_key = True
                elif isinstance(frame.key, int):
                    frame.key += 1
            i += 1
        elif char in "\"'":
            start_line = line
            value, i, line = _read_string(text, i, line)
            top = stack[-1] if stack else None
            if top is not None and top.is_object and top.expecting_key and _colon_follows(text, i):
                top.key = value
                top.expecting_key = False
                out[_path(stack)] = start_line
        else:
            i += 1
    return out


def _read_string(text: str, start: int, line: int) -> tuple[str, int, int]:
    quote = text[start]
    i = start + 1
    n = len(text)
    chars: list[str] = []
    while i < n and text[i] != quote:
        if text[i] == "\\" and i + 1 < n:
            chars.append(text[i + 1])
            i += 2
            continue
        if text[i] == "\n":
            line += 1
        chars.append(text[i])
        i += 1
    return "".join(chars), i + 1, line


def _colon_follows(text: str, i: int) -> bool:
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    return i < n and text[i] == ":"


def _path(stack: list[_Frame]) -> JsonPath:
    return tuple(frame.key for frame in stack if frame.key is not None)
