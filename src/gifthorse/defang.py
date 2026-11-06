"""Turn live indicators into inert text and pull them out of a snippet.

Defanging makes a URL, host or IP safe to paste into a chat or an abuse
report: no client will turn ``hxxps://a[.]example[.]invalid`` into a request.
Only real indicators are rewritten, so a file name like ``Budget.vbs`` or a
call like ``JSON.stringify`` is left readable. Indicators and evidence are
defanged in every output, the ``--iocs`` block included; the raw value travels
only in the JSON ``value`` field. Member paths and target names are shown as
they are, since they name what you received.

A bare dotted name counts as a host when its last label is a known TLD, or
when it is the argument of a download command (curl, wget, fetch,
Invoke-WebRequest, iwr, certutil -urlcache, bitsadmin /transfer), whatever its
TLD: that is where a scheme-less staging host sits.
"""

from __future__ import annotations

import re

from .model import Indicator

_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'`<>)\]}]+", re.IGNORECASE)
# A host starts only where no label character, dot or hyphen comes before it. With a
# plain word boundary, a run like a.a.a.a offers a start at every label and each
# start walks the rest of the run, which is quadratic.
_HOST = re.compile(
    r"(?<![a-z0-9.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}\b",
    re.IGNORECASE,
)
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
_SHA = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)
_WALLET = re.compile(r"\b0x[0-9a-f]{40}\b", re.IGNORECASE)
_SCHEME = re.compile(r"\b(https?|ftp|wss?)(://)", re.IGNORECASE)

# A bare dotted name is only treated as a host when its last label is a known
# or reserved TLD. This keeps file names and member access (Budget.vbs,
# JSON.stringify, module.exports, WinHttp.WinHttpRequest) out of the host list.
_TLDS = frozenset(
    {
        "invalid",
        "test",
        "example",
        "localhost",
        "local",
        "onion",
        "com",
        "net",
        "org",
        "io",
        "dev",
        "app",
        "co",
        "ai",
        "me",
        "tv",
        "cc",
        "info",
        "biz",
        "xyz",
        "online",
        "site",
        "tech",
        "cloud",
        "store",
        "shop",
        "edu",
        "gov",
        "mil",
        "int",
        "eu",
        "us",
        "uk",
        "ca",
        "de",
        "fr",
        "nl",
        "au",
        "jp",
        "cn",
        "ru",
        "br",
        "in",
        "it",
        "es",
        "se",
        "ch",
        "pl",
        "kr",
    }
)


# A download command and the arguments after it, up to a pipe, a command
# separator or the next download command (so a run of repeated commands is
# still read from one start per character).
_FETCH_CMD = r"(?:curl|wget|fetch|invoke-webrequest|iwr|certutil(?:\.exe)?|bitsadmin(?:\.exe)?)"
_FETCH_ARGS = re.compile(
    r"\b(?P<cmd>" + _FETCH_CMD + r")\b(?P<args>(?:(?!\b" + _FETCH_CMD + r"\b)[^\n|;&])*+)",
    re.IGNORECASE,
)
_ARG_SPLIT = re.compile(r"[\s'\"`()<>,=]+")
_HOST_ARG = re.compile(
    r"(?<![a-z0-9.-])(?P<host>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23})"
    r"(?::\d{1,5})?(?P<path>/\S*)?",
    re.IGNORECASE,
)
# A dotted argument with no path whose last label is a common file extension is
# an output or input file name (-o stage.bat), not a host.
_FILE_LABELS = frozenset(
    {
        "sh",
        "bash",
        "ps1",
        "bat",
        "cmd",
        "exe",
        "dll",
        "msi",
        "vbs",
        "js",
        "json",
        "txt",
        "zip",
        "tar",
        "gz",
        "tgz",
        "xz",
        "bz2",
        "py",
        "pl",
        "rb",
        "php",
        "html",
        "htm",
        "xml",
        "csv",
        "log",
        "md",
        "jar",
        "bin",
        "dat",
        "tmp",
        "conf",
        "cfg",
        "ini",
        "yaml",
        "yml",
        "toml",
        "pem",
        "key",
        "crt",
        "deb",
        "rpm",
        "dmg",
        "pkg",
        "iso",
        "img",
        "apk",
        "so",
        "dylib",
        "lnk",
        "hta",
        "scr",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "mov",
        "mp4",
        "plist",
        "out",
    }
)


def _command_hosts(text: str) -> list[str]:
    """Dotted host arguments of download commands, whatever their TLD."""

    hosts: list[str] = []
    for match in _FETCH_ARGS.finditer(text):
        cmd = match.group("cmd").lower()
        args = match.group("args")
        if cmd.startswith("certutil") and "-urlcache" not in args.lower():
            continue
        if cmd.startswith("bitsadmin") and "/transfer" not in args.lower():
            continue
        for token in _ARG_SPLIT.split(args):
            if not token or token.startswith(("-", "/")):
                continue
            found = _HOST_ARG.fullmatch(token)
            if found is None:
                continue
            host = found.group("host")
            last = host.rsplit(".", 1)[-1].lower()
            if found.group("path") is None and last in _FILE_LABELS:
                continue
            hosts.append(host)
    return hosts


def _defang_host(value: str) -> str:
    return value.replace(".", "[.]")


def _defang_url(value: str) -> str:
    out = _SCHEME.sub(lambda m: m.group(1).replace("t", "x") + "[://]", value)
    if "[://]" not in out:
        out = out.replace("://", "[://]")
    return out.replace(".", "[.]")


def _is_host(value: str) -> bool:
    label = value.rsplit(".", 1)[-1].lower()
    return label in _TLDS


def extract_indicators(text: str) -> tuple[Indicator, ...]:
    """Find URLs, hosts, IPs, long hashes and ETH-style wallets in ``text``."""

    found: dict[tuple[str, str], Indicator] = {}

    def add(kind: str, value: str, defanged: str) -> None:
        found.setdefault((kind, value), Indicator(kind, value, defanged))

    covered: list[tuple[int, int]] = []
    for match in _URL.finditer(text):
        raw = match.group(0).rstrip(".,);]'\"")
        add("url", raw, _defang_url(raw))
        covered.append((match.start(), match.start() + len(raw)))

    def inside_url(start: int, end: int) -> bool:
        return any(a <= start and end <= b for a, b in covered)

    for match in _WALLET.finditer(text):
        add("wallet", match.group(0), match.group(0))
    for match in _SHA.finditer(text):
        if not _WALLET.fullmatch(match.group(0)):
            add("sha256", match.group(0), match.group(0))
    for match in _IPV4.finditer(text):
        add("ipv4", match.group(0), match.group(0).replace(".", "[.]"))
    for match in _IPV6.finditer(text):
        if match.group(0).count(":") >= 2:
            add("ipv6", match.group(0), match.group(0).replace(":", "[:]"))
    for match in _HOST.finditer(text):
        value = match.group(0)
        if inside_url(match.start(), match.end()):
            continue
        if _IPV4.fullmatch(value) or not _is_host(value):
            continue
        add("host", value, _defang_host(value))
    for value in _command_hosts(text):
        if not _IPV4.fullmatch(value):
            add("host", value, _defang_host(value))

    return tuple(found.values())


def escape_controls(text: str) -> str:
    """Escape control, format and line-separator characters so text from a
    received file cannot move the cursor, clear the terminal or reorder the
    line it is printed on. Printable text, backslashes included, is unchanged."""

    if text.isprintable():
        return text
    out: list[str] = []
    for char in text:
        if char.isprintable() or char == " ":
            out.append(char)
        elif ord(char) <= 0xFF:
            out.append(f"\\x{ord(char):02x}")
        elif ord(char) <= 0xFFFF:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(f"\\U{ord(char):08x}")
    return "".join(out)


def defang(text: str) -> str:
    """Rewrite only the real indicators in ``text`` so none stays clickable."""

    indicators = extract_indicators(text)
    out = text
    for ind in sorted(indicators, key=lambda i: len(i.value), reverse=True):
        out = out.replace(ind.value, ind.defanged)
    return out
