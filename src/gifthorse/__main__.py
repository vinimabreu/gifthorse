"""``python -m gifthorse`` entry point, which refuses to run unprotected.

Plain ``python -m`` puts the current directory first on the import path before
any of this package's code runs, so a file in that directory named like a
standard-library module (``json.py``, ``argparse.py``) is imported in place of
the real one. The guard below cannot undo that for modules the interpreter
itself imports while starting the module runner (a planted ``importlib.py``
runs before this file does). What it can do is refuse to go any further unless
the interpreter was started with that path entry switched off: ``-P``,
``PYTHONSAFEPATH=1`` or ``-I``. Only ``sys`` is used before the decision, and
no ``__future__`` import is used, since that module is not guaranteed to be
loaded yet. The installed ``gifthorse`` command is not affected: its first
path entry is the scripts directory, not the current one.
"""

import sys

_REFUSAL = (
    "gifthorse: refusing to run as 'python -m gifthorse' without -P.\n"
    "Plain 'python -m' imports files from the current directory before the real\n"
    "standard library, so a folder you received could run code here. Use the\n"
    "installed 'gifthorse' command, or 'python -P -m gifthorse' (or set\n"
    "PYTHONSAFEPATH=1), and never start Python from inside a received folder.\n"
)


def is_protected() -> bool:
    """True when the current directory is not on the import path."""

    return bool(sys.flags.safe_path or sys.flags.isolated)


def main(argv: "list[str] | None" = None) -> int:
    if not is_protected():
        sys.stderr.write(_REFUSAL)
        return 2
    from .cli import main as cli_main

    return cli_main(list(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    raise SystemExit(main())
