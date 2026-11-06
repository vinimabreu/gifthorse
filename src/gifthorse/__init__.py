"""gifthorse: look a gift in the mouth before you let it in.

The public names are loaded lazily so importing the package touches nothing
beyond the standard model. This matters for ``python -m gifthorse``: plain
``python -m`` puts the current directory first on the import path, and a file
dropped there named like a standard-library module would be imported in place
of the real one. ``__main__`` refuses to go on unless that path entry is off
(``-P``, ``PYTHONSAFEPATH=1`` or ``-I``), and this file deliberately imports
nothing at module load, not even ``typing`` or ``__future__``.
"""

__version__ = "0.1.0"

__all__ = [
    "Coverage",
    "Finding",
    "Indicator",
    "Limits",
    "Report",
    "Severity",
    "Verdict",
    "scan_bytes",
    "scan_path",
]

# Type checkers treat any name called TYPE_CHECKING as always true; at runtime
# this is false, so the imports below run only for the checker, never on import.
TYPE_CHECKING = False
if TYPE_CHECKING:
    from .engine import scan_bytes, scan_path
    from .model import Coverage, Finding, Indicator, Limits, Report, Severity, Verdict

_ENGINE = {"scan_bytes", "scan_path"}
_MODEL = {"Coverage", "Finding", "Indicator", "Limits", "Report", "Severity", "Verdict"}


def __getattr__(name: str) -> object:
    if name in _ENGINE:
        from . import engine

        return getattr(engine, name)
    if name in _MODEL:
        from . import model

        return getattr(model, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
