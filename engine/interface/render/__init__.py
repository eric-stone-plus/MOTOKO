'Render layer for the MOTOKO interface.\n\nFramework-independent: pure functions from frozen snapshot dataclasses to\nRich renderables (:mod:`.panels`), plus theme tokens (:mod:`.theme`) and the\nP5 redaction helpers (:mod:`.redact`). No Textual import anywhere in this\npackage, so a future Rich-Live ``motoko watch`` tier can reuse everything.'

from __future__ import annotations

__all__ = [
    "Theme",
    "get_builtin_theme",
    "letter_flags",
    "load_theme_file",
    "panels",
    "redact",
    "theme",
]

_LAZY_SUBMODULES = ("panels", "redact", "theme")
_THEME_REEXPORTS = ("Theme", "get_builtin_theme", "letter_flags", "load_theme_file")


def __getattr__(name: str):
    """Resolve submodules and theme re-exports on first access."""
    if name in _LAZY_SUBMODULES:
        import importlib

        module = importlib.import_module(f".{name}", __name__)
        globals()[name] = module
        return module
    if name in _THEME_REEXPORTS:
        from . import theme as _theme

        return getattr(_theme, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
