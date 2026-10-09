'Render layer for the MOTOKO interface.'

from __future__ import annotations

__all__ = [
    "redact",
]

_LAZY_SUBMODULES = ("redact",)


def __getattr__(name: str):
    """Resolve submodules on first access."""
    if name in _LAZY_SUBMODULES:
        import importlib

        module = importlib.import_module(f".{name}", __name__)
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
