"""Compatibility module forwarding to the single ``motoko`` CLI."""

from __future__ import annotations

import sys

from core.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["interface", *sys.argv[1:]]))
