"Interface dispatch behind the engine's single ``motoko`` CLI."

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path

from interface.snapshot import InterfaceSnapshot

Provider = Callable[[], InterfaceSnapshot]


def load_provider(*, demo: bool, root: Path | None,
                  runtime_root: Path | None = None) -> tuple[Provider, str | None]:
    """Build a provider; root is the project home, runtime_root holds data."""
    from interface.collectors import build_interface_snapshot

    return (lambda: build_interface_snapshot(root, demo, runtime_root=runtime_root)), None


def run(args: argparse.Namespace) -> int:
    """Render the read-only status snapshot with the engine-selected runtime."""
    from core import util
    from interface.collectors import close_sessions

    provider, _notice = load_provider(demo=args.demo, root=util.motoko_root(),
                                      runtime_root=args.root)
    try:
        from interface.status import render_status_and_print

        return render_status_and_print(args, provider=provider)
    finally:
        close_sessions()
