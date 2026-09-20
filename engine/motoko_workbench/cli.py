"""Workbench dispatch behind the engine's single ``motoko`` CLI.

The engine owns argument parsing and runtime selection. UI dependencies are
loaded only for an interactive mode; plain status remains stdlib-only.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from motoko_workbench.snapshot import WorkbenchSnapshot

Provider = Callable[[], WorkbenchSnapshot]


def load_provider(*, demo: bool, root: Path | None,
                  runtime_root: Path | None = None) -> tuple[Provider, str | None]:
    """Build a provider; root is the project home, runtime_root holds data."""
    from motoko_workbench.collectors import build_workbench_snapshot

    return (lambda: build_workbench_snapshot(root, demo, runtime_root=runtime_root)), None


def resolve_theme(name: str):
    """Resolve a built-in theme or a key=value theme file."""
    from motoko_workbench.render.theme import get_builtin_theme, load_theme_file

    builtin = get_builtin_theme(name)
    if builtin is not None:
        return builtin, []
    return load_theme_file(name)


def run(args: argparse.Namespace) -> int:
    """Run a view using the engine-selected runtime and interpreter."""
    from core import util
    from motoko_workbench.collectors import close_sessions

    provider, _notice = load_provider(demo=args.demo, root=util.motoko_root(),
                                      runtime_root=args.root)
    mode = args.mode
    if mode == "tui" and not (sys.stdin.isatty() and sys.stdout.isatty()):
        mode = "status"
    try:
        if mode == "status":
            from motoko_workbench.status import render_status_and_print

            return render_status_and_print(args, provider=provider)
        try:
            if mode == "watch":
                from motoko_workbench.watch import run_watch

                return run_watch(args, provider=provider)
            from motoko_workbench.app import WorkbenchApp

            theme, warnings = resolve_theme(args.theme)
            for warning in warnings:
                print(f"theme warning: {warning}", file=sys.stderr)
            WorkbenchApp(provider=provider, wb_theme=theme).run()
            return 0
        except ModuleNotFoundError as exc:
            if (exc.name or "").split(".")[0] not in {"textual", "rich"}:
                raise
            print("Workbench dependencies are missing. From the source checkout, run "
                  "`make -C engine install-workbench`; for a wheel, install "
                  "'core-engine[workbench]'.", file=sys.stderr)
            return 2
    finally:
        close_sessions()
