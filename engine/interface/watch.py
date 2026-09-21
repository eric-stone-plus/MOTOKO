"""``motoko watch`` — Rich Live fullscreen rotator tier (DESIGN section 0, tier 2).

The minimal real-time layer for machines that have rich but not Textual: a
1s poll loop collects one frozen :class:`InterfaceSnapshot` per tick in a
worker thread (crash isolation, design section 2: a failing/stalling
collector never takes the UI down) and Rich Live repaints a rotating stack
of panel renderables built from :mod:`interface.render.panels` —
page 0 is the OVERVIEW wall (engagements table + run progress + feed tail),
page 1 the ENGAGEMENT drill-down (cooldowns/legs/gates). The page flips
every ``rotate_after`` ticks; ``q`` or Ctrl-C exits cleanly.

Graceful degradation (design P4/P6):
- no alternate screen: Live runs inline (``screen=False``), so there is no
  mode-switch flicker; Live's context exit restores the terminal, and the
  key watcher restores termios settings in its own ``finally``;
- a provider that raises or stalls keeps the last good frame on screen and
  raises the STALE banner — never fake freshness;
- without rich the module still imports (the poll loop is stdlib-only) and
  :func:`run_watch` falls back to printing one one-shot status frame.

``--theme`` is resolved through :mod:`interface.render.theme`
(built-in name or key=value file). Because panels.py bakes token colors
into the Text objects inline, a ``rich.Console(theme=...)`` mapping is
applied *additionally* (token names as rich style names) so future
renderables can reference tokens symbolically; it is not required for the
current panels, which carry their colors inline (documented limitation:
styles already inlined by panels are not remapped by the Console theme).

stdlib + rich only; no Textual import. The poll-loop core
(:class:`WatchLoop`, :func:`poll_once`) is unit-testable with a stub
provider and never starts Live.

Future cli.py wiring (cli.py is owned by another stream — add exactly this):

    watch_parser = subparsers.add_parser("watch", help="Rich Live rotator")
    watch_parser.add_argument("--demo", action="store_true")
    watch_parser.add_argument("--root", type=Path, default=None)
    watch_parser.add_argument("--theme", default="motoko-dark")
    watch_parser.set_defaults(func=run_watch)  # from .watch
    # and in main():  return args.func(args)
"""

from __future__ import annotations

import argparse
import select
import sys
import threading
import time
from collections.abc import Callable

from interface.collectors import build_interface_snapshot
from interface.snapshot import InterfaceSnapshot

try:  # the poll loop below is stdlib-only; rich is needed for rendering only
    from rich.console import Console, Group
    from rich.live import Live
    from rich.text import Text
    from rich.theme import Theme as RichTheme

    from interface.render import panels
    from interface.render.theme import Theme, get_builtin_theme, load_theme_file

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - degraded path is covered via monkeypatch
    RICH_AVAILABLE = False

#: The cli.py seam: any zero-arg callable returning one consistent frame.
Provider = Callable[[], InterfaceSnapshot]

DEFAULT_POLL_S = 1.0
"""One poll per second (design section 6: global tick 1s)."""

POLL_TIMEOUT_S = 5.0
"""A provider that has not answered within this window counts as stalled."""

ROTATE_AFTER_TICKS = 10
"""Flip to the next page after this many ticks (10 ticks at 1s each)."""

FEED_LINES = 8
"""Activity-feed tail length shown on the overview page."""

PAGES: tuple[str, ...] = ("overview", "engagement")
"""The rotator pages, in flip order."""

__all__ = [
    "DEFAULT_POLL_S",
    "FEED_LINES",
    "PAGES",
    "POLL_TIMEOUT_S",
    "RICH_AVAILABLE",
    "ROTATE_AFTER_TICKS",
    "Provider",
    "WatchLoop",
    "build_frame",
    "poll_once",
    "resolve_theme",
    "run_watch",
]


# ------------------------------------------------------------ poll loop core


def poll_once(
    provider: Provider, *, timeout_s: float = POLL_TIMEOUT_S
) -> tuple[InterfaceSnapshot | None, str | None]:
    """Run ``provider`` in a worker thread; return ``(snapshot, error)``.

    Exactly one half of the pair is meaningful: a successful poll returns
    ``(snapshot, None)``; a raised provider returns ``(None, "Exc: msg")``;
    a provider that stalls past ``timeout_s`` returns ``(None, ...stalled
    ...)`` and the daemon worker is left to die with the process. Never
    raises (crash isolation, design section 2).
    """
    outcome: list[tuple[str, object]] = []

    def _work() -> None:
        try:
            outcome.append(("ok", provider()))
        except Exception as exc:  # noqa: BLE001 - any failure must degrade
            outcome.append(("error", f"{type(exc).__name__}: {exc}"))

    worker = threading.Thread(target=_work, name="motoko-watch-collector", daemon=True)
    worker.start()
    worker.join(timeout_s)
    if not outcome:
        return None, f"collector stalled > {timeout_s:.0f}s"
    kind, payload = outcome[0]
    if kind == "error":
        return None, str(payload)
    return payload, None  # type: ignore[return-value]  # ("ok", snapshot)


class WatchLoop:
    """Poll-loop state machine: one :meth:`tick` per cycle, no Live required.

    A good frame replaces the displayed snapshot and clears any previous
    transport error; a frame carrying ``collector_error`` keeps its data but
    flags STALE. A poll failure (raise/stall) keeps the last good frame on
    screen and flags STALE with the failure reason (P6: never fake
    freshness).
    """

    def __init__(
        self,
        provider: Provider,
        *,
        poll_interval_s: float = DEFAULT_POLL_S,
        poll_timeout_s: float = POLL_TIMEOUT_S,
    ) -> None:
        self.provider = provider
        self.poll_interval_s = poll_interval_s
        self.poll_timeout_s = poll_timeout_s
        self.tick_count = 0
        self.snapshot: InterfaceSnapshot | None = None
        self.error: str | None = None
        self.stop_requested = False

    def tick(self) -> bool:
        """Run one poll cycle; return False once the loop should stop."""
        if self.stop_requested:
            return False
        self.tick_count += 1
        snapshot, error = poll_once(self.provider, timeout_s=self.poll_timeout_s)
        if error is None and snapshot is not None:
            self.snapshot = snapshot
            self.error = snapshot.collector_error or None
        elif error is not None:
            self.error = error  # keep the last good frame on screen
        return not self.stop_requested

    @property
    def stale(self) -> bool:
        """True while the STALE banner must show (poll or collector error)."""
        return self.error is not None

    def stop(self) -> None:
        """Request a clean stop; the next tick is a no-op."""
        self.stop_requested = True


# ---------------------------------------------------------------- rendering


def resolve_theme(name: str) -> tuple[Theme | None, list[str]]:
    """Resolve ``--theme``: built-in name first, else a key=value file path.

    Returns ``(theme, warnings)``; a missing/unreadable file yields
    ``(None, warnings)`` so the caller can fall back to motoko-dark.
    """
    if not RICH_AVAILABLE:  # pragma: no cover - degraded branch
        return None, ["rich not available; theme ignored"]
    builtin = get_builtin_theme(name)
    if builtin is not None:
        return builtin, []
    try:
        return load_theme_file(name)
    except OSError as exc:
        return None, [f"theme {name!r} unreadable ({exc}); using motoko-dark"]


def build_frame(
    loop: WatchLoop,
    theme: Theme,
    *,
    theme_name: str,
    watched: str | None,
    page: int,
    uptime_s: float,
) -> Group:
    """One rotator frame: ``PAGES[page % len(PAGES)]`` body plus footer."""
    index = page % len(PAGES)
    if index == 0:
        body = _overview_page(loop, theme, theme_name=theme_name, watched=watched,
                              uptime_s=uptime_s)
    else:
        body = _engagement_page(loop, theme, theme_name=theme_name, watched=watched,
                                uptime_s=uptime_s)
    footer = Text(
        f"page {index + 1}/{len(PAGES)} ({PAGES[index]})   q quit   ctrl-c quit",
        style=theme.style("text.muted"),
    )
    return Group(body, Text(), footer)


def _header_parts(
    loop: WatchLoop,
    theme: Theme,
    *,
    theme_name: str,
    watched: str | None,
    uptime_s: float,
) -> list[Text]:
    """Topbar plus the STALE banner when the current frame is not fresh."""
    parts = [panels.topbar(loop.snapshot, theme, theme_name=theme_name,
                           watched=watched, uptime_s=uptime_s)]
    if loop.stale:
        banner = Text(f"STALE - {loop.error}", style=f"bold {theme.style('state.crit')}")
        parts.append(banner)
    return parts


def _overview_page(
    loop: WatchLoop,
    theme: Theme,
    *,
    theme_name: str,
    watched: str | None,
    uptime_s: float,
) -> Group:
    """OVERVIEW wall: engagements table, run progress, activity feed tail."""
    parts: list[Text | Group] = _header_parts(loop, theme, theme_name=theme_name,
                                              watched=watched, uptime_s=uptime_s)
    snapshot = loop.snapshot
    if snapshot is None:
        parts.append(Text("waiting for first frame...", style=theme.style("text.muted")))
        return Group(*parts)
    table = panels.Table.grid(padding=(0, 2))
    for _key, label in panels.ENGAGEMENT_COLUMNS:
        table.add_column(label)
    for eng in snapshot.engagements:
        table.add_row(*panels.engagement_row_cells(eng, theme))
    parts.append(table)
    followed = panels.pick_engagement(snapshot, watched)
    parts.append(Text())
    parts.append(panels.run_progress(followed, theme))
    if followed is not None and followed.events_tail:
        parts.append(Text())
        for event in followed.events_tail[-FEED_LINES:]:
            parts.append(panels.event_line(event, theme))
    return Group(*parts)


def _engagement_page(
    loop: WatchLoop,
    theme: Theme,
    *,
    theme_name: str,
    watched: str | None,
    uptime_s: float,
) -> Group:
    """ENGAGEMENT drill-down page: cooldowns, loop legs, gates."""
    parts: list[Text | Group] = _header_parts(loop, theme, theme_name=theme_name,
                                              watched=watched, uptime_s=uptime_s)
    followed = panels.pick_engagement(loop.snapshot, watched)
    parts.append(panels.run_progress_header(followed, theme))
    parts.append(Text())
    parts.append(panels.cooldowns_panel(followed, theme))
    parts.append(Text())
    if followed is not None:  # legs/gates need an engagement, unlike cooldowns
        parts.append(panels.legs_panel(followed, theme))
        parts.append(Text())
        parts.append(panels.gates_panel(followed, theme))
    return Group(*parts)


# ------------------------------------------------------------------ running


def run_watch(
    args: argparse.Namespace | None = None,
    *,
    provider: Provider | None = None,
    console: Console | None = None,
    max_ticks: int | None = None,
    poll_interval_s: float = DEFAULT_POLL_S,
    rotate_after: int = ROTATE_AFTER_TICKS,
) -> int:
    """cli.py entry point: run the Rich Live rotator until q / Ctrl-C.

    ``args`` needs ``demo`` (bool), ``root`` (Path | None) and optionally
    ``theme`` (str); ``provider``/``console``/``max_ticks`` override the
    defaults for tests. Returns 0 on every clean exit path.
    """
    if args is None:
        args = argparse.Namespace(demo=False, root=None, theme="motoko-dark")
    resolved = provider
    if resolved is None:
        root = getattr(args, "root", None)
        demo = bool(getattr(args, "demo", False))

        def resolved() -> InterfaceSnapshot:
            return build_interface_snapshot(root, demo)

    if not RICH_AVAILABLE:
        # graceful degradation: no rich -> print one one-shot frame and exit
        from interface.status import render_status

        print(render_status(resolved()))
        return 0

    theme_name = str(getattr(args, "theme", "motoko-dark") or "motoko-dark")
    theme, warnings = resolve_theme(theme_name)
    if theme is None:
        theme_name = "motoko-dark"
        theme = get_builtin_theme(theme_name)
    if theme is None:  # pragma: no cover - motoko-dark always exists
        print("watch: no usable theme", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"theme warning: {warning}", file=sys.stderr)
    if console is None:
        console = Console(theme=_rich_console_theme(theme))
    loop = WatchLoop(resolved, poll_interval_s=poll_interval_s)
    watcher = _spawn_key_watcher(loop.stop)
    started = time.monotonic()
    try:
        # screen=False: inline rendering, no alternate-screen flicker; the
        # context exit restores the terminal even on Ctrl-C.
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            while not loop.stop_requested and (max_ticks is None
                                               or loop.tick_count < max_ticks):
                loop.tick()
                page = (loop.tick_count // max(1, rotate_after)) % len(PAGES)
                live.update(build_frame(loop, theme, theme_name=theme_name,
                                        watched=getattr(args, "watched", None),
                                        page=page,
                                        uptime_s=time.monotonic() - started))
                _interruptible_sleep(poll_interval_s, loop)
    except KeyboardInterrupt:
        pass  # Ctrl-C is a clean exit path
    finally:
        loop.stop()
        if watcher is not None:
            watcher_thread, watcher_stop = watcher
            watcher_stop.set()
            watcher_thread.join(timeout=1.0)
    return 0


def _interruptible_sleep(seconds: float, loop: WatchLoop) -> None:
    """Sleep in small slices so 'q' reacts within ~50ms, not a full second."""
    deadline = time.monotonic() + max(0.0, seconds)
    while time.monotonic() < deadline and not loop.stop_requested:
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def _rich_console_theme(theme: Theme) -> RichTheme:
    """Map our token schema onto rich style names (token name = style name).

    Straightforward 1:1 mapping; the current panels do not reference these
    names (colors ride inline), so this only future-proofs the Console.
    """
    return RichTheme({name: value for name, value in theme.tokens.items()})


def _spawn_key_watcher(
    on_quit: Callable[[], None],
) -> tuple[threading.Thread, threading.Event] | None:
    """Best-effort 'q' key watcher: POSIX tty only, never blocks exit.

    Puts the terminal into cbreak mode and watches stdin for ``q``/``Q``;
    restores the previous termios attributes in its ``finally`` (also when
    stopped via the returned event). Returns (thread, stop_event) or None
    when there is no usable tty / termios (Windows, pipes, pytest).
    """
    try:
        import termios
        import tty

        if not sys.stdin.isatty():
            return None
        fd = sys.stdin.fileno()
    except (ImportError, ValueError, OSError):
        return None
    stop = threading.Event()

    def _watch() -> None:
        try:
            previous = termios.tcgetattr(fd)
        except (OSError, ValueError, termios.error):
            return
        try:
            tty.setcbreak(fd)
            while not stop.is_set():
                ready, _, _ = select.select([fd], [], [], 0.2)
                if not ready:
                    continue
                char = sys.stdin.read(1)
                if not char:  # EOF: stop watching, restore the terminal
                    return
                if char in ("q", "Q"):
                    on_quit()
                    return
        except (OSError, ValueError):
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, previous)
            except termios.error:
                pass

    thread = threading.Thread(target=_watch, name="motoko-watch-keys", daemon=True)
    thread.start()
    return thread, stop
