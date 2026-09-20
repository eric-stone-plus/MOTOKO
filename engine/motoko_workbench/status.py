"""``motoko status`` — one-shot summary tier (DESIGN section 0, tier 1).

Renders one frozen :class:`WorkbenchSnapshot` as a compact static table and
exits: the cron/script/SSH glance whose zero-dependency claim is binding.
Rich is used for table layout *only when importable*; every path degrades
to a plain ASCII table rendered by stdlib code, so the tier stays usable in
a bare python3. Output is deliberately uncolored plain text (grep-able,
log-friendly); ASCII placeholders ("-" for unknown, a fixed-width ``·`` flag
cell mirroring render.theme.FLAG_SPECS order) keep it pipe-safe.

P5 redaction: this tier renders *counts and shapes* only. All content
arrives pre-redacted upstream (collectors -> render.redact) and event
summaries are contract-safe, so they render as-is; the only free text that
is NOT contract-clean — the heartbeat message (a raw engine-written file)
and the collector error string — passes through
:func:`motoko_workbench.render.redact.redact_text` as belt-and-braces. No
filesystem, no network, no subprocess is touched.

stdlib + rich(-if-present) only; no Textual import.

Future cli.py wiring (cli.py is owned by another stream — add exactly this):

    status_parser = subparsers.add_parser(
        "status", help="one-shot plain summary (zero-dependency tier)")
    status_parser.add_argument("--demo", action="store_true")
    status_parser.add_argument("--root", type=Path, default=None)
    status_parser.set_defaults(func=render_status_and_print)  # from .status
    # and in main():  return args.func(args)
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable
from typing import TextIO

from motoko_workbench.collectors import build_workbench_snapshot
from motoko_workbench.render.redact import redact_text
from motoko_workbench.snapshot import (
    HYP_STATES,
    EngagementSnapshot,
    GatesSummary,
    WorkbenchSnapshot,
)

try:  # rich is layout sugar for this tier, never a requirement
    import rich.console

    _HAVE_RICH = True
except ImportError:  # pragma: no cover - simulated via monkeypatch in tests
    _HAVE_RICH = False

#: The cli.py seam: any zero-arg callable returning one consistent frame.
Provider = Callable[[], WorkbenchSnapshot]

#: Column model of the summary table (order is fixed; both render paths align).
STATUS_HEADERS: tuple[str, ...] = (
    "engagement", "state", "hb", "runner", "hyps", "finds", "wave", "cd",
    "gates", "flags",
)

#: Columns rendered right-aligned in the rich path (indices into STATUS_HEADERS).
_RIGHT_ALIGNED = frozenset({4, 5, 6, 7})

__all__ = [
    "STATUS_HEADERS",
    "Provider",
    "render_status",
    "render_status_and_print",
    "render_status_plain",
]


def render_status(snapshot: WorkbenchSnapshot) -> str:
    """Render one snapshot as a compact summary string (pure, no printing).

    Uses a rich-rendered boxed table when rich is importable, otherwise the
    guaranteed-stdlib ASCII table. Both paths carry identical content; see
    :func:`render_status_plain` for the always-available shape.
    """
    if _HAVE_RICH:
        rendered = _rich_status(snapshot)
        if rendered is not None:
            return rendered
    return render_status_plain(snapshot)


def render_status_plain(snapshot: WorkbenchSnapshot) -> str:
    """Render the summary with stdlib only — the zero-dependency fallback.

    Never touches rich, so it works with rich absent; the returned string is
    a header line, an ASCII-ruled table (one row per engagement) and note
    lines (collector error, recent activity).
    """
    header, rows, notes = _status_parts(snapshot)
    widths = list(map(len, STATUS_HEADERS))
    for row in rows:
        widths = [max(w, len(cell)) for w, cell in zip(widths, row)]
    lines = [header, ""]
    lines.append("  ".join(h.ljust(w) for h, w in zip(STATUS_HEADERS, widths)).rstrip())
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip())
    lines.append("")
    lines.extend(notes)
    return "\n".join(lines)


def render_status_and_print(
    args: argparse.Namespace,
    *,
    provider: Provider | None = None,
    out: TextIO | None = None,
) -> int:
    """cli.py entry point: collect one frame, print the status table, exit 0.

    ``args`` needs ``demo`` (bool) and ``root`` (Path | None) attributes only
    (both read defensively via getattr). ``provider`` overrides the default
    ``build_workbench_snapshot(root, demo)`` for tests. Never raises on
    collector problems: failures arrive inside the snapshot (design section
    2, crash isolation).
    """
    if provider is None:
        root = getattr(args, "root", None)
        demo = bool(getattr(args, "demo", False))

        def provider() -> WorkbenchSnapshot:
            return build_workbench_snapshot(root, demo)

    print(render_status(provider()), file=out if out is not None else sys.stdout)
    return 0


# ----------------------------------------------------------------- content


def _status_parts(
    snapshot: WorkbenchSnapshot,
) -> tuple[str, list[tuple[str, ...]], list[str]]:
    """Single content source for both render paths: header, rows, notes."""
    rows = [_engagement_row(eng) for eng in snapshot.engagements]
    notes: list[str] = []
    if snapshot.collector_error:
        notes.append(f"COLLECTOR ERROR: {redact_text(snapshot.collector_error)}")
    if not snapshot.engagements:
        notes.append("no engagements in snapshot")
    else:
        notes.extend(_followed_notes(snapshot))
    return _header_line(snapshot), rows, notes


def _header_line(snapshot: WorkbenchSnapshot) -> str:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(snapshot.taken_at))
    return f"MOTOKO status - {stamp} - {len(snapshot.engagements)} engagement(s)"


def _engagement_row(eng: EngagementSnapshot) -> tuple[str, ...]:
    """One table row; cells are plain strings (pre-redacted by the contract)."""
    state = "live" if eng.live else "sealed" if eng.sealed else "idle"
    if eng.stale:
        state += " STALE"
    hyps = "/".join(str(eng.hyps.get(s, 0)) for s in HYP_STATES) if eng.hyps else "-"
    finds = str(sum(eng.findings.values())) if eng.findings else "-"
    wave = f"{eng.wave.current}/{eng.wave.total}" if eng.wave is not None else "-"
    return (
        eng.id,
        state,
        _fmt_age(eng.heartbeat_age_s),
        "alive" if eng.runner_alive else "down",
        hyps,
        finds,
        wave,
        str(len(eng.cooldowns)),
        _gates_cell(eng.gates),
        _flags_cell(eng),
    )


def _gates_cell(gates: GatesSummary | None) -> str:
    if gates is None:
        return "-"
    if not gates.doctor_available:
        return "doctor n/a"
    all_ok = gates.sections_ok == gates.sections_total and gates.ok
    return f"{gates.sections_ok}/{gates.sections_total}" + (" ok" if all_ok else " FAIL")


def _flags_cell(eng: EngagementSnapshot) -> str:
    """Letter flags derivable from the contract (mirrors panels.derive_flags).

    ``C`` cooldown active, ``W`` WAF-aware (reason=detected), ``S`` stuck
    testing (``stuck_testing_s`` above ``STUCK_AFTER_S``), ``K`` a canary
    event observed in the engagement's tail. ``L`` (lane saturation) has no
    observable data source yet and never appears (P6, see derive_flags).
    """
    from motoko_workbench.snapshot import STUCK_AFTER_S

    active = {
        "C": bool(eng.cooldowns),
        "K": eng.canary_tripped,
        "L": False,  # no observable data source yet (P6)
        "M": False,
        "S": (eng.stuck_testing_s is not None
              and eng.stuck_testing_s > STUCK_AFTER_S),
        "W": any(cd.reason == "detected" for cd in eng.cooldowns),
    }
    order = "CKLMSW"
    return "".join(letter if active[letter] else "·" for letter in order)


def _fmt_age(seconds: float | None) -> str:
    """Humanize an age exactly like panels.fmt_duration (stdlib twin)."""
    if seconds is None or seconds < 0:
        return "?"
    total = int(seconds)
    if total >= 3600:
        return f"{total // 3600}h{(total % 3600) // 60:02d}m"
    if total >= 60:
        return f"{total // 60}m{total % 60:02d}s"
    return f"{total}s"


def _followed_notes(snapshot: WorkbenchSnapshot, *, limit: int = 4) -> list[str]:
    """Active cooldowns and newest feed lines of the followed engagement.

    Follows the first live engagement, else the first one (same rule as
    panels.pick_engagement, kept stdlib-local for the plain path). Cooldown
    origins are already masked labels (``origin-<hash8>``) and event
    summaries are contract-redacted upstream, so both render as-is; the
    heartbeat message is a raw engine-written string and passes through
    ``redact_text`` here.
    """
    followed = _followed(snapshot)
    if followed is None:
        return []
    notes: list[str] = []
    if followed.cooldowns:
        notes.append("cooldowns (origins masked, P5):")
        for cd in followed.cooldowns:
            notes.append(f"  {cd.origin:<18} {_fmt_age(cd.remaining_s)} left ({cd.reason})")
    activity = ["recent activity (newest last):"]
    if followed.heartbeat_msg:
        activity.append(f"  heartbeat: {redact_text(followed.heartbeat_msg)}")
    for event in followed.events_tail[-limit:]:
        stamp = event.ts[11:19] if len(event.ts) >= 19 else event.ts
        activity.append(f"  {stamp} {event.kind:<22} {event.summary}")
    if len(activity) > 1:
        notes.extend(activity)
    return notes


def _followed(snapshot: WorkbenchSnapshot) -> EngagementSnapshot | None:
    for eng in snapshot.engagements:
        if eng.live:
            return eng
    return snapshot.engagements[0] if snapshot.engagements else None


# ------------------------------------------------------- rich layout sugar


def _rich_status(snapshot: WorkbenchSnapshot) -> str | None:
    """Render the same content through a rich boxed grid (no ANSI escapes).

    Returns None when rich cannot be imported after all (import-time probe
    raced or partial install): the caller falls back to the plain table.
    """
    try:
        from io import StringIO

        from rich import box
        from rich.console import Console, Group
        from rich.table import Table
        from rich.text import Text
    except ImportError:  # pragma: no cover - guarded by the _HAVE_RICH probe
        return None
    header, rows, notes = _status_parts(snapshot)
    table = Table(box=box.SIMPLE, pad_edge=False)
    for index, name in enumerate(STATUS_HEADERS):
        table.add_column(name, justify="right" if index in _RIGHT_ALIGNED else "left")
    for row in rows:
        table.add_row(*row)
    console = Console(file=StringIO(), width=110, highlight=False)
    console.print(Group(Text(header, style="bold"), table,
                        *(Text(note) for note in notes)))
    return console.file.getvalue()
