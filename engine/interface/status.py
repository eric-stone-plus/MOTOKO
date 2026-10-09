'``motoko status`` — one-shot summary tier (the internal design notes, tier 1).\n\nRenders one frozen :class:`InterfaceSnapshot` as a compact static table and\nexits: the cron/script/SSH glance whose zero-dependency claim is binding.\nRich is used for table layout *only when importable*; every path degrades\nto a plain ASCII table rendered by stdlib code, so the tier stays usable in\na bare python3. Output is deliberately uncolored plain text (grep-able,\nlog-friendly); ASCII placeholders ("-" for unknown, a fixed-width ``·`` flag\ncell in the C/K/L/M/S/W order) keep it pipe-safe.\n\nP5 redaction: this tier renders *counts and shapes* only. All content\narrives pre-redacted upstream (collectors -> render.redact) and event\nsummaries are contract-safe, so they render as-is; the only free text that\nis NOT contract-clean — the heartbeat message (a raw engine-written file)\nand the collector error string — passes through\n:func:`interface.render.redact.redact_text` as belt-and-braces. No\nfilesystem, no network, no subprocess is touched.'

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable
from typing import TextIO

from interface.collectors import build_interface_snapshot
from interface.render.redact import redact_text
from interface.snapshot import (
    HYP_STATES,
    EngagementSnapshot,
    GatesSummary,
    InterfaceSnapshot,
)

try:  # rich is layout sugar for this tier, never a requirement
    import rich.console

    _HAVE_RICH = True
except ImportError:  # pragma: no cover - simulated via monkeypatch in tests
    _HAVE_RICH = False

#: The cli.py seam: any zero-arg callable returning one consistent frame.
Provider = Callable[[], InterfaceSnapshot]

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


def render_status(snapshot: InterfaceSnapshot) -> str:
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


def render_status_plain(snapshot: InterfaceSnapshot) -> str:
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
    ``build_interface_snapshot(root, demo)`` for tests. Never raises on
    collector problems: failures arrive inside the snapshot (the internal design notes, crash isolation).
    """
    if provider is None:
        root = getattr(args, "root", None)
        demo = bool(getattr(args, "demo", False))

        def provider() -> InterfaceSnapshot:
            return build_interface_snapshot(root, demo)

    print(render_status(provider()), file=out if out is not None else sys.stdout)
    return 0


# ----------------------------------------------------------------- content


def _status_parts(
    snapshot: InterfaceSnapshot,
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
    if snapshot.served_by:
        notes.append(_provenance_note(snapshot))
    return _header_line(snapshot), rows, notes


def _provenance_note(snapshot: InterfaceSnapshot) -> str:
    """One greppable ``src:`` line: which collector served each panel.

    Full per-panel detail (the topbar shows only the compact glance form):
    ``src: engagements=fs events=ro-sqlite gates=adapter motoko/1``. Values
    are collector names stamped by the assembly layer, not target data, so
    they render as-is.
    """
    parts = " ".join(f"{panel}={source}"
                     for panel, source in snapshot.served_by.items())
    return f"src: {parts}"


def _header_line(snapshot: InterfaceSnapshot) -> str:
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
    """Letter flags derivable from the contract.

    ``C`` cooldown active, ``W`` WAF-aware (reason=detected), ``S`` stuck
    testing (``stuck_testing_s`` above ``STUCK_AFTER_S``), ``K`` a canary
    event observed in the engagement's tail. ``L`` (lane saturation) has no
    observable data source yet and never appears (P6).
    """
    from interface.snapshot import STUCK_AFTER_S

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
    """Humanize an age; stdlib-local, format fixed by the status contract."""
    if seconds is None or seconds < 0:
        return "?"
    total = int(seconds)
    if total >= 3600:
        return f"{total // 3600}h{(total % 3600) // 60:02d}m"
    if total >= 60:
        return f"{total // 60}m{total % 60:02d}s"
    return f"{total}s"


def _followed_notes(snapshot: InterfaceSnapshot, *, limit: int = 4) -> list[str]:
    """Active cooldowns and newest feed lines of the followed engagement.

    Follows the first live engagement, else the first one; kept stdlib-local
    for the plain path. Cooldown
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
        notes.append("cooldowns (origins masked):")
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


def _followed(snapshot: InterfaceSnapshot) -> EngagementSnapshot | None:
    for eng in snapshot.engagements:
        if eng.live:
            return eng
    return snapshot.engagements[0] if snapshot.engagements else None


# ------------------------------------------------------- rich layout sugar


def _rich_status(snapshot: InterfaceSnapshot) -> str | None:
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
    table = Table(box=box.SIMPLE, pad_edge=False, collapse_padding=True, expand=False)
    for index, name in enumerate(STATUS_HEADERS):
        kwargs: dict[str, object] = {
            "justify": "right" if index in _RIGHT_ALIGNED else "left",
            "no_wrap": True,
            "overflow": "fold",
        }
        if index == 0:
            kwargs["min_width"] = 12
        table.add_column(name, **kwargs)
    for row in rows:
        table.add_row(*row)

    def make_console(width: int) -> Console:
        return Console(
            file=StringIO(), width=width, highlight=False, color_system=None,
            legacy_windows=False, force_terminal=False,
        )

    # A hardcoded width silently folded/dropped the trailing columns (finds,
    # wave, cd, gates, flags) whenever a legal long engagement id blew past
    # it. Measure the table's natural width with one probe render and size
    # the real console to fit it (120 stays the floor for short content).
    probe = make_console(10_000)
    probe.print(table)
    natural = max((len(line) for line in probe.file.getvalue().splitlines()),
                  default=0)
    console = make_console(max(120, natural + 1))
    console.print(Group(Text(header, style="bold"), table,
                        *(Text(note) for note in notes)))
    return console.file.getvalue()
