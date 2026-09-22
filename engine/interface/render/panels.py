"""Pure panel renderers: snapshot dataclasses -> Rich renderables.

Every function here is a plain ``snapshot -> renderable`` mapping with no
Textual import and no I/O, so the same renderables feed the Textual app, a
future Rich-Live ``motoko watch`` tier and one-shot ``motoko status`` output
(DESIGN section 0). Widgets in ``app.py`` call these on their refresh
multiplier and push the result into Static/RichLog.

Panels render *counts and shapes*, never target content (P5): the snapshot
contract guarantees upstream redaction, and nothing here widens it.

Only snapshot fields are read — where the DESIGN wants data the frozen
contract does not carry (lane saturation, token burn), the gap is rendered
as an explicit "no data" note (P6: never fake freshness) rather than
invented. Canary trips and the stuck_testing age joined the contract with
``canary_tripped``/``stuck_testing_s``; the L flag remains an honest gap.
"""

from __future__ import annotations

import time

from rich.console import Group
from rich.table import Table
from rich.text import Text

from interface.render.theme import Theme, letter_flags
from interface.snapshot import (
    STUCK_AFTER_S,
    EngagementSnapshot,
    Event,
    InterfaceSnapshot,
)

# Block glyphs for bars, with ASCII fallback ladder (DESIGN section 7).
BAR_FILL = "█"
BAR_EMPTY = "░"

EVENT_KIND_STYLES: tuple[tuple[str, str], ...] = (
    ("opsec", "feed.kind_opsec"),
    ("waf", "feed.kind_opsec"),
    ("rule", "feed.kind_rule"),
    ("ui.", "feed.kind_rule"),
    ("entity", "feed.kind_entity"),
    ("finding", "feed.kind_entity"),
    ("edge", "feed.kind_entity"),
    ("act", "feed.kind_act"),
    ("scan", "feed.kind_act"),
)

#: Overview cells are short; drill-down keeps the contract state names.
_FUNNEL_SHORT = {
    "candidate": "cand",
    "triaged": "triaged",
    "reproduced": "repro",
    "verified": "verified",
    "exploitable": "exploit",
    "confirmed_impact": "confirm",
    "false_positive": "fp",
    "duplicate": "dup",
    "out_of_scope": "oos",
    "wont_test": "wont",
}

_FUNNEL_TOKEN = {
    "candidate": "funnel.bar",
    "triaged": "funnel.bar",
    "reproduced": "state.info",
    "verified": "state.info",
    "exploitable": "state.ok",
    "confirmed_impact": "state.ok",
    "false_positive": "text.muted",
    "duplicate": "text.muted",
    "out_of_scope": "text.muted",
    "wont_test": "text.muted",
}

#: Column model for the ENGAGEMENTS panel; shared by the Textual DataTable in
#: app.py (stable row keys + update_cell) and by pure-Rich consumers.
ENGAGEMENT_COLUMNS: tuple[tuple[str, str], ...] = (
    # (column key, header label)
    ("id", "id"),
    ("state", "state"),
    ("live", "live"),
    ("hyps", "hyps"),
    ("finds", "finds"),
    ("flags", "flags"),
)

def bar(ratio: float, width: int, theme: Theme, *, token: str = "funnel.bar") -> Text:
    """A fixed-width block bar with ASCII fallback semantics (P4/gradients off).

    ``ratio`` is clamped to 0..1; a negative or non-finite ratio renders empty.
    """
    try:
        clamped = max(0.0, min(1.0, float(ratio)))
    except (TypeError, ValueError):
        clamped = 0.0
    filled = round(clamped * width)
    out = Text()
    if filled:
        out.append(BAR_FILL * filled, style=theme.style(token))
    rest = width - filled
    if rest > 0:
        out.append(BAR_EMPTY * rest, style=theme.style("progress.back"))
    return out


def fmt_duration(seconds: float | None) -> str:
    """Humanize a duration: ``41m``, ``2m31s``, ``18s``; ``?`` when unknown."""
    if seconds is None or seconds < 0:
        return "?"
    total = int(seconds)
    if total >= 3600:
        return f"{total // 3600}h{(total % 3600) // 60:02d}m"
    if total >= 60:
        return f"{total // 60}m{total % 60:02d}s"
    return f"{total}s"


def fmt_count(count: int | None) -> str:
    """Counts render as digits or an em-dash when unknown (never ``0`` lies)."""
    return "—" if count is None else str(count)


def fmt_clock(ts: str) -> str:
    """HH:MM:SS from an ISO-ish timestamp; otherwise the original string.

    Activity lines are scanned by clock time (DESIGN section 3.1). Full
    ISO stamps stay on the snapshot; only the display is shortened.
    """
    if not ts:
        return ts
    t_at = ts.find("T")
    if t_at >= 0:
        clock = ts[t_at + 1: t_at + 9]
        if len(clock) == 8 and clock[2] == ":" and clock[5] == ":":
            return clock
    if len(ts) >= 8 and ts[2] == ":" and ts[5] == ":":
        return ts[:8]
    return ts


def empty_note(message: str, theme: Theme) -> Text:
    """Muted one-line empty / loading / unavailable copy (P6: never fake data)."""
    return Text(message, style=theme.style("text.muted"))


def derive_flags(eng: EngagementSnapshot, *, paused: bool = False) -> dict[str, bool]:
    """Letter flags derivable from the frozen snapshot contract.

    ``C`` (cooldown) and ``W`` (WAF aware, reason=detected) come from
    ``cooldowns``; ``M`` is the UI-level manual-pause latch; ``S`` lights when
    the snapshot-carried stuck_testing age exceeds ``STUCK_AFTER_S`` (a strix
    deep-dive legitimately holds testing up to 7200s — research/04) and ``K``
    when an ``opsec_canary_skip`` event was observed (engine writes exactly
    that kind for every canary trip, verified in core/orchestrator.py).

    ``L`` (egress lane saturation) remains a documented gap: today's data
    sources carry no per-lane budget/observation pair, so it is never faked
    (P6; DESIGN section 11).
    """
    return {
        "C": bool(eng.cooldowns),
        "K": bool(eng.canary_tripped),
        "L": False,  # egress lane saturation is not observable yet (P6 gap)
        "M": bool(paused),
        "S": (eng.stuck_testing_s is not None
              and eng.stuck_testing_s > STUCK_AFTER_S),
        "W": any(c.reason == "detected" for c in eng.cooldowns),
    }


def engagement_row_cells(eng: EngagementSnapshot, theme: Theme) -> tuple[Text, ...]:
    """One ENGAGEMENTS table row (aligned with :data:`ENGAGEMENT_COLUMNS`)."""
    if eng.live:
        state = Text("active", style=theme.style("state.info"))
        dot = Text("●", style=theme.style("live.dot"))
    elif eng.sealed:
        state = Text("sealed", style=theme.style("text.muted"))
        dot = Text("○", style=theme.style("sealed.dot"))
    else:
        state = Text("idle", style=theme.style("text.muted"))
        dot = Text("○", style=theme.style("sealed.dot"))
    hyps = sum(eng.hyps.values()) if eng.hyps else 0
    finds = sum(eng.findings.values()) if eng.findings else 0
    if eng.stale:
        state = Text(f"{state.plain} ▲ stale", style=theme.style("state.warn"))
    return (
        Text(eng.id, style=theme.style("text.primary")),
        state,
        dot,
        Text(f"{hyps:>4}", style=theme.style("text.primary")),
        Text(f"{finds:>4}", style=theme.style("text.primary")),
        letter_flags(derive_flags(eng), theme),
    )


def topbar(snapshot: InterfaceSnapshot | None, theme: Theme, *, theme_name: str,
           watched: str | None, uptime_s: float) -> Text:
    """The one-line header strip (DESIGN section 3.1 mockup, sanitized)."""
    stamp = Text()
    stamp.append("MOTOKO", style=f"bold {theme.style('accent')}")
    stamp.append("  ")
    stamp.append(_timestamp(), style=theme.style("text.primary"))
    if snapshot is None:
        stamp.append("  ·  hydrating…", style=theme.style("state.stale"))
    else:
        n_eng = len(snapshot.engagements)
        n_live = sum(1 for eng in snapshot.engagements if eng.live)
        stamp.append(f"  ·  {n_eng} eng", style=theme.style("text.muted"))
        if n_live:
            stamp.append(f"  {n_live} live", style=theme.style("live.dot"))
        else:
            stamp.append("  none live", style=theme.style("text.muted"))
    stamp.append(f"  ·  {theme_name}", style=theme.style("text.muted"))
    if watched:
        stamp.append("  ·  watch ", style=theme.style("text.muted"))
        stamp.append(watched, style=theme.style("accent"))
    stamp.append(f"  ·  up {fmt_duration(uptime_s)}", style=theme.style("text.muted"))
    if snapshot is not None and snapshot.collector_error:
        stamp.append("  ·  COLLECTOR ERROR", style=f"bold {theme.style('state.crit')}")
    return stamp


def _timestamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def run_progress_header(eng: EngagementSnapshot | None, theme: Theme) -> Text:
    """One-line drill-down header: ``ENGAGEMENT <id> ─ live ● ─ runner …``."""
    if eng is None:
        return Text("ENGAGEMENT — select one via enter in ENGAGEMENTS or : engagement <id>",
                    style=theme.style("text.muted"))
    line = Text()
    line.append("ENGAGEMENT ", style=f"bold {theme.style('panel.title')}")
    line.append(eng.id, style=f"bold {theme.style('text.primary')}")
    if eng.live:
        line.append("  ─  live ●", style=theme.style("live.dot"))
    elif eng.sealed:
        line.append("  ─  sealed ○", style=theme.style("sealed.dot"))
    else:
        line.append("  ─  idle ○", style=theme.style("sealed.dot"))
    line.append("  ─  runner ", style=theme.style("text.muted"))
    if eng.runner_alive:
        line.append("alive", style=theme.style("state.ok"))
    else:
        line.append("not running", style=theme.style("text.muted"))
    if eng.stale:
        line.append("  ─  ▲ stale", style=theme.style("state.warn"))
    if eng.heartbeat_age_s is not None:
        line.append(f"  ─  heartbeat {fmt_duration(eng.heartbeat_age_s)} old",
                    style=theme.style("text.muted"))
    return line


def run_progress(eng: EngagementSnapshot | None, theme: Theme) -> Group:
    """RUN PROGRESS panel body (multiplier x1): wave bar, tools, rates, ETA."""
    if eng is None:
        return Group(empty_note("no engagements", theme))
    lines: list[Text] = []
    header = Text()
    if eng.live:
        header.append("● live", style=f"bold {theme.style('live.dot')}")
    elif eng.sealed:
        header.append("○ sealed", style=theme.style("sealed.dot"))
    else:
        header.append("○ idle", style=theme.style("text.muted"))
    header.append(f"  {eng.id}", style=theme.style("text.primary"))
    if eng.heartbeat_age_s is not None:
        header.append(f"  hb {fmt_duration(eng.heartbeat_age_s)}",
                      style=theme.style("text.muted"))
    if eng.runner_alive:
        header.append("  runner alive", style=theme.style("state.ok"))
    else:
        header.append("  runner down", style=theme.style("text.muted"))
    if eng.stale:
        header.append("  ▲ stale", style=theme.style("state.warn"))
    lines.append(header)
    wave = eng.wave
    if wave is None:
        lines.append(empty_note("no wave data", theme))
    else:
        total = max(1, wave.total)
        ratio = wave.current / total
        complete = wave.current >= wave.total and wave.total > 0
        fill = "state.ok" if complete else "progress.fill"
        line = Text()
        line.append(f"wave {wave.current}/{wave.total} ")
        line.append_text(bar(ratio, 18, theme, token=fill))
        pct = round(min(1.0, max(0.0, ratio)) * 100)
        line.append(f"  {pct}%",
                    style=theme.style("state.ok" if complete else "text.primary"))
        if complete:
            line.append("  done", style=f"bold {theme.style('state.ok')}")
        elif wave.eta_s is not None:
            line.append(f"  ~{fmt_duration(wave.eta_s)} eta",
                        style=theme.style("text.muted"))
        else:
            line.append("  eta —", style=theme.style("text.muted"))
        lines.append(line)
        line2 = Text()
        line2.append(f"tools {wave.tools_done}/{wave.tools_total}")
        findings_style = "state.ok" if wave.findings_new else "text.muted"
        line2.append(f"   findings +{wave.findings_new}",
                     style=theme.style(findings_style))
        n_cd = len(eng.cooldowns)
        if n_cd:
            n429 = sum(1 for cooldown in eng.cooldowns if cooldown.reason == "429")
            line2.append(f"   cd {n_cd}", style=theme.style("opsec.cooldown"))
            if n429:
                line2.append(f"  429:{n429}", style=theme.style("opsec.cooldown"))
        lines.append(line2)
    if eng.heartbeat_msg:
        lines.append(Text(eng.heartbeat_msg, style=theme.style("text.muted")))
    return Group(*lines)


def event_line(event: Event, theme: Theme) -> Text:
    """One ACTIVITY FEED line: ``HH:MM:SS kind summary`` with kind-class color.

    Unknown kinds render in their own name (never collapsed to "other" —
    the DESIGN feeds the panel from ro-SQLite for exactly this reason).
    """
    line = Text()
    line.append(f"{fmt_clock(event.ts)}  ", style=theme.style("feed.ts"))
    kind_style = theme.style("text.primary")
    for prefix, token in EVENT_KIND_STYLES:
        if event.kind.startswith(prefix):
            kind_style = theme.style(token)
            break
    line.append(f"{event.kind:<22} ", style=kind_style)
    line.append(event.summary, style=theme.style("text.primary"))
    return line


def hypotheses(eng: EngagementSnapshot, theme: Theme, *, compact: bool = False) -> Group:
    """HYPOTHESES panel body (x2): per-state counts + mini bars.

    ``compact=True`` uses a two-column count grid so the overview cell stays
    readable at 80×24; the drill-down keeps the per-state bars.
    """
    total = max(1, sum(eng.hyps.values()))
    note = Text()
    if eng.hyps.get("testing"):
        note.append("testing held ", style=theme.style("text.muted"))
        note.append(f"{eng.hyps['testing']}", style=theme.style("accent"))
        if eng.stuck_testing_s is not None:
            stuck = eng.stuck_testing_s > STUCK_AFTER_S
            note.append(" · oldest ", style=theme.style("text.muted"))
            note.append(fmt_duration(eng.stuck_testing_s),
                        style=theme.style("state.warn" if stuck else "accent"))
        else:
            note.append(" · S n/a", style=theme.style("text.muted"))
    else:
        note.append("no open testing", style=theme.style("text.muted"))
    states = ("proposed", "testing", "done", "rejected")
    if compact:
        rows = Table.grid(padding=(0, 1))
        rows.add_column()
        rows.add_column(justify="right")
        rows.add_column()
        rows.add_column(justify="right")
        cells = []
        for state in states:
            count = eng.hyps.get(state, 0)
            style = theme.style("accent") if state == "testing" else theme.style("text.primary")
            cells.append(Text(state, style=theme.style("text.muted")))
            cells.append(Text(str(count), style=style))
        rows.add_row(*cells[:4])
        rows.add_row(*cells[4:])
        return Group(rows, note)
    rows = Table.grid(padding=(0, 2))
    rows.add_column()
    rows.add_column(justify="right")
    rows.add_column()
    for state in states:
        count = eng.hyps.get(state, 0)
        style = theme.style("accent") if state == "testing" else theme.style("text.primary")
        rows.add_row(
            Text(state, style=theme.style("text.muted")),
            Text(str(count), style=style),
            bar(count / total, 10, theme),
        )
    return Group(rows, note)


def finding_funnel(eng: EngagementSnapshot, theme: Theme, *, compact: bool = False) -> Group:
    """FINDING FUNNEL panel body (x2): the 10-state finding machine.

    ``compact=True`` is a two-column count grid for the overview cell; the
    drill-down keeps one bar per state.
    """
    from interface.snapshot import FINDING_STATES

    order = list(FINDING_STATES)
    total = max(1, sum(eng.findings.get(state, 0) for state in order))
    if compact:
        rows = Table.grid(padding=(0, 1))
        rows.add_column()
        rows.add_column(justify="right")
        rows.add_column()
        rows.add_column(justify="right")
        for index in range(0, len(order), 2):
            left = order[index]
            right = order[index + 1] if index + 1 < len(order) else None
            left_count = eng.findings.get(left, 0)
            cells = [
                Text(_FUNNEL_SHORT.get(left, left), style=theme.style("text.muted")),
                Text(str(left_count), style=theme.style(_FUNNEL_TOKEN.get(left, "text.primary"))),
            ]
            if right is not None:
                right_count = eng.findings.get(right, 0)
                cells.extend([
                    Text(_FUNNEL_SHORT.get(right, right), style=theme.style("text.muted")),
                    Text(str(right_count),
                         style=theme.style(_FUNNEL_TOKEN.get(right, "text.primary"))),
                ])
            rows.add_row(*cells)
        return Group(rows)
    rows = Table.grid(padding=(0, 2))
    rows.add_column()
    rows.add_column(justify="right")
    rows.add_column()
    for state in order:
        count = eng.findings.get(state, 0)
        token = _FUNNEL_TOKEN.get(state, "funnel.bar")
        rows.add_row(
            Text(state, style=theme.style("text.muted")),
            Text(str(count), style=theme.style("text.primary")),
            bar(count / total, 10, theme, token=token),
        )
    return Group(rows)


def legs_panel(eng: EngagementSnapshot, theme: Theme, *, compact: bool = False) -> Group:
    """TOKENS + LLM LEGS panel body (x5): leg status dots + verdicts.

    ``compact=True`` drops the round number so one leg fits on one line in
    the narrow overview cell; the drill-down ("loop rounds") shows it all.

    Token burn renders as an explicit gap note: the engine has no token
    instrumentation yet (DESIGN section 11.1) — showing a made-up number
    would violate P6.
    """
    lines: list[Text] = []
    note = empty_note(
        "token burn: n/a (no engine counters)" if compact
        else "token burn: no engine instrumentation (estimated n/a)",
        theme,
    )
    if not eng.legs:
        lines.append(empty_note("no loop legs observed", theme))
    dot_for = {"ok": "state.ok", "busy": "state.busy", "idle": "state.idle",
               "error": "state.crit"}
    for leg in eng.legs:
        line = Text()
        dot_style = theme.style(dot_for.get(leg.state, "state.idle"))
        name = leg.name[:10] if compact else leg.name
        width = 10 if compact else 12
        line.append(f"{name:<{width}} ", style=theme.style("text.primary"))
        line.append("● ", style=dot_style)
        line.append(f"{leg.state:<5}" if compact else f"{leg.state:<6}",
                    style=dot_style)
        if not compact and leg.last_round is not None:
            line.append(f" r{leg.last_round}", style=theme.style("text.muted"))
        if leg.verdict:
            verdict_style = ("state.ok" if leg.verdict == "CONTINUE"
                             else "state.warn" if leg.verdict == "ROLLBACK"
                             else "state.crit")
            line.append(f" {leg.verdict}", style=theme.style(verdict_style))
        lines.append(line)
    return Group(note, *lines)


def gates_panel(eng: EngagementSnapshot, theme: Theme) -> Group:
    """GATES panel body (x15): doctor sections + rules ratchet counts."""
    gates = eng.gates
    if gates is None:
        return Group(empty_note("adapter unavailable", theme))
    line = Text()
    line.append("doctor ", style=theme.style("text.muted"))
    if not gates.doctor_available:
        line.append("unavailable", style=theme.style("state.warn"))
    else:
        ok_all = gates.sections_ok == gates.sections_total
        badge_style = theme.style("state.ok" if ok_all else "state.warn")
        line.append(f"{gates.sections_ok}/{gates.sections_total}",
                    style=f"bold {badge_style}")
        line.append(" OK" if ok_all else " ATTENTION", style=badge_style)
    line2 = Text()
    line2.append("rules  ", style=theme.style("text.muted"))
    line2.append(f"never-fires {gates.rules_never_fires}", style=theme.style("text.primary"))
    high_style = theme.style("state.crit" if gates.rules_high else "text.primary")
    line2.append(f"  HIGH {gates.rules_high}", style=high_style)
    return Group(line, line2)


def cooldowns_panel(eng: EngagementSnapshot | None, theme: Theme) -> Group:
    """COOLDOWNS drill-down body (x2): countdown bars per masked origin."""
    if eng is None:
        return Group(empty_note("no engagements", theme))
    if not eng.cooldowns:
        return Group(empty_note("no active cooldowns", theme))
    longest = max((c.remaining_s for c in eng.cooldowns), default=1) or 1
    lines: list[Text] = []
    for cd in eng.cooldowns:
        line = Text()
        line.append(f"{cd.origin:<18}", style=theme.style("text.primary"))
        line.append_text(bar(cd.remaining_s / longest, 16, theme,
                             token="opsec.cooldown"))
        line.append(f" {fmt_duration(cd.remaining_s)} left", style=theme.style("text.primary"))
        reason_style = theme.style("opsec.canary" if cd.reason == "detected"
                                   else "opsec.cooldown")
        line.append(f"  ({cd.reason})", style=reason_style)
        lines.append(line)
    return Group(*lines)


def detail_section(section: str, eng: EngagementSnapshot | None, theme: Theme) -> Group:
    """ENGAGEMENT drill-down detail body for one sidebar section (x2)."""
    if eng is None:
        return Group(empty_note("no data yet", theme))
    if section == "overview":
        return run_progress(eng, theme)
    if section == "hypotheses":
        return hypotheses(eng, theme)
    if section == "findings":
        return finding_funnel(eng, theme)
    if section in ("queue/inflight", "tool runs"):
        return _tool_runs(eng, theme)
    if section == "cooldowns":
        return cooldowns_panel(eng, theme)
    if section == "loop rounds":
        return legs_panel(eng, theme)
    if section == "waves/rounds":
        return _waves(eng, theme)
    if section == "evidence/obs":
        return Group(empty_note(
            "Raw evidence stays on the engine host; MOTOKO displays redacted summaries.",
            theme,
        ))
    return Group(Text(f"unknown section {section!r}", style=theme.style("state.warn")))


def _tool_runs(eng: EngagementSnapshot, theme: Theme) -> Group:
    if not eng.inflight:
        return Group(empty_note("no tool runs in flight", theme))
    rows = Table.grid(padding=(0, 2))
    rows.add_column(justify="right")
    rows.add_column()
    rows.add_column(justify="right")
    rows.add_column()
    for run in eng.inflight:
        if isinstance(run.hypothesis_id, int):
            hyp = f"#{run.hypothesis_id}"
        else:
            hyp = run.hypothesis_id or "—"
        state_style = ("state.busy" if run.state in ("running", "inflight")
                       else "text.primary")
        rows.add_row(
            Text(run.tool, style=theme.style("text.primary")),
            Text(hyp, style=theme.style("text.muted")),
            Text(run.state, style=theme.style(state_style)),
            Text(fmt_duration(run.duration_s), style=theme.style("text.muted")),
        )
    return Group(rows)


def _waves(eng: EngagementSnapshot, theme: Theme) -> Group:
    if eng.wave is None:
        return Group(empty_note("no wave data", theme))
    wave = eng.wave
    complete = wave.current >= wave.total and wave.total > 0
    line = Text()
    line.append(f"wave {wave.current}/{wave.total}  ")
    line.append_text(bar(wave.current / max(1, wave.total), 30, theme,
                         token="state.ok" if complete else "funnel.bar"))
    line.append(f"  tools {wave.tools_done}/{wave.tools_total}")
    if complete:
        line.append("  done", style=f"bold {theme.style('state.ok')}")
    return Group(line)


def report_body(kind: str, snapshot: InterfaceSnapshot | None, theme: Theme,
                arg: str | None = None) -> Group:
    """REPORTS screen body for ``:doctor`` / ``:rules`` / ``:digest <id>``.

    When ``snapshot.reports`` carries the requested text — keys ``doctor``,
    ``rules``, ``digest:<id>`` — it is rendered as a plain scrollable block
    with a provenance line; the text is collected upstream on the GATES x15
    lane, already redacted and size-capped (collectors/__init__.py). The
    panel never re-redacts: the snapshot contract guarantees it (P5).

    Without adapter text the earlier stub rendering applies unchanged:
    gate summaries and an honest "content source not wired" note (fail-closed
    degradation, P6). The GATES panel keeps its summary counts — only this
    screen shows full report text.
    """
    if snapshot is not None and snapshot.reports:
        text = _adapter_report_text(snapshot, kind, arg)
        if text is not None:
            provenance = Text(
                # fmt_duration renders "?" when the age is unknown (None).
                f"source: motoko adapter, {fmt_duration(snapshot.reports_age_s)} old",
                style=theme.style("text.muted"),
            )
            return Group(provenance, Text(), Text(text))
    stub = Text(
        f"v1 stub: full :{kind} text comes from the adapter op (not wired in "
        "prototype); rendering the snapshot summary.",
        style=theme.style("text.muted"),
    )
    if snapshot is None:
        return Group(stub, Text(), Text("no data yet", style=theme.style("text.muted")))
    if kind == "doctor":
        rows = Table.grid(padding=(0, 2))
        rows.add_column()
        rows.add_column(justify="right")
        rows.add_column()
        for eng in snapshot.engagements:
            gates = eng.gates
            if gates is None:
                rows.add_row(Text(eng.id), Text("adapter unavailable",
                                                style=theme.style("text.muted")))
                continue
            if not gates.doctor_available:
                rows.add_row(
                    Text(eng.id),
                    Text("n/a", style=theme.style("text.muted")),
                    Text("DOCTOR UNAVAILABLE", style=theme.style("state.warn")),
                )
                continue
            ok = gates.sections_ok == gates.sections_total and gates.ok
            style = theme.style("state.ok" if ok else "state.crit")
            rows.add_row(
                Text(eng.id),
                Text(f"{gates.sections_ok}/{gates.sections_total}", style=style),
                Text("OK" if ok else "FAIL", style=style),
            )
        return Group(stub, Text(), rows)
    if kind == "rules":
        rows = Table.grid(padding=(0, 2))
        rows.add_column()
        rows.add_column(justify="right")
        rows.add_column(justify="right")
        rows.add_row(
            Text("engagement", style=theme.style("table.header")),
            Text("never-fires", style=theme.style("table.header")),
            Text("HIGH", style=theme.style("table.header")),
        )
        for eng in snapshot.engagements:
            gates = eng.gates
            never = gates.rules_never_fires if gates else None
            high = gates.rules_high if gates else None
            rows.add_row(
                Text(eng.id),
                Text(fmt_count(never)),
                Text(fmt_count(high), style=theme.style(
                    "state.crit" if high else "text.primary")),
            )
        return Group(stub, Text(), rows)
    if kind == "digest":
        eng = _by_id(snapshot, arg) if arg else None
        if arg and eng is None:
            return Group(stub, Text(),
                         Text(f"unknown engagement {arg!r}", style=theme.style("state.warn")))
        body = Group(
            run_progress(eng or (snapshot.engagements[0] if snapshot.engagements else None),
                         theme),
            Text(),
            hypotheses(eng, theme) if eng else Text(""),
        )
        return Group(stub, Text(), body)
    return Group(stub, Text(), Text(f"unknown report {kind!r}", style=theme.style("state.warn")))


def _adapter_report_text(snapshot: InterfaceSnapshot, kind: str,
                         arg: str | None) -> str | None:
    """Resolve the requested report kind from the snapshot's reports mapping.

    ``digest`` without an argument resolves to the digest the collector
    actually fetched (the live-or-first engagement's ``digest:<id>`` key);
    with an argument only that engagement's text matches, so an unfetched
    digest honestly falls back to the stub instead of showing another
    engagement's report.
    """
    reports = snapshot.reports
    if kind == "digest":
        if arg:
            return reports.get(f"digest:{arg}")
        for key in sorted(reports):
            if key.startswith("digest:"):
                return reports[key]
        return None
    return reports.get(kind)


def _by_id(snapshot: InterfaceSnapshot, eng_id: str) -> EngagementSnapshot | None:
    for eng in snapshot.engagements:
        if eng.id == eng_id:
            return eng
    return None


def pick_engagement(snapshot: InterfaceSnapshot | None,
                    watched: str | None) -> EngagementSnapshot | None:
    """Which engagement the RUN PROGRESS / FEED panels follow right now."""
    if snapshot is None or not snapshot.engagements:
        return None
    if watched:
        for eng in snapshot.engagements:
            if eng.id == watched:
                return eng
    for eng in snapshot.engagements:
        if eng.live:
            return eng
    return snapshot.engagements[0]
