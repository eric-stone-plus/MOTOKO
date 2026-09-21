"""The MOTOKO interface — Textual application (design/DESIGN.md sections 3, 5, 6).

Three screens plus overlays:

- OVERVIEW (default, box-grid): ENGAGEMENTS table, RUN PROGRESS, ACTIVITY
  FEED, HYPOTHESES / FINDING FUNNEL / TOKENS+LEGS / GATES small panels.
- ENGAGEMENT drill-down (sidebar + detail, lazydocker-style), sections
  reachable with ``1``-``9``.
- REPORTS (``:doctor`` / ``:rules`` / ``:digest <id>``) full-screen summary.

Overlays: ``?`` help generated from the live keymap, ``⌃P`` command palette
(Textual built-in + our provider, recently used commands first), k9s-style
``:`` command bar, the ``v`` event-log modal (section 4 #3 feed raw lines)
and the structured confirm dialog (section 5.3) for write actions.

OVERVIEW table verbs (section 5.1): ``/`` regex filter, ``n``/``N`` match
navigation, ``f`` follow-mode (the selection rides its row across refreshes,
sorts and filter changes) and ``c`` copy-masked-summary.

Refresh discipline (section 6): one global 1s tick via :meth:`App.set_interval`;
panels re-render on multipliers (feed/progress x1, tables x2, tokens x5,
gates x15). Snapshot frames arrive from a thread worker through
``call_from_thread`` — the render loop is never blocked. STALE semantics:
data age > 3x multiplier -> yellow border; > 10x -> red border + STALE badge;
collector error -> banner + terminal bell once.

All write actions (:pause/:resume, reveal) are v1 stubs: they show the
structured confirm dialog and, on confirm, only echo an audit line into the
activity feed (P7). The real engine wiring is post-prototype.
"""

from __future__ import annotations

import re
import time
from collections import deque
from datetime import datetime
from typing import Protocol

from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.coordinate import Coordinate
from textual.css.query import NoMatches
from textual.screen import ModalScreen, Screen
from textual.widget import Widget
from textual.widgets import Button, DataTable, Footer, Input, OptionList, RichLog, Static
from textual.widgets.data_table import CellDoesNotExist, ColumnKey, RowDoesNotExist
from textual.worker import Worker

from interface.render import panels
from interface.render.theme import (
    Theme,
    get_builtin_theme,
    letter_flags,
    load_theme_file,
)
from interface.snapshot import EngagementSnapshot, Event, InterfaceSnapshot


def _sort_order_key(key: str):
    """Snapshot-side sort key for an ENGAGEMENTS column (Text is unorderable)."""
    return {
        "id": lambda e: e.id,
        "hyps": lambda e: sum(e.hyps.values()) if e.hyps else 0,
        "finds": lambda e: sum(e.findings.values()) if e.findings else 0,
    }[key]


#: The data-layer boundary: the app knows nothing about collectors.
class SnapshotProvider(Protocol):
    """Anything callable that returns one consistent snapshot frame."""

    def __call__(self) -> InterfaceSnapshot: ...


TICK_S = 1.0
FEED_LIMIT = 2000
#: Per-panel refresh multipliers on the global 1s tick (DESIGN section 6).
PANEL_MULTIPLIERS: dict[str, int] = {
    "engagements": 2,
    "feed": 1,
    "progress": 1,
    "hyp": 2,
    "funnel": 2,
    "legs": 5,
    "gates": 15,
}
PANEL_TITLES: dict[str, str] = {
    "engagements": "ENGAGEMENTS",
    "feed": "ACTIVITY FEED",
    "progress": "RUN PROGRESS",
    "hyp": "HYPOTHESES",
    "funnel": "FINDING FUNNEL",
    "legs": "TOKENS + LLM LEGS",
    "gates": "GATES",
}
STALE_WARN_X = 3  # age > 3x multiplier -> yellow border
STALE_CRIT_X = 10  # age > 10x multiplier -> red border + STALE badge
CONFIRM_TIMEOUT_S = 30.0  # section 5.3: timeout = safe side = no action
RECENT_COMMANDS_MAX = 8
RECENT_SCORE_BOOST = 0.05
#: ``:`` commands that run without an argument (recents bookkeeping).
_ARGLESS_COMMANDS = frozenset(
    {"doctor", "rules", "pause", "resume", "help", "overview"}
)


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------


class InterfaceScreen(Screen):
    """Base for main screens: hosts the ``:`` command bar and ``?`` help."""

    BINDINGS = [
        Binding("colon", "command_bar", "Command", show=False),
        Binding("question_mark", "app.help_overlay", "Help", show=False),
        Binding("escape", "escape_or_close", show=False),
    ]

    #: selector of the widget to (re)focus when overlays close
    body_focus: str = "#detail"

    def __init__(self) -> None:
        super().__init__()
        self._bar_focus: Widget | None = None

    def command_bar(self) -> Input:
        """The screen's command bar input."""
        return self.query_one("#command-bar", Input)

    def compose_command_bar(self) -> ComposeResult:
        yield Input(
            id="command-bar",
            placeholder=(
                ": doctor | rules | digest <id> | engagement <id> | watch <id>"
                " | pause | resume | theme <name> | help   (enter run · esc close)"
            ),
        )

    def focus_body(self) -> None:
        """Focus the screen's primary widget (kept across overlay close)."""
        previous, self._bar_focus = self._bar_focus, None
        if previous is not None and previous.is_mounted and previous.focusable:
            previous.focus()
            return
        try:
            self.query_one(self.body_focus).focus()
        except NoMatches:
            pass

    def action_command_bar(self) -> None:
        self.open_bar(self.command_bar())

    def open_bar(self, bar: Input) -> None:
        """Show one input at a time and restore its originating pane on close."""
        if not isinstance(self.focused, Input):
            self._bar_focus = self.focused
        for other in self.query("#command-bar, #filter-bar"):
            if other is not bar:
                other.remove_class("visible")
        bar.add_class("visible")
        bar.focus()

    def action_escape_or_close(self) -> None:
        """esc closes the command bar if open, else the screen's own verb."""
        bar = self.command_bar()
        if bar.has_class("visible"):
            bar.remove_class("visible")
            bar.value = ""
            self.focus_body()
        else:
            self.handle_escape()

    def handle_escape(self) -> None:
        """Screen-specific esc verb; default is a no-op."""

    def close_command_bar(self) -> None:
        bar = self.command_bar()
        bar.remove_class("visible")
        bar.value = ""
        self.focus_body()

    @on(Input.Submitted, "#command-bar")
    def _command_submitted(self, event: Input.Submitted) -> None:
        value = event.value
        self.close_command_bar()
        self.app.run_command(value)


class OverviewScreen(InterfaceScreen):
    """DESIGN section 3.1 — the box-grid overview wall (default screen)."""

    body_focus = "#engagements"

    BINDINGS = [
        Binding("s", "sort", "Sort"),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("slash", "filter_bar", "Filter"),
        Binding("n", "match_next", "Next match", show=False),
        Binding("N", "match_previous", "Previous match", show=False),
        Binding("f", "follow_toggle", "Follow"),
        Binding("c", "copy_summary", "Copy", show=False),
        Binding("v", "event_log", "Events"),
        # Shadows the base screen's hidden escape binding (same action, so the
        # close-command-bar / close-filter chain is unchanged) purely to give
        # the footer a visible quit affordance on this screen only.
        Binding("escape", "escape_or_close", "Quit"),
    ]

    def handle_escape(self) -> None:
        """Terminal end of the esc chain: nothing open on OVERVIEW → quit
        confirm. Every other context (dialog/overlay/bar/drill-down) consumes
        esc earlier, so this can never fire mid-interaction."""
        self.app.action_confirm_quit()

    SORT_CYCLE: tuple[tuple[str, bool], ...] = (
        # (column key, reverse) — cycled by `s`
        ("id", False),
        ("hyps", True),
        ("finds", True),
    )

    def __init__(self) -> None:
        super().__init__()
        self.col_keys: dict[str, ColumnKey] = {}
        self._sort_pos = 0

    def compose(self) -> ComposeResult:
        yield Static(id="topbar")
        yield Static(id="banner")
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield DataTable(id="engagements", cursor_type="row")
                yield RichLog(id="feed", max_lines=FEED_LIMIT, markup=False,
                              wrap=False, auto_scroll=False)
            with Vertical(id="right"):
                yield Static(id="progress")
                with Horizontal(id="mid-row"):
                    yield Static(id="hyp")
                    yield Static(id="funnel")
                with Horizontal(id="bot-row"):
                    yield Static(id="legs")
                    yield Static(id="gates")
        yield from self.compose_command_bar()
        yield Input(
            id="filter-bar",
            placeholder=("/ regex — matches engagement id + letter flags"
                         "   (enter apply · empty or esc clears)"),
        )
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#engagements", DataTable)
        self.col_keys = {
            key: table.add_column(label, key=key)
            for key, label in panels.ENGAGEMENT_COLUMNS
        }
        table.focus()
        self.app._update_topbar()

    def on_screen_resume(self) -> None:
        self.app._update_topbar()
        self.app._flush_audit()

    @on(DataTable.RowSelected)
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        eng_id = event.row_key.value
        if eng_id:
            self.app.open_engagement(eng_id)

    def action_sort(self) -> None:
        """``s`` cycles the ENGAGEMENTS sort column (DESIGN section 5.1).

        Sorting happens on the snapshot side and the table is rebuilt once
        per keypress: DataTable.sort compares cell values and rich Text
        cells are not orderable. The rebuild is filter-aware (hidden rows
        stay hidden) and follow-aware (the cursor re-anchors on the followed
        row), so the selection rides its row, not its position.
        """
        key, reverse = self.SORT_CYCLE[self._sort_pos % len(self.SORT_CYCLE)]
        self._sort_pos += 1
        app: InterfaceApp = self.app
        frame = app.snapshot
        if frame is None:
            return
        app._sort_active = (key, reverse)
        ordered = sorted(app._visible_engagements(), key=_sort_order_key(key),
                         reverse=reverse)
        app._rebuild_engagements(ordered)
        app.notify(f"sort: {key}{' desc' if reverse else ''}")


    def filter_bar(self) -> Input:
        """The overview's regex filter input."""
        return self.query_one("#filter-bar", Input)

    def action_filter_bar(self) -> None:
        """``/`` — open the ENGAGEMENTS regex filter bar (DESIGN section 5.1)."""
        bar = self.filter_bar()
        bar.value = self.app._filter_text  # prefill: edit the active pattern
        self.open_bar(bar)

    def action_escape_or_close(self) -> None:
        """esc closes the filter bar (and clears the filter) before the rest."""
        bar = self.filter_bar()
        if bar.has_class("visible"):
            bar.remove_class("visible")
            bar.value = ""
            self.app.clear_filter()
            self.focus_body()
            return
        super().action_escape_or_close()

    @on(Input.Submitted, "#filter-bar")
    def _filter_submitted(self, event: Input.Submitted) -> None:
        """enter in the filter bar: apply (empty pattern = clear)."""
        self.filter_bar().remove_class("visible")
        self.focus_body()
        self.app.apply_filter(event.value.strip())


    def action_match_next(self) -> None:
        """``n`` — next row matching the active filter (wraps around)."""
        self._step_match(1)

    def action_match_previous(self) -> None:
        """``N`` — previous row matching the active filter (wraps around)."""
        self._step_match(-1)

    def _step_match(self, delta: int) -> None:
        app: InterfaceApp = self.app
        if app._filter_re is None:
            app.notify("no filter active — press / first", severity="warning")
            return
        table = self.query_one("#engagements", DataTable)
        if table.row_count == 0:
            app.notify("no rows match the filter", severity="warning")
            return
        # Every visible row matches by construction (non-matching rows are
        # hidden), so the next match is the next visible row, with wraparound.
        target = (table.cursor_coordinate.row + delta) % table.row_count
        table.move_cursor(row=target)


    def action_follow_toggle(self) -> None:
        """``f`` — follow mode: the selection rides its row across rebuilds."""
        app: InterfaceApp = self.app
        app._follow = not app._follow
        if app._follow:
            app._follow_key = app._overview_cursor_key()
            app.notify("follow on — selection rides the row")
        else:
            app._follow_key = None
            app.notify("follow off")
        app._apply_panel_titles()

    @on(DataTable.RowHighlighted)
    def _row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """While following, the latch rides cursor movement (j/k/arrows/n/N)."""
        app: InterfaceApp = self.app
        if not app._follow:
            return
        key = event.row_key.value
        if key is None:
            return
        if app._follow_key is not None and app._follow_key not in app._visible_row_keys():
            # The followed row is temporarily hidden (filter/sort rebuild):
            # keep the latch on it instead of re-latching the clamped cursor.
            return
        app._follow_key = key


    def action_copy_summary(self) -> None:
        """``c`` — copy the selected engagement's masked one-line summary."""
        app: InterfaceApp = self.app
        eng_id = app._overview_cursor_key()
        if eng_id is None:
            app.notify("no engagement selected", severity="warning")
            return
        eng = app.current_engagement(eng_id)
        if eng is None:
            app.notify(f"unknown engagement: {eng_id}", severity="error")
            return
        summary = app.masked_summary(eng)
        if hasattr(app, "copy_to_clipboard"):
            # textual>=8: OSC52 copy; the summary is built from the
            # already-redacted snapshot only (P5), so this leaks no raw data.
            app.copy_to_clipboard(summary)
            app.notify(f"copied: {summary}")
        else:  # pragma: no cover - textual>=8 always provides the API
            app.notify(summary)

    def action_cursor_down(self) -> None:
        """``j`` — vim cursor on the ENGAGEMENTS table."""
        self.query_one("#engagements", DataTable).action_cursor_down()

    def action_cursor_up(self) -> None:
        """``k`` — vim cursor on the ENGAGEMENTS table."""
        self.query_one("#engagements", DataTable).action_cursor_up()

    def action_event_log(self) -> None:
        '``v`` — event-log modal for the cursor-selected engagement.'
        app: InterfaceApp = self.app
        eng_id = app._overview_cursor_key()
        if eng_id is None:
            eng = app.current_engagement()
            eng_id = eng.id if eng is not None else None
        if eng_id is None:
            app.notify("no engagement to show", severity="warning")
            return
        app.push_screen(EventLogOverlay(eng_id))


class SectionList(OptionList):
    """Keyboard and mouse navigation with stable, bounded section selection."""

    BINDINGS = [
        Binding("up,k", "cursor_up", "Previous section", show=False),
        Binding("down,j", "cursor_down", "Next section", show=False),
        Binding("enter", "select", "Detail"),
        Binding("right", "screen.focus_detail", "Detail", show=False),
    ]

    def action_cursor_down(self) -> None:
        self.highlighted = min((self.highlighted or 0) + 1, self.option_count - 1)

    def action_cursor_up(self) -> None:
        self.highlighted = max((self.highlighted or 0) - 1, 0)


class DetailScroll(VerticalScroll):
    """Keep scrolling local to the detail pane when it holds keyboard focus."""

    BINDINGS = [
        Binding("j", "scroll_down", "Scroll down", show=False),
        Binding("k", "scroll_up", "Scroll up", show=False),
        Binding("left", "screen.focus_sidebar", "Sections"),
    ]


class EngagementScreen(InterfaceScreen):
    """DESIGN section 3.2 — sidebar + detail drill-down (lazydocker-style)."""

    body_focus = "#sidebar"
    SECTIONS: tuple[str, ...] = (
        "overview",
        "hypotheses",
        "findings",
        "queue/inflight",
        "tool runs",
        "cooldowns",
        "loop rounds",
        "waves/rounds",
        "evidence/obs",
    )

    BINDINGS = [
        Binding(str(n), f"section({n})", name.capitalize(), show=False)
        for n, name in enumerate(SECTIONS, start=1)
    ] + [
        Binding("r", "app.refresh_now", "Refresh", show=False),
        Binding("left", "focus_sidebar", "Sections"),
        Binding("right", "focus_detail", "Detail"),
        Binding("escape", "escape_or_close", "Back"),
        Binding("R", "reveal", "Reveal", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.engagement_id: str | None = None
        self.section_idx = 0

    def compose(self) -> ComposeResult:
        yield Static(id="drill-head")
        with Horizontal(id="drill"):
            yield SectionList(*(f"{n}  {name}" for n, name in enumerate(self.SECTIONS, 1)),
                              id="sidebar")
            with DetailScroll(id="detail-scroll"):
                yield Static(id="detail")
        yield from self.compose_command_bar()
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#sidebar").border_title = "SECTIONS · ↑↓ / 1–9"
        self.rerender()
        self.focus_body()

    def on_screen_resume(self) -> None:
        self.rerender()

    def set_engagement(self, eng_id: str) -> None:
        self.engagement_id = eng_id
        self.section_idx = 0
        if self.is_mounted:
            self.rerender()
            self.query_one("#detail-scroll").scroll_home(animate=False)

    def action_section(self, n: int) -> None:
        """``1``-``9`` jump straight to a sidebar section (DESIGN section 5.1)."""
        if 1 <= n <= len(self.SECTIONS):
            self.query_one("#sidebar", OptionList).highlighted = n - 1
            self.action_focus_sidebar()

    @on(OptionList.OptionHighlighted, "#sidebar")
    def _section_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        event.stop()
        if self.section_idx != event.option_index:
            self.section_idx = event.option_index
            self.rerender()
            self.query_one("#detail-scroll").scroll_home(animate=False)

    @on(OptionList.OptionSelected, "#sidebar")
    def _section_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self.action_focus_detail()

    def action_focus_sidebar(self) -> None:
        self.query_one("#sidebar").focus()

    def action_focus_detail(self) -> None:
        self.query_one("#detail-scroll").focus()

    def handle_escape(self) -> None:
        self.app.goto_screen("overview")

    def action_reveal(self) -> None:
        """``R`` — v1 stub: real reveal needs raw collector data; we only
        write the audit line the design requires (P5/P7)."""
        self.app.audit(f"ui.reveal section='{self.SECTIONS[self.section_idx]}' "
                       "engagement='" + (self.engagement_id or "?") + "' (stub)")
        self.app.notify("reveal is a v1 stub — audit line written", severity="warning")

    @property
    def section(self) -> str:
        return self.SECTIONS[self.section_idx]

    def refresh_content(self) -> None:
        """Called by the app on the x2 'tables' tick while this screen is up."""
        if self.is_mounted and self.screen is self:
            self.rerender()

    def rerender(self) -> None:
        app: InterfaceApp = self.app
        theme = app.ui_theme
        eng = app.current_engagement(self.engagement_id)
        head = self.query_one("#drill-head", Static)
        head.update(panels.run_progress_header(eng, theme))
        self.query_one("#sidebar", OptionList).highlighted = self.section_idx
        self.query_one("#detail-scroll").border_title = self.section.upper()
        detail = panels.detail_section(self.section, eng, theme)
        self.query_one("#detail", Static).update(detail)


class ReportsScreen(InterfaceScreen):
    """DESIGN section 3.3 — full-screen report (doctor / rules / digest)."""

    body_focus = "#report-scroll"
    BINDINGS = [
        Binding("r", "force_refresh", "Refresh"),
        Binding("q", "back", "Back", show=False),
        Binding("escape", "escape_or_close", "Back"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.kind: str = "doctor"
        self.arg: str | None = None

    def compose(self) -> ComposeResult:
        yield Static(id="report-head")
        with VerticalScroll(id="report-scroll"):
            yield Static(id="report-body")
        yield from self.compose_command_bar()
        yield Footer()

    def on_mount(self) -> None:
        self.rerender()

    def on_screen_resume(self) -> None:
        self.rerender()

    def set_report(self, kind: str, arg: str | None) -> None:
        self.kind, self.arg = kind, arg
        if self.is_mounted:
            self.rerender()

    def refresh_content(self) -> None:
        """Called by the app on the x15 'gates' tick while this screen is up."""
        if self.is_mounted and self.screen is self:
            self.rerender()

    def handle_escape(self) -> None:
        self.action_back()

    def action_back(self) -> None:
        self.app.goto_screen("overview")

    def action_force_refresh(self) -> None:
        self.app.action_refresh_now()
        self.rerender()

    def rerender(self) -> None:
        app: InterfaceApp = self.app
        theme = app.ui_theme
        head = Text()
        head.append(f"REPORT — :{self.kind}", style=f"bold {theme.style('panel.title')}")
        if self.arg:
            head.append(f" {self.arg}", style=theme.style("accent"))
        head.append("   (esc/q back · r force refresh)", style=theme.style("text.muted"))
        self.query_one("#report-head", Static).update(head)
        body = panels.report_body(self.kind, app.snapshot, theme, self.arg)
        self.query_one("#report-body", Static).update(body)


class HelpOverlay(ModalScreen):
    """``?`` overlay — generated from the *live* keymap (k9s pattern)."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("question_mark", "dismiss", show=False),
    ]

    def __init__(self, source: Screen) -> None:
        super().__init__()
        self._source = source

    def compose(self) -> ComposeResult:
        with Vertical(id="help-box"):
            yield Static("KEYBINDINGS — generated from the live keymap",
                         id="help-title")
            yield VerticalScroll(Static(self._build_table(), id="help-table"))
            yield Static("esc close · overlays: ? help  ⌃P palette  : command", id="help-foot")

    def _build_table(self) -> Table:
        theme: Theme = self.app.ui_theme
        table = Table.grid(padding=(0, 3))
        table.add_column(justify="right")
        table.add_column()
        rows: list[tuple[str, str]] = []
        try:
            active = self._source.active_bindings
        except Exception:  # pragma: no cover - defensive, keeps help usable
            active = {}
        for key, info in sorted(active.items()):
            binding = getattr(info, "binding", None)
            description = getattr(binding, "description", "") if binding else ""
            if description:
                rows.append((key, description))
        for key, description in rows:
            table.add_row(Text(key, style=theme.style("accent")),
                          Text(description, style=theme.style("text.primary")))
        return table


class EventLogOverlay(ModalScreen):
    '    One line per snapshot event, ``ts + kind + summary``: every line is the\n    already-redacted snapshot payload, so no new redaction (and no raw data\n    path) is needed here. Scrollable; esc closes.\n    '

    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, eng_id: str | None = None) -> None:
        super().__init__()
        self._eng_id = eng_id

    def compose(self) -> ComposeResult:
        with Vertical(id="eventlog-box"):
            yield Static("", id="eventlog-title")
            yield VerticalScroll(id="eventlog-scroll")
            yield Static("esc close", id="eventlog-foot")

    def on_mount(self) -> None:
        app: InterfaceApp = self.app
        theme = app.ui_theme
        eng = app.current_engagement(self._eng_id)
        tail = eng.events_tail if eng is not None else ()
        title = Text("EVENT LOG", style=f"bold {theme.style('panel.title')}")
        title.append(f" — last {len(tail)} (redacted)",
                     style=theme.style("text.muted"))
        self.query_one("#eventlog-title", Static).update(title)
        if eng is None:
            self.query_one("#eventlog-scroll", VerticalScroll).mount(
                Static(Text("no data yet", style=theme.style("text.muted")),
                       classes="eventlog-line"))
            return
        foot = Text()
        foot.append(eng.id, style=theme.style("accent"))
        foot.append("  ·  esc close", style=theme.style("text.muted"))
        self.query_one("#eventlog-foot", Static).update(foot)
        if not tail:
            self.query_one("#eventlog-scroll", VerticalScroll).mount(
                Static(Text("no events in tail", style=theme.style("text.muted")),
                       classes="eventlog-line"))
            return
        self.query_one("#eventlog-scroll", VerticalScroll).mount(
            *[Static(panels.event_line(event, theme), classes="eventlog-line")
              for event in tail])


class ConfirmButton(Button):
    """Pointer entry selects the same answer as keyboard navigation."""

    def on_enter(self) -> None:
        self.focus()


class ConfirmDialog(ModalScreen):
    """Structured confirm dialog (DESIGN section 5.3, oh-my-pi ``ask`` pattern).

    Buttons + impact text. Fail-closed: esc or
    30s of silence resolve as Cancel — never as action.

    Cancel starts selected in yellow. Keyboard and pointer selection share
    the same full-button highlight; only activation resolves the dialog.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("left", "cycle_button", "Other button"),
        Binding("right", "cycle_button", "Other button"),
    ]

    def __init__(self, title: str, impact: str) -> None:
        super().__init__()
        self._title = title
        self._impact = impact

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Static(self._title, id="confirm-title")
            yield Static(self._impact, id="confirm-impact")
            with Horizontal(id="confirm-buttons"):
                yield ConfirmButton("Cancel", id="btn-cancel")
                yield ConfirmButton("Confirm", id="btn-confirm")
            yield Static("← → choose · Enter accept · Esc cancel", id="confirm-hint")

    def on_mount(self) -> None:
        self.query_one("#btn-cancel", Button).focus()
        self.set_timer(CONFIRM_TIMEOUT_S, self.action_cancel)

    def action_cancel(self) -> None:
        if self.is_mounted:
            self.dismiss(False)

    def action_cycle_button(self) -> None:
        """Move focus to the other button, wrapping at both ends.

        Textual's own focus navigation is Tab-based, so an operator reaching for
        an arrow key — the reflex everywhere else in this UI, where the cursor
        keys and j/k drive the tables — got nothing, and clicking was the only
        way to change the answer. With two buttons left and right are the same
        move, which is what "cycle" means here.
        """
        buttons = (self.query_one("#btn-cancel", Button),
                   self.query_one("#btn-confirm", Button))
        try:
            idx = buttons.index(self.focused)
        except ValueError:
            idx = 0                  # focus is nowhere in particular: Cancel
        buttons[(idx + 1) % len(buttons)].focus()

    @on(Button.Pressed, "#btn-cancel")
    def _cancel(self) -> None:
        self.dismiss(False)

    @on(Button.Pressed, "#btn-confirm")
    def _confirm(self) -> None:
        self.dismiss(True)


# ---------------------------------------------------------------------------
# Command palette provider
# ---------------------------------------------------------------------------


class InterfaceCommandProvider(Provider):
    """Command palette provider: the same vocabulary as ``:`` command mode.

    Recently executed commands (tracked by :meth:`InterfaceApp.run_command`)
    are ordered first, most recent first; the rest keep their stable
    definition order (DESIGN section 5.2, recents-first).
    """

    def _ordered_commands(self) -> list[tuple[str, str, object]]:
        """The command table with recents floated to the top (MRU first)."""
        app: InterfaceApp = self.app  # type: ignore[assignment]
        entries = {name: (name, help_text, callback)
                   for name, help_text, callback in self.commands()}
        ordered: list[tuple[str, str, object]] = []
        for name in reversed(app._recent_commands):
            entry = entries.pop(name, None)
            if entry is not None:
                ordered.append(entry)
        ordered.extend(entries.values())
        return ordered

    def commands(self) -> list[tuple[str, str, object]]:
        app: InterfaceApp = self.app  # type: ignore[assignment]
        return [
            ("doctor", "REPORTS: doctor gate summary (v1 stub content)",
             lambda: app.run_command("doctor")),
            ("rules", "REPORTS: rules static ratchet (v1 stub content)",
             lambda: app.run_command("rules")),
            ("digest", "REPORTS: engagement digest — use : digest <id> for an id",
             lambda: app.run_command("digest")),
            ("engagement", "drill into an engagement — use : engagement <id>",
             lambda: app.run_command("engagement")),
            ("watch", "follow an engagement in RUN PROGRESS — : watch <id>",
             lambda: app.run_command("watch")),
            ("pause", "runner control (structured confirm, v1 stub)",
             lambda: app.run_command("pause")),
            ("resume", "runner control (structured confirm, v1 stub)",
             lambda: app.run_command("resume")),
            ("help", "keymap overlay", lambda: app.run_command("help")),
            ("overview", "back to the OVERVIEW screen",
             lambda: app.run_command("overview")),
        ]

    async def discover(self) -> Hits:
        for name, help_text, callback in self._ordered_commands():
            yield DiscoveryHit(name, callback, help=help_text)

    async def search(self, query: str) -> Hits:
        app: InterfaceApp = self.app  # type: ignore[assignment]
        matcher = self.matcher(query)
        recents = set(app._recent_commands)
        for name, help_text, callback in self._ordered_commands():
            score = matcher.match(name)
            if score <= 0:
                continue
            if name in recents:
                # Recents-first also inside fuzzy results: a small boost
                # lifts equal-scoring recents above the rest (section 5.2).
                score = min(1.0, score + RECENT_SCORE_BOOST)
            yield Hit(score, matcher.highlight(name), callback, help=help_text)


# ---------------------------------------------------------------------------
# The App
# ---------------------------------------------------------------------------


class InterfaceApp(App[None]):
    """The MOTOKO interface application shell."""

    TITLE = "MOTOKO"
    COMMANDS = App.COMMANDS | {InterfaceCommandProvider}

    BINDINGS = [
        Binding("r", "refresh_now", "Refresh"),
        Binding("1", "switch('overview')", "Overview"),
        Binding("2", "switch('engagement')", "Engagement"),
        Binding("3", "switch('reports')", "Reports"),
        Binding("ctrl+l", "redraw", "Redraw", show=False),
        Binding("ctrl+q", "explain_quit", show=False, priority=True),
        Binding("ctrl+c", "explain_quit", show=False, priority=True),
    ]

    def action_explain_quit(self) -> None:
        """ctrl+q / ctrl+c no longer quit — point at the esc path."""
        self.notify("quit: press esc on the OVERVIEW screen, then confirm",
                    severity="information", timeout=5)

    CSS = """
    #topbar { height: 1; padding: 0 1; color: $text; }
    #banner { display: none; height: 1; padding: 0 1; }
    #banner.visible { display: block; color: $error; }
    #body { height: 1fr; }
    #left { width: 1fr; }
    #right { width: 1fr; }
    #progress { height: 2fr; }
    #mid-row, #bot-row { height: 1fr; }
    #hyp, #funnel, #legs, #gates { width: 1fr; }
    #engagements { height: 2fr; }
    #feed { height: 1fr; }
    #engagements, #feed, #progress, #hyp, #funnel, #legs, #gates {
        border: tall $border-blurred;
        background: $panel;
    }
    .stale-warn { border: tall $warning; }
    .stale-crit { border: tall $error; }
    #command-bar { display: none; dock: bottom; border: tall $border; }
    #command-bar.visible { display: block; }
    #filter-bar { display: none; dock: bottom; border: tall $border; }
    #filter-bar.visible { display: block; }
    #eventlog-box { width: 100; height: 80%; border: tall $border;
                    background: $panel; padding: 1 2; }
    #eventlog-title { color: $text; margin-bottom: 1; }
    #eventlog-scroll { height: 1fr; }
    #eventlog-foot { color: $text-muted; padding-top: 1; }
    #drill-head { height: 1; padding: 0 1; color: $text; }
    #drill { height: 1fr; }
    #sidebar { width: 26; height: 1fr; border: tall $border-blurred; background: $panel; }
    #sidebar:focus, #detail-scroll:focus, #engagements:focus, #feed:focus {
        border: tall $accent;
    }
    #detail-scroll { width: 1fr; border: tall $border-blurred; background: $panel; }
    #detail { padding: 0 1; }
    #report-head { height: 1; padding: 0 1; }
    #report-scroll { height: 1fr; border: tall $border-blurred; background: $panel; }
    #report-body { padding: 0 1; }
    #help-box { width: 72; max-width: 95%; height: 70%; border: tall $border;
                background: $panel; padding: 1 2; }
    #help-title { color: $text; }
    #help-foot { color: $text-muted; }
    #confirm-box { width: 64; max-width: 95%; height: auto; max-height: 95%;
                   overflow-y: auto; border: tall $border;
                   background: $panel; padding: 1 2; }
    #confirm-title { text-style: bold; color: $text; margin-bottom: 1; }
    #confirm-impact { color: $text; margin-bottom: 1; }
    #confirm-buttons { height: auto; align-horizontal: center; }
    #confirm-buttons Button {
        min-width: 12; margin: 0 1; background: $panel; color: $text;
        border: tall $border-blurred; text-style: none; background-tint: transparent;
    }
    #confirm-buttons Button:focus {
        background: $warning; color: $background;
        border: tall $warning; text-style: bold;
    }
    #confirm-hint { color: $text-muted; text-align: center; margin-top: 1; }
    #eventlog-box { max-width: 95%; }
    /* ModalScreen has no alignment of its own, so every overlay was pinned to
       the top-left corner of the terminal and read as a stray panel rather
       than a dialog. Centering is one rule for all three because they share
       the defect, not three rules that can drift apart. */
    HelpOverlay, EventLogOverlay, ConfirmDialog { align: center middle; }
    Button { margin: 0 2; }
    """

    def __init__(self, provider: SnapshotProvider, ui_theme: Theme | None = None,
                 theme_name: str | None = None) -> None:
        super().__init__()
        self._provider = provider
        self._provider_worker: Worker[None] | None = None
        self.ui_theme: Theme = (
            ui_theme or get_builtin_theme("motoko-dark")  # type: ignore[arg-type]
        )
        self.theme_name = theme_name or self.ui_theme.name
        self.snapshot: InterfaceSnapshot | None = None
        self._tick = 0
        self._last_data_mono = time.monotonic()
        self._watched: str | None = None
        self._engagement_id: str | None = None
        self._feed_stream_id: str | None = None
        self._feed_events: dict[int, Event] = {}
        self._feed_audits: deque[tuple[float, int, Text]] = deque(maxlen=FEED_LIMIT)
        self._feed_serial = 0
        self._feed_dirty = False
        self._row_keys: dict[str, object] = {}
        self._started_at = time.monotonic()
        self._overview = OverviewScreen()
        self._engagement = EngagementScreen()
        self._reports = ReportsScreen()
        self._bell_on_error = True
        self._last_gates_ok: bool | None = None
        self._sort_active: tuple[str, bool] | None = None
        self._hydrated = False
        # -- OVERVIEW table verbs (DESIGN section 5.1; session-only state) --
        self._filter_re: re.Pattern[str] | None = None
        self._filter_text: str = ""  # pattern as typed, for the title hint
        self._follow: bool = False
        self._follow_key: str | None = None
        self._recent_commands: deque[str] = deque(maxlen=RECENT_COMMANDS_MAX)

    # -- lifecycle ----------------------------------------------------------

    def get_default_screen(self) -> Screen:
        """The OVERVIEW wall is the app's initial screen (DESIGN section 3.1)."""
        return self._overview

    def on_mount(self) -> None:
        self._activate_theme(self.ui_theme)
        self.install_screen(self._engagement, name="engagement")
        self.install_screen(self._reports, name="reports")
        self.set_interval(TICK_S, self._on_tick)
        self._fetch()

    def goto_screen(self, name: str) -> None:
        """Navigate between the three main screens.

        Implemented with push/pop instead of ``switch_screen``: Textual 8.2.8
        pops a result callback the *initial default* screen never received,
        so switching away from the first screen raises IndexError. Push/pop
        keeps the stack bookkeeping intact and depth stays <= 2.
        """
        targets = {
            "overview": self._overview,
            "engagement": self._engagement,
            "reports": self._reports,
        }
        if name not in targets:
            raise ValueError(f"unknown MOTOKO screen: {name!r}")
        target = targets[name]
        if self.screen is target:
            return
        self._unwind_to_base()
        if target is not self._overview:
            self.push_screen(target)

    def _unwind_to_base(self) -> None:
        while len(self._screen_stack) > 1:
            self.pop_screen()

    def _activate_theme(self, render_theme: Theme) -> None:
        """Map render tokens onto a Textual theme (widget chrome).

        Widget chrome (borders, backgrounds, stale classes) uses Textual's
        standard variables ($border-blurred, $warning, $error, $panel, ...),
        which the ColorSystem derives from the token mapping below — so
        switching themes restyles the chrome too. Panel *content* colors come
        from the render tokens directly (render.panels), never from CSS.
        """
        from textual.theme import Theme as TextualTheme

        tokens = render_theme.tokens
        ttheme = TextualTheme(
            name=f"motoko-{render_theme.name}",
            primary=tokens.get("accent", "#4a9eff"),
            secondary=tokens.get("accent.muted", "#2b5f8f"),
            success=tokens.get("state.ok", "#8fd460"),
            warning=tokens.get("state.warn", "#e8c34a"),
            error=tokens.get("state.crit", "#f05b5b"),
            accent=tokens.get("accent", "#4a9eff"),
            foreground=tokens.get("text.primary", "#d6e2ee"),
            background=tokens.get("bg", "#101418"),
            surface=tokens.get("panel.bg", "#141a20"),
            panel=tokens.get("panel.bg", "#141a20"),
            dark=True,
        )
        self.register_theme(ttheme)
        self.theme = ttheme.name

    # -- data flow (never block the render loop) ----------------------------

    def _fetch(self) -> None:
        """Start a poll only after the previous provider thread has finished."""
        if self._provider_worker is None or self._provider_worker.is_finished:
            self._provider_worker = self._collect_frame()

    @work(thread=True, group="provider")
    def _collect_frame(self) -> None:
        """Collect off-loop without cancelling or overlapping a slow poll.

        Cancelling a Textual worker cannot stop its Python thread. Scheduling
        stays on the UI thread in _fetch, leaving at most one provider active.
        """
        try:
            frame = self._provider()
        except Exception as exc:  # collector crash isolation (DESIGN section 2)
            try:
                self.call_from_thread(self._apply_error, exc)
            except Exception:
                pass  # app shut down under us
            return
        try:
            self.call_from_thread(self._apply_snapshot, frame)
        except Exception:
            if self.is_running:
                raise
            # App shut down under us; nothing left to post to.

    def _apply_snapshot(self, frame: InterfaceSnapshot) -> None:
        """Single mutation path for snapshot data (bubbletea discipline)."""
        previous_error = self.snapshot.collector_error if self.snapshot else None
        previous_ids = {eng.id for eng in self.snapshot.engagements} if self.snapshot else set()
        current_ids = {eng.id for eng in frame.engagements}
        self.snapshot = frame
        if self._watched not in current_ids:
            self._watched = None
        if self._follow_key not in current_ids:
            self._follow_key = None
        if self._engagement_id is not None and self._engagement_id not in current_ids:
            self._engagement_id = None
            self._engagement.engagement_id = None
            if self.screen is self._engagement:
                self.goto_screen("overview")
        self._last_data_mono = time.monotonic()
        if frame.collector_error:
            self._show_banner(f"COLLECTOR ERROR: {frame.collector_error}")
            if not previous_error and self._bell_on_error:
                self.bell()
        else:
            self._hide_banner()
            if previous_error and self._bell_on_error:
                self.bell()  # collector recovered: one ring (DESIGN section 6)
        self._write_new_feed_events()
        self._flush_audit()
        if not self._hydrated:
            self._hydrated = self._overview_hydrated() or not frame.engagements
        self._update_due(force=not self._hydrated or previous_ids != current_ids)
        self._apply_panel_titles()
        self._bell_on_gate_flip()

    def _overview_hydrated(self) -> bool:
        """True once the ENGAGEMENTS wall shows rows (boot hydration done)."""
        if not self._overview.is_mounted:
            return False
        try:
            table = self._overview.query_one("#engagements", DataTable)
        except NoMatches:
            return False
        return table.row_count > 0

    def _apply_error(self, exc: Exception) -> None:
        """Provider raised: keep the last frame, escalate visibility."""
        self._show_banner(f"COLLECTOR THREAD ERROR: {exc!r}")
        if self._bell_on_error:
            self.bell()

    def _bell_on_gate_flip(self) -> None:
        """One ring when the followed engagement's doctor verdict flips.

        The GATES panel only re-renders at x15, so a transition could stay
        unseen for up to 15s — the bell makes it immediate (DESIGN 3.3/7).
        """
        eng = self.current_engagement()
        gates_ok = eng.gates.ok if eng is not None and eng.gates is not None else None
        try:
            if (self._last_gates_ok is not None and gates_ok is not None
                    and gates_ok != self._last_gates_ok and self._bell_on_error):
                self.bell()
        finally:
            self._last_gates_ok = gates_ok

    def _on_tick(self) -> None:
        """Global 1s tick: fetch + multiplier-driven panel refresh + staleness."""
        self._tick += 1
        self._fetch()
        if self.snapshot is not None:
            self._update_due()
        self._apply_panel_titles()
        self._update_topbar()

    def _update_due(self, force: bool = False) -> None:
        tick = self._tick
        if force or tick % 1 == 0:  # x1
            self._update_progress()
        if force or tick % 2 == 0:  # x2
            self._update_engagements()
            self._update_small("hyp")
            self._update_small("funnel")
            self._engagement.refresh_content()
        if force or tick % 5 == 0:  # x5
            self._update_small("legs")
        if force or tick % 15 == 0:  # x15
            self._update_small("gates")
            self._reports.refresh_content()

    # -- panel updates -------------------------------------------------------

    def _overview_widget(self, selector: str):
        screen = self._overview
        if not screen.is_mounted:
            return None
        try:
            return screen.query_one(selector)
        except NoMatches:
            return None

    def current_engagement(self, eng_id: str | None = None) -> EngagementSnapshot | None:
        """The engagement a panel should render: explicit id > watched > live."""
        frame = self.snapshot
        if frame is None:
            return None
        if eng_id:
            for eng in frame.engagements:
                if eng.id == eng_id:
                    return eng
            return None
        return panels.pick_engagement(frame, self._watched)

    def _update_progress(self) -> None:
        widget = self._overview_widget("#progress")
        if widget is None:
            return
        eng = self.current_engagement()
        widget.update(panels.run_progress(eng, self.ui_theme))

    def _update_small(self, panel_id: str) -> None:
        widget = self._overview_widget(f"#{panel_id}")
        if widget is None:
            return
        eng = self.current_engagement()
        if eng is None:
            widget.update(Text("no data yet", style=self.ui_theme.style("text.muted")))
            return
        if panel_id == "hyp":
            widget.update(panels.hypotheses(eng, self.ui_theme))
        elif panel_id == "funnel":
            widget.update(panels.finding_funnel(eng, self.ui_theme))
        elif panel_id == "legs":
            widget.update(panels.legs_panel(eng, self.ui_theme, compact=True))
        elif panel_id == "gates":
            widget.update(panels.gates_panel(eng, self.ui_theme))

    def _update_engagements(self) -> None:
        """ENGAGEMENTS table with stable row keys + update_cell (no rebuild).

        Filter-aware: only engagements matching the active ``/`` regex get
        rows; rows that stopped matching are removed. Matching ids keep
        their row keys, so the ``update_cell`` stream and follow-mode keep
        working across refreshes.
        """
        table = self._overview_widget("#engagements")
        frame = self.snapshot
        if table is None or frame is None:
            return
        assert isinstance(table, DataTable)
        seen: set[str] = set()
        added_new = False
        for eng in frame.engagements:
            if not self._matches_filter(eng):
                continue
            seen.add(eng.id)
            cells = panels.engagement_row_cells(eng, self.ui_theme)
            if eng.id not in self._row_keys:
                self._row_keys[eng.id] = table.add_row(*cells, key=eng.id)
                added_new = True
                continue
            for (col_key, _label), value in zip(panels.ENGAGEMENT_COLUMNS, cells):
                table.update_cell(eng.id, self._overview.col_keys[col_key], value,
                                  update_width=True)
        for gone in [k for k in self._row_keys if k not in seen]:
            table.remove_row(self._row_keys.pop(gone))
        if added_new and self._sort_active:
            key, reverse = self._sort_active
            self._rebuild_engagements(
                sorted(self._visible_engagements(), key=_sort_order_key(key),
                       reverse=reverse))
            return
        self._apply_follow()

    # -- overview table: filter / follow / cursor (DESIGN section 5.1) ---------

    def _visible_engagements(self) -> list[EngagementSnapshot]:
        """Snapshot engagements matching the active filter, in frame order."""
        if self.snapshot is None:
            return []
        return [e for e in self.snapshot.engagements if self._matches_filter(e)]

    def _matches_filter(self, eng: EngagementSnapshot) -> bool:
        """Case-insensitive regex match on engagement id and its flag string."""
        if self._filter_re is None:
            return True
        if self._filter_re.search(eng.id):
            return True
        flags = letter_flags(panels.derive_flags(eng), self.ui_theme).plain
        return bool(self._filter_re.search(flags))

    def apply_filter(self, pattern: str) -> None:
        """Apply the ``/`` regex filter (case-insensitive) and rebuild.

        An empty pattern clears the filter; an invalid regex notifies and
        keeps the previous filter (fail-closed, P6: never pretend it worked).
        """
        if not pattern:
            self.clear_filter()
            return
        try:
            self._filter_re = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            self.notify(f"invalid filter regex — kept previous: {exc}",
                        severity="error")
            return
        self._filter_text = pattern
        self._rebuild_engagements(self._visible_engagements())
        self._apply_panel_titles()
        self.notify(f"filter: {pattern}")

    def clear_filter(self) -> None:
        """Drop the ``/`` filter and restore every row."""
        had_filter = self._filter_re is not None
        self._filter_re = None
        self._filter_text = ""
        self._rebuild_engagements(self._visible_engagements())
        self._apply_panel_titles()
        if had_filter:
            self.notify("filter cleared")

    def _rebuild_engagements(self, ordered: list[EngagementSnapshot]) -> None:
        """Full ENGAGEMENTS rebuild (``s`` sort / filter changes).

        Used where the incremental ``update_cell`` path cannot express the
        change (row order, visibility). Row keys stay stable per id; with
        follow-mode on, the cursor re-anchors on the followed row afterwards.
        """
        table = self._overview_widget("#engagements")
        if table is None or not isinstance(table, DataTable):
            return
        table.clear()
        self._row_keys.clear()
        for eng in ordered:
            cells = panels.engagement_row_cells(eng, self.ui_theme)
            self._row_keys[eng.id] = table.add_row(*cells, key=eng.id)
        self._apply_follow()

    def _overview_cursor_key(self) -> str | None:
        """The row key currently under the ENGAGEMENTS cursor (None if empty)."""
        table = self._overview_widget("#engagements")
        if not isinstance(table, DataTable) or table.row_count == 0:
            return None
        row = max(0, min(table.cursor_coordinate.row, table.row_count - 1))
        value = table.coordinate_to_cell_key(Coordinate(row, 0)).row_key.value
        return value if isinstance(value, str) else None

    def _visible_row_keys(self) -> list[str]:
        """Row keys in display order (display order == insertion order)."""
        table = self._overview_widget("#engagements")
        if not isinstance(table, DataTable):
            return []
        keys: list[str] = []
        for row in range(table.row_count):
            value = table.coordinate_to_cell_key(Coordinate(row, 0)).row_key.value
            if isinstance(value, str):
                keys.append(value)
        return keys

    def _apply_follow(self) -> None:
        """Follow-mode (`f`): re-anchor the cursor on the remembered row."""
        if not self._follow or self._follow_key is None:
            return
        table = self._overview_widget("#engagements")
        if not isinstance(table, DataTable):
            return
        try:
            row = table.get_row_index(self._follow_key)
        except (CellDoesNotExist, RowDoesNotExist):
            return  # followed row hidden or gone; the latch stays on it
        if table.cursor_coordinate.row != row:
            table.move_cursor(row=row)

    def _update_topbar(self) -> None:
        widget = self._overview_widget("#topbar")
        if widget is None:
            return
        widget.update(panels.topbar(
            self.snapshot, self.ui_theme, theme_name=self.theme_name,
            watched=self._watched, uptime_s=time.monotonic() - self._started_at,
        ))

    def _apply_panel_titles(self) -> None:
        """Border titles + STALE escalation (DESIGN section 6)."""
        now = time.monotonic()
        age = now - self._last_data_mono
        for panel_id, mult in PANEL_MULTIPLIERS.items():
            widget = self._overview_widget(f"#{panel_id}")
            if widget is None:
                continue
            title = Text(PANEL_TITLES[panel_id], style=self.ui_theme.style("panel.title"))
            if panel_id == "feed":
                title.append(f" ─ newest first · polled {age:.0f}s ago",
                             style=self.ui_theme.style("text.muted"))
            if panel_id == "engagements":
                # OVERVIEW table-verb state hints (DESIGN section 5.1).
                if self._filter_text:
                    title.append(f" ─ filter: {self._filter_text}",
                                 style=self.ui_theme.style("text.muted"))
                if self._follow:
                    title.append("  ● follow", style=self.ui_theme.style("accent"))
            if age > STALE_CRIT_X * mult:
                title.append("  ■ STALE", style=f"bold {self.ui_theme.style('state.crit')}")
                widget.add_class("stale-crit")
                widget.remove_class("stale-warn")
            elif age > STALE_WARN_X * mult:
                title.append("  ▲ stale?", style=self.ui_theme.style("state.stale"))
                widget.add_class("stale-warn")
                widget.remove_class("stale-crit")
            else:
                widget.remove_class("stale-warn")
                widget.remove_class("stale-crit")
            widget.border_title = title

    # -- feed -----------------------------------------------------------------

    def _write_new_feed_events(self) -> None:
        """Merge the selected engagement's tail and display newest dates first."""
        eng = self.current_engagement()
        stream = eng.id if eng else None
        if self._feed_stream_id != stream:
            self._feed_stream_id = stream
            self._feed_events.clear()
            self._feed_audits.clear()
            self._feed_dirty = True
        if eng is not None:
            for event in eng.events_tail:
                if self._feed_events.get(event.seq) != event:
                    self._feed_events[event.seq] = event
                    self._feed_dirty = True
            if len(self._feed_events) > FEED_LIMIT:
                newest = sorted(self._feed_events.values(), key=self._event_sort_key,
                                reverse=True)[:FEED_LIMIT]
                self._feed_events = {event.seq: event for event in newest}
        self._render_feed()

    @staticmethod
    def _event_sort_key(event: Event) -> tuple[float, int]:
        """Compare ISO timestamps by instant, including timezone offsets."""
        try:
            stamp = datetime.fromisoformat(event.ts).timestamp()
        except (ValueError, OverflowError, OSError):
            stamp = float("-inf")  # unparseable timestamps remain visible last
        return stamp, event.seq

    def _render_feed(self) -> None:
        feed = self._overview_widget("#feed")
        if not self._feed_dirty or not isinstance(feed, RichLog):
            return
        rows = [(*self._event_sort_key(event), panels.event_line(event, self.ui_theme))
                for event in self._feed_events.values()]
        rows.extend(self._feed_audits)
        rows.sort(key=lambda row: row[:2], reverse=True)
        # RichLog appends only. Rebuild the bounded view when content changes;
        # idle polls leave it intact. Keep the viewport on the newest rows.
        feed.clear()
        for _stamp, _seq, line in rows[:FEED_LIMIT]:
            feed.write(line, scroll_end=False)
        feed.scroll_home(animate=False)
        self._feed_dirty = False

    def audit(self, summary: str) -> None:
        """Echo a UI audit line into the activity feed (P7; stub for v1)."""
        theme = self.ui_theme
        now = datetime.now().astimezone()
        line = Text(f"{now.isoformat(timespec='seconds')} ", style=theme.style("feed.ts"))
        line.append("ui.audit", style=theme.style("feed.kind_rule"))
        line.append(f" {summary}", style=theme.style("text.primary"))
        self._feed_serial += 1
        self._feed_audits.append((now.timestamp(), self._feed_serial, line))
        self._feed_dirty = True
        self._flush_audit()

    def _flush_audit(self) -> None:
        self._render_feed()

    # -- banners / notifications ----------------------------------------------

    def _show_banner(self, text: str) -> None:
        widget = self._overview_widget("#banner")
        if widget is not None:
            widget.update(Text(text, style=f"bold {self.ui_theme.style('state.crit')}"))
            widget.add_class("visible")

    def _hide_banner(self) -> None:
        widget = self._overview_widget("#banner")
        if widget is not None:
            widget.remove_class("visible")

    # -- actions / navigation ---------------------------------------------------

    def action_switch(self, screen: str) -> None:
        self.goto_screen(screen)

    def action_refresh_now(self) -> None:
        """``r`` — fetch a frame immediately and re-render every panel."""
        self._fetch()
        if self.snapshot is not None:
            self._update_due(force=True)
            self._apply_panel_titles()

    def action_redraw(self) -> None:
        """⌃L — force a full layout refresh of the current screen."""
        self.screen.refresh(layout=True)

    def action_help_overlay(self) -> None:
        self.push_screen(HelpOverlay(self.screen))

    def open_engagement(self, eng_id: str) -> None:
        if self.current_engagement(eng_id) is None:
            self.notify(f"unknown engagement: {eng_id}", severity="error")
            return
        self._engagement_id = eng_id
        self._engagement.set_engagement(eng_id)
        self.goto_screen("engagement")

    def show_report(self, kind: str, arg: str | None) -> None:
        self._reports.set_report(kind, arg)
        self.goto_screen("reports")

    # -- command mode (: and palette share this) --------------------------------

    def masked_summary(self, eng: EngagementSnapshot) -> str:
        """One-line masked summary for the clipboard (P5: snapshot data only).

        Built exclusively from the already-redacted snapshot fields: id,
        state, letter-flag string and hypothesis/finding totals. No raw
        target content can enter this string by construction.
        """
        state = "active" if eng.live else "sealed" if eng.sealed else "idle"
        if eng.stale:
            state += " ▲ stale"
        hyps = sum(eng.hyps.values()) if eng.hyps else 0
        finds = sum(eng.findings.values()) if eng.findings else 0
        flags = letter_flags(panels.derive_flags(eng), self.ui_theme).plain
        return f"{eng.id} {state} flags={flags} hyps={hyps} finds={finds}"

    def run_command(self, line: str) -> None:
        """Parse and run one ``:``-mode command (also backs the palette)."""
        text = line.strip().lstrip(":").strip()
        if not text:
            return
        cmd, *rest = text.split()
        arg = " ".join(rest) or None
        if cmd in _ARGLESS_COMMANDS:
            self._remember_command(cmd)
        if cmd == "doctor":
            self.show_report("doctor", None)
        elif cmd == "rules":
            self.show_report("rules", None)
        elif cmd == "digest":
            if not arg:
                self.notify("usage: :digest <engagement-id>", severity="warning")
                return
            self._remember_command(cmd)
            self.show_report("digest", arg)
        elif cmd == "engagement":
            if not arg:
                self.notify("usage: :engagement <engagement-id>", severity="warning")
                return
            self._remember_command(cmd)
            self.open_engagement(arg)
        elif cmd == "watch":
            if not arg:
                self.notify("usage: :watch <engagement-id>", severity="warning")
                return
            if self.current_engagement(arg) is None:
                self.notify(f"unknown engagement: {arg}", severity="error")
                return
            self._remember_command(cmd)
            self._watched = arg
            self._write_new_feed_events()
            self._update_due(force=True)
            self.audit(f"ui.watch engagement='{arg}'")
            self.notify(f"watching {arg}")
        elif cmd in ("pause", "resume"):
            self._confirm_runner_control(cmd)
        elif cmd == "help":
            self.action_help_overlay()
        elif cmd == "overview":
            self.goto_screen("overview")
        elif cmd == "theme":
            if not arg:
                self.notify("usage: :theme <name|file>", severity="warning")
                return
            self._remember_command(cmd)
            self._command_theme(arg)
        else:
            self.notify(f"unknown command: {cmd}", severity="error")
            self.audit(f"ui.error unknown command '{cmd}'")

    def _remember_command(self, cmd: str) -> None:
        """Record a successfully dispatched command (palette recents-first).

        MRU order: a repeat execution moves the name to the front; the deque
        evicts the oldest beyond :data:`RECENT_COMMANDS_MAX` (session-only).
        """
        if cmd in self._recent_commands:
            self._recent_commands.remove(cmd)
        self._recent_commands.append(cmd)

    def _command_theme(self, arg: str | None) -> None:
        if not arg:
            self.notify("usage: :theme <name|file>", severity="warning")
            return
        builtin = get_builtin_theme(arg)
        if builtin is not None:
            self.ui_theme, self.theme_name = builtin, builtin.name
        else:
            try:
                loaded, warnings = load_theme_file(arg)
            except OSError as exc:
                self.notify(f"theme load failed: {exc}", severity="error")
                return
            for warning in warnings:
                self.notify(warning, severity="warning")
            self.ui_theme, self.theme_name = loaded, loaded.name
        self._activate_theme(self.ui_theme)
        self.audit(f"ui.theme '{self.theme_name}'")
        self.notify(f"theme: {self.theme_name}")

    def action_confirm_quit(self) -> None:
        ''
        dialog = ConfirmDialog(
            title="Quit MOTOKO?",
            impact=(
                "Close this monitor session. Running scans continue.\n"
                f"No response within {CONFIRM_TIMEOUT_S:.0f}s cancels."
            ),
        )
        self.push_screen(dialog, self._on_quit_confirmed)

    def _on_quit_confirmed(self, ok: bool) -> None:
        if ok:
            self.audit("ui.quit confirmed")
            self.exit()
        else:
            self.notify("quit cancelled")

    def _confirm_runner_control(self, action: str) -> None:
        """Structured confirm for the write stubs (DESIGN section 5.3)."""
        dialog = ConfirmDialog(
            title=f"run :{action} ?",
            impact=(
                "Effect: post a runner control intent via the engine adapter "
                "(existing CLI semantics — never a signal by name).\n"
                "Prototype: NOT wired. Confirming only echoes an audit line "
                "into the activity feed; no engine state is touched.\n"
                f"Fail-closed: no answer within {CONFIRM_TIMEOUT_S:.0f}s = Cancel."
            ),
        )
        self.push_screen(dialog, lambda ok: self._on_control_confirmed(action, ok))

    def _on_control_confirmed(self, action: str, ok: bool) -> None:
        if ok:
            self.audit(f"ui.control :{action} confirmed (v1 stub — no engine write)")
            self.notify(f":{action} confirmed (stub)")
        else:
            self.audit(f"ui.control :{action} cancelled (fail-closed)")
