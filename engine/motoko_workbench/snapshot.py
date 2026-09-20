"""Snapshot contract for the MOTOKO workbench.

The UI layer only ever reads frozen snapshots produced by the collector
thread (see design/DESIGN.md section 8 for the rationale). Every field here
is part of the interface between the data layer and the render layer; both
sides code against this file, which is owned by the design (not by either
agent).

All target-identifying content is redacted upstream, in the collectors, via
motoko_workbench.render.redact. A snapshot must be safe to render as-is.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Event:
    """Projection of one graph.db `events` row (activity feed line)."""

    seq: int
    ts: str
    kind: str
    summary: str  # produced by the kind-whitelist renderer, already redacted


@dataclass(frozen=True)
class Cooldown:
    """One active per-origin cooldown (OPSEC panel countdown bar)."""

    origin: str  # already masked (e.g. "origin-1a2b3c4d")
    remaining_s: int
    reason: str  # "429" | "detected" | ...


@dataclass(frozen=True)
class ToolRun:
    """One in-flight tool execution (TOOL RUNS panel row)."""

    tool: str
    hypothesis_id: int | None
    state: str
    duration_s: float | None


@dataclass(frozen=True)
class WaveProgress:
    """Scan wave progress for the RUN PROGRESS panel."""

    current: int
    total: int
    tools_done: int
    tools_total: int
    findings_new: int
    eta_s: float | None  # 60s-smoothed; None while too few samples


@dataclass(frozen=True)
class GatesSummary:
    'Doctor + rules static report (GATES panel / :doctor screen).'

    sections_ok: int
    sections_total: int  # doctor
    rules_never_fires: int
    rules_high: int  # rules --json ratchet rows
    ok: bool
    doctor_available: bool = True


@dataclass(frozen=True)
class LegStatus:
    """One LLM loop leg (TOKENS/LEGS panel status dot)."""

    name: str
    state: str  # ok | busy | idle | error
    last_round: int | None
    verdict: str | None  # CONTINUE | ROLLBACK | STOP


STUCK_AFTER_S = 7200.0
"""Testing age above which the ``S`` flag lights.

A strix deep-dive legitimately holds a hypothesis in ``testing`` for up to
7200s (research/04-motoko-data-sources.md; DESIGN section 11.3), so ``S`` is
a marker, not an alarm: everything at or under this budget is normal deep
work. Lives on the contract so every tier (panels, status, watch) shares one
threshold definition.
"""

HYP_STATES = ("proposed", "testing", "done", "rejected")
FINDING_STATES = (
    "candidate",
    "triaged",
    "reproduced",
    "verified",
    "exploitable",
    "confirmed_impact",
    "wont_test",
    "retired",
    "no_target",
    "duplicate",
)


@dataclass(frozen=True)
class EngagementSnapshot:
    """Everything the UI shows about one engagement, one consistent frame."""

    id: str
    live: bool
    sealed: bool
    heartbeat_age_s: float | None
    heartbeat_msg: str | None
    runner_alive: bool
    hyps: Mapping[str, int] = field(default_factory=dict)
    findings: Mapping[str, int] = field(default_factory=dict)
    inflight: tuple[ToolRun, ...] = ()
    cooldowns: tuple[Cooldown, ...] = ()
    wave: WaveProgress | None = None
    legs: tuple[LegStatus, ...] = ()
    gates: GatesSummary | None = None
    events_tail: tuple[Event, ...] = ()  # newest last, ascending seq
    events_head_seq: int = 0
    stale: bool = False
    # Age (seconds) of the oldest hypothesis currently in ``testing`` whose
    # tool_runs are ALL terminal — the engine's own stuck_testing definition
    # (core/graph_health.py). None when no such hypothesis exists, the graph
    # is empty/unreadable, or the hypothesis was never dispatched.
    stuck_testing_s: float | None = None
    # True once an ``opsec_canary_skip`` event was observed for this
    # engagement (sticky for the collector session — see GraphCollector).
    canary_tripped: bool = False


@dataclass(frozen=True)
class WorkbenchSnapshot:
    """One frame of the whole workbench; posted to the UI via call_from_thread."""

    taken_at: float
    engagements: tuple[EngagementSnapshot, ...]
    collector_error: str | None = None
    # Full adapter report texts for the REPORTS screen (:doctor/:rules/:digest),
    # keyed "doctor" | "rules" | "digest:<engagement-id>". Empty when no adapter
    # is available (fail-closed: panels fall back to the summary rendering).
    # Every value is redacted and size-capped upstream (collectors/__init__.py).
    reports: Mapping[str, str] = field(default_factory=dict)
    # Age of the report texts at snapshot time (None = never fetched). One
    # timestamp covers the whole mapping: all three ops are fetched together
    # on the GATES x15 lane.
    reports_age_s: float | None = None
