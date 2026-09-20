'DemoCollector — fully synthetic, deterministic workbench data (--demo).\n\nThree synthetic engagements so every panel has something to show on a\nmachine with no MOTOKO runtime (design section 8, demo mode):\n\nThe ``reports`` mapping is filled with clearly-labelled synthetic adapter\ntexts (doctor/rules/digest) so the REPORTS screen shows real content shape\nwithout any adapter process.\n\nEverything is a pure function of ``time.time()`` (or an injected ``now``):\nthe same instant always yields the same snapshot, and successive instants\nstream — event seq numbers advance, cooldowns count down, tool durations\ngrow. Fixture-style target identifiers use ``example.invalid`` and\n``203.0.113.0/24`` only, and every summary/origin/report passes through\n``render.redact`` exactly like the real collectors do.\n'

from __future__ import annotations

import time

from motoko_workbench.render.redact import origin_label, redact_text, redact_url
from motoko_workbench.snapshot import (
    FINDING_STATES,
    HYP_STATES,
    Cooldown,
    EngagementSnapshot,
    Event,
    GatesSummary,
    LegStatus,
    ToolRun,
    WaveProgress,
    WorkbenchSnapshot,
)

DEMO_EPOCH = 1758300000.0
"""Reference epoch (2026-09-19); all periodic motion is measured from it."""

_TAIL_SIZE = 12

# Scripted live-feed cycle: (kind, summary template). Templates may embed
# ``{url}``, which is redacted before the Event is frozen. Kinds mirror the
# real writer vocabulary (research/04) so the feed renderer gets exercise.
_EVENT_SCRIPT: tuple[tuple[str, str], ...] = (
    ("act.dedup", "act.dedup target={url}"),
    ("entity.transition", "hyp#a1b2c3d4 from=testing to=done"),
    ("rule_hit_class", "rule_hit_class jwt (nuclei)"),
    ("opsec_cooldown_skip", "opsec_cooldown_skip reason=429 origin={origin}"),
    ("entity.transition", "fnd#9f8e7d6c from=triaged to=verified"),
    ("scan.wave.completed", "scan.wave.completed wave={wave} stop_reason=wave_boundary"),
    ("act.dedup", "act.dedup target={url2}"),
    ("waf_detected", "waf_detected tool=ffuf"),
    ("entity.transition", "hyp#5d4c3b2a from=proposed to=testing"),
    ("edge.added", "edge.added rel=discovered_on"),
    ("finding.duplicate_seen", "finding.duplicate_seen duplicate_count=2"),
    ("entity.upsert", "entity.upsert asset#7c6b5a49 state=active"),
)

_URL_A = "https://api.example.invalid/v2/login"
_URL_B = "http://203.0.113.10/admin"
_ORIGIN_A = "https://shop.example.invalid"
_SEALED_EVENTS: tuple[tuple[int, str, str, str], ...] = (
    (1, "2026-09-16T08:00:05.120000+00:00", "entity.upsert",
     "asset#1a2b3c4d state=active"),
    (2, "2026-09-16T08:01:12.004000+00:00", "entity.upsert",
     "finding#2b3c4d5e state=candidate"),
    (3, "2026-09-16T08:03:40.500000+00:00", "entity.transition",
     "finding#2b3c4d5e from=candidate to=triaged"),
    (4, "2026-09-16T08:05:00.000000+00:00", "edge.added",
     "edge.added rel=discovered_on"),
)

#: Extra tail event for ``demo-sealed-1`` only, so the ``K`` flag is
#: exercisable. Summary mirrors the engine's whitelist rendering of an
#: ``opsec_canary_skip`` payload (only ``tool`` is safe to project — the
#: payload's url/canary token are target data, P5).
_SEALED_CANARY_EVENT: tuple[int, str, str, str] = (
    5, "2026-09-16T08:06:30.000000+00:00", "opsec_canary_skip",
    "hyp#4c3b2a19 tool=nuclei",
)

# Stuck-testing ages straddling the strix 7200s budget (research/04): the
# live engagement's oldest testing hypothesis drifts upward from 6900s but
# wraps every 240s, so it never crosses the budget; the sealed one is
# stranded just over it. Both sides of the ``S`` threshold stay exercisable.
_LIVE_STUCK_BASE_S = 6900.0
_LIVE_STUCK_PERIOD_S = 240.0
_SEALED_STUCK_TESTING_S = 7260.0

_DEMO_REPORTS_AGE_S = 6.0
"""Plausible fixed age for the synthetic report texts (deterministic)."""

_DEMO_DOCTOR_REPORT = """MOTOKO doctor — 13 categories, 0 FAIL
  python: OK=1 WARN=0 FAIL=0
  storage: OK=1 WARN=0 FAIL=0
  temporary_storage: OK=1 WARN=0 FAIL=0
  tools: OK=1 WARN=0 FAIL=0
  verification_backends: OK=2 WARN=0 FAIL=0
  container: OK=1 WARN=0 FAIL=0
  audit_config: OK=1 WARN=0 FAIL=0
  linter: OK=1 WARN=0 FAIL=0
  credentials: OK=0 WARN=0 FAIL=0
  reflector: OK=1 WARN=0 FAIL=0
  wordlists: OK=1 WARN=0 FAIL=0
  engagements: OK=1 WARN=0 FAIL=0
  egress: OK=1 WARN=0 FAIL=0
--- no failures (demo projection, synthetic)"""

_DEMO_RULES_REPORT = """MOTOKO rules — 42 total, 41 fireable
  severity: HIGH=0 MEDIUM=2 LOW=6
  findings by code:
    R-CTXP-012: 3
    R-DEAD-004: 2
    R-NOPARSE-002: 2
    R-VOC-001: 1
(demo projection, synthetic)"""


def _phase(now: float, period: float) -> float:
    """Position within a periodic window, in [0, period)."""
    return (now - DEMO_EPOCH) % period


def _cycle_index(now: float, period: float, length: int) -> int:
    return int(_phase(now, period) / period * length) % length


def _live_events(now: float, head_seq: int) -> tuple[Event, ...]:
    """Last ``_TAIL_SIZE`` scripted events, ascending seq, ending at head."""
    events: list[Event] = []
    first = max(1, head_seq - _TAIL_SIZE + 1)
    for seq in range(first, head_seq + 1):
        kind, template = _EVENT_SCRIPT[(seq - 1) % len(_EVENT_SCRIPT)]
        summary = template.format(
            url=redact_url(_URL_A), url2=redact_url(_URL_B),
            origin=origin_label(_ORIGIN_A),
            wave=(seq - 1) // len(_EVENT_SCRIPT) + 1,
        )
        ts = _beat_ts(now - (head_seq - seq) * 2.0)
        events.append(Event(seq=seq, ts=ts, kind=kind, summary=summary))
    return tuple(events)


def _beat_ts(now: float) -> str:
    """Demo timestamp in the engine's UTC ISO style."""
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now))


def _live_engagement(now: float) -> EngagementSnapshot:
    seq_head = int((now - DEMO_EPOCH) / 2.0)  # one event every 2s
    tools_done = 18 + int((now - DEMO_EPOCH) / 30.0) % 17
    cooldown_left = int(1800 - _phase(now, 1800.0))
    # Oldest testing hypothesis drifts up but wraps below the strix budget:
    # the ``S`` flag must stay dark for a legitimately-held deep-dive.
    stuck_s = _LIVE_STUCK_BASE_S + _phase(now, _LIVE_STUCK_PERIOD_S)
    return EngagementSnapshot(
        id="demo-live-1",
        live=True,
        sealed=False,
        heartbeat_age_s=round(_phase(now, 1.0), 3),
        heartbeat_msg=f"progress:arjun:{tools_done}/34",
        runner_alive=True,
        hyps={"proposed": 12, "testing": 4, "done": 20, "rejected": 3},
        findings={"candidate": 5, "triaged": 8, "reproduced": 3, "verified": 2,
                  "exploitable": 1, "confirmed_impact": 1, "wont_test": 2,
                  "retired": 1, "no_target": 1, "duplicate": 4},
        inflight=(
            ToolRun(tool="nuclei", hypothesis_id=441, state="running",
                    duration_s=round(3.0 + _phase(now, 90.0), 1)),
            ToolRun(tool="ffuf", hypothesis_id=438, state="pending",
                    duration_s=0.0),
        ),
        cooldowns=(Cooldown(origin=origin_label(_ORIGIN_A),
                            remaining_s=cooldown_left, reason="429"),),
        wave=WaveProgress(current=3, total=7,
                          tools_done=tools_done,
                          tools_total=34, findings_new=6, eta_s=2460.0),
        legs=(
            LegStatus(name="qwen", state="ok", last_round=12, verdict="CONTINUE"),
            LegStatus(name="kimi", state="busy", last_round=12, verdict=None),
            LegStatus(name="grok", state="idle", last_round=11, verdict="CONTINUE"),
            LegStatus(name="glm", state="error", last_round=10, verdict="ROLLBACK"),
        ),
        gates=GatesSummary(sections_ok=13, sections_total=13,
                           rules_never_fires=1, rules_high=0, ok=True),
        events_tail=_live_events(now, max(1, seq_head)),
        events_head_seq=max(1, seq_head),
        stuck_testing_s=round(stuck_s, 1),
        canary_tripped=False,
        stale=False,
    )


def _sealed_engagement(now: float, *, stale: bool,
                       canary: bool = False) -> EngagementSnapshot:
    """One frozen sealed engagement.

    ``canary=True`` (``demo-sealed-1``) adds the ``opsec_canary_skip`` tail
    event and the stranded ``testing`` hypothesis just over the 7200s
    budget, exercising the ``K`` and ``S`` flags; the stale variant
    (``demo-sealed-2``) carries neither, so both flags have a dark side.
    """
    del now  # sealed state is frozen; only the stale/canary variants differ
    events = (_SEALED_EVENTS + (_SEALED_CANARY_EVENT,)) if canary \
        else _SEALED_EVENTS
    return EngagementSnapshot(
        id="demo-sealed-2" if stale else "demo-sealed-1",
        live=False,
        sealed=True,
        heartbeat_age_s=None if not stale else 259200.0,
        heartbeat_msg=None if not stale else "all-done",
        runner_alive=False,
        hyps={"proposed": 4, "testing": 1 if canary else 0, "done": 30,
              "rejected": 2},
        findings={"candidate": 0, "triaged": 12, "reproduced": 2, "verified": 4,
                  "exploitable": 1, "confirmed_impact": 2, "wont_test": 0,
                  "retired": 0, "no_target": 3, "duplicate": 5},
        inflight=(),
        cooldowns=(),
        wave=WaveProgress(current=2, total=2, tools_done=41, tools_total=41,
                          findings_new=9, eta_s=None),
        legs=(LegStatus(name="qwen", state="ok", last_round=7, verdict="STOP"),
              LegStatus(name="kimi", state="ok", last_round=7, verdict="STOP")),
        gates=GatesSummary(sections_ok=13, sections_total=13,
                           rules_never_fires=0, rules_high=0, ok=True),
        events_tail=tuple(
            Event(seq=seq, ts=ts, kind=kind,
                  summary=redact_text(summary.format(url=redact_url(_URL_A))))
            for seq, ts, kind, summary in events
        ),
        events_head_seq=events[-1][0],
        stuck_testing_s=_SEALED_STUCK_TESTING_S if canary else None,
        canary_tripped=canary,
        stale=stale,
    )


def _demo_digest_text(eng: EngagementSnapshot) -> str:
    """Synthetic digest projection coherent with the engagement's counts."""
    hyps = " ".join(f"{state}={eng.hyps.get(state, 0)}" for state in HYP_STATES)
    findings = " ".join(f"{state}={eng.findings.get(state, 0)}"
                        for state in FINDING_STATES)
    wave = (f"latest wave: {eng.wave.current} stop_reason=wave_boundary"
            if eng.wave is not None else "latest wave: none")
    return ("MOTOKO digest — "
            f"{eng.id} (demo projection, synthetic)\n"
            f"  hypothesis: {hyps}\n"
            f"  finding: {findings}\n"
            f"  last event seq: {eng.events_head_seq}\n"
            f"  {wave}")


def _demo_reports(engagements: tuple[EngagementSnapshot, ...]) -> dict[str, str]:
    """Clearly-synthetic REPORTS texts, redacted like real collector output."""
    reports = {
        "doctor": redact_text(_DEMO_DOCTOR_REPORT),
        "rules": redact_text(_DEMO_RULES_REPORT),
    }
    for eng in engagements:
        reports[f"digest:{eng.id}"] = redact_text(_demo_digest_text(eng))
    return reports


class DemoCollector:
    """Produce a fully synthetic WorkbenchSnapshot; stdlib-only, no I/O."""

    def snapshot(self, *, now: float | None = None) -> WorkbenchSnapshot:
        """One demo frame. Deterministic for a given ``now``."""
        current = time.time() if now is None else now
        engagements = (
            _live_engagement(current),
            _sealed_engagement(current, stale=False, canary=True),
            _sealed_engagement(current, stale=True),
        )
        return WorkbenchSnapshot(
            taken_at=current,
            engagements=engagements,
            reports=_demo_reports(engagements),
            reports_age_s=_DEMO_REPORTS_AGE_S,
        )
