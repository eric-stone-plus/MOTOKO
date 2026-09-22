'Snapshot assembly: three collectors -> one frozen InterfaceSnapshot.\n\n``build_interface_snapshot`` is the single entry point the UI (and the\ndemo path) consumes. It wires FileCollector (filesystem facts),\nGraphCollector (ro-SQLite facts) and the same installation\'s\nAdapterClient (doctor/rules gates + REPORTS screen texts) into\nper-engagement EngagementSnapshot frames. Every failure degrades: a locked\ndatabase yields empty graph facts, a missing adapter yields ``gates=None``\nand an empty ``reports`` mapping, a doctor op that fails while rules data is\nvalid yields a rules-only ``GatesSummary`` with ``doctor_available=False``\n(never a pass verdict), a missing runtime root yields an empty engagement\nlist with a ``collector_error`` — nothing raises into the UI\n(design/DESIGN.md section 2, crash isolation).\n\nAdapter request budget (verified against engine/core/adapter.py): one\nprocess serves at most 32 requests. Per 15s window this collector spends\nexactly 3 — doctor (1), rules (1) and one digest (1) for the live-or-first\nengagement — plus a single capabilities handshake at spawn. That is ~10\nwindows (~150s) per adapter process, after which AdapterClient transparently\nrespawns. The doctor/rules responses are fetched ONCE and shared between the\nGatesSummary projection and the report texts, so adding the reports cost\nexactly one extra request per window (the digest); no interval was lowered.\n\nThe engine\'s motoko/1 protocol carries STRUCTURED JSON only — there is no\ntext op. Observed shapes (core/adapter.py ``_read``): doctor ->\n``{"checks": [{"category", "counts": {OK, WARN, FAIL}}], "failures"}`` (the\nper-check diagnostic MESSAGES are projected away engine-side and never ride\nthe wire), rules -> ``{"rules_total", "fireable", "counts", "by_code"}``,\ndigest -> ``{"counts": {kind: {state: n}}, "last_event", "latest_wave"}`` and\n``{"error": "engagement_not_found"}`` (exit 2) for unknown engagements. The\n"full report text" stored in ``InterfaceSnapshot.reports`` is therefore a\nlocal text projection of those payloads — deterministic, redacted, capped —\nnot the engine CLI\'s printed output. A missing/failed op simply leaves its\nkey out (fail-closed).\n'

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from interface.collectors.adapter import AdapterClient
from interface.collectors.demo import DemoCollector
from interface.collectors.files import EngagementFiles, FileCollector
from interface.collectors.graph import GraphCollector, GraphFacts
from interface.render.redact import redact_text
from interface.snapshot import (
    EngagementSnapshot,
    GatesSummary,
    InterfaceSnapshot,
    WaveProgress,
)

__all__ = ["build_interface_snapshot"]

GATES_TTL_S = 15.0
"""Heavy adapter report ops run at most this often (GATES panel x15 lane)."""

REPORT_TEXT_CAP_CHARS = 20_000
"""Hard cap for one report text carried in the snapshot.

Strix-style byte-budgeted projection (research/05, section 13.8): a report
that would blow up the UI is truncated LOUDLY, never silently clipped.
"""

REPORT_TRUNCATION_MARKER = "\n... [truncated]"
"""Appended when a report text exceeds the cap — visible, greppable."""


class _CollectorSession:
    """Long-lived collector set for one (root, use_adapter) pair."""

    def __init__(self, root: Path, use_adapter: bool, runtime_root: Path) -> None:
        self.file_collector = FileCollector(root, runtime_root=runtime_root)
        self.graph_collector = GraphCollector(root, runtime_root=runtime_root)
        self.adapter = AdapterClient(runtime_root=runtime_root) if use_adapter else None
        self.gates: GatesSummary | None = None
        self.reports: dict[str, str] = {}
        self.reports_at: float | None = None
        self.gates_at = 0.0
        self.engagement_ids: set[str] | None = None

    def gates_refresh(self, now: float,
                      files: Sequence[EngagementFiles] = ()) -> GatesSummary | None:
        """Return cached gates, re-querying the adapter at most per TTL.

        On a TTL boundary the doctor/rules/digest ops run together and also
        fill ``self.reports`` (the REPORTS screen texts, see module
        docstring for the budget math). A failed probe degrades to
        ``None``/empty reports ("adapter unavailable") instead of holding a
        stale verdict — P6, honest staleness beats fake data.
        """
        if self.adapter is None:
            return None
        if now - self.gates_at >= GATES_TTL_S:
            doctor = self.adapter.doctor() or {}
            rules = self.adapter.rules() or {}
            self.gates = _gates_from_payloads(doctor, rules)
            self.reports = _reports_from_payloads(self.adapter, doctor,
                                                  rules, files)
            self.reports_at = now
            self.gates_at = now
        return self.gates


#: Sessions include both the installation and runtime path in their identity.
_SESSIONS: dict[tuple[str, str, bool], _CollectorSession] = {}


def close_sessions() -> None:
    """Reap this interface's adapter children on a normal CLI exit."""
    sessions = list(_SESSIONS.values())
    _SESSIONS.clear()
    for session in sessions:
        if session.adapter is not None:
            session.adapter.close()


def _gates_from_payloads(doctor: dict, rules: dict) -> GatesSummary | None:
    'Doctor + rules payloads -> GatesSummary (GATES panel / :doctor screen).'
    checks = doctor.get("checks")
    doctor_ok = isinstance(checks, list) and bool(checks)
    total = rules.get("rules_total")
    rules_ok = isinstance(total, int) and not isinstance(total, bool)
    if not doctor_ok and not rules_ok:
        return None
    counts = rules.get("counts") if isinstance(rules.get("counts"), dict) else {}
    fireable = rules.get("fireable")
    never_fires = (total - fireable
                   if isinstance(total, int) and isinstance(fireable, int)
                   else 0)
    high = _int_or_0(counts, "HIGH")
    if not doctor_ok:
        return GatesSummary(sections_ok=0, sections_total=0,
                            rules_never_fires=max(0, never_fires),
                            rules_high=high,
                            ok=False, doctor_available=False)
    # ``checks`` is a list of categories.  Each category carries its own
    # OK/WARN/FAIL row counts; summing the OK rows and comparing that with the
    # number of categories mixes units (a healthy doctor used to render 26/13
    # and FAIL).  The badge is about category health, so count categories with
    # zero FAIL rows instead.
    sections_ok = 0
    for check in checks:
        check_counts = check.get("counts") if isinstance(check, dict) else None
        if (isinstance(check_counts, dict)
                and _int_or_0(check_counts, "FAIL") == 0):
            sections_ok += 1
    failures = doctor.get("failures")
    failures = failures if isinstance(failures, int) else None
    return GatesSummary(sections_ok=sections_ok, sections_total=len(checks),
                        rules_never_fires=max(0, never_fires),
                        rules_high=high,
                        ok=failures == 0)


def _int_or_0(mapping: Mapping, key: str) -> int:
    """A plain int from a JSON mapping, or 0 (bools are not ints here)."""
    value = mapping.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


# -- report text projections (structured adapter payloads -> capped text) --

def _cap_report(text: str) -> str:
    """Hard-truncate an over-long report with a loud marker (P6: visible)."""
    if len(text) <= REPORT_TEXT_CAP_CHARS:
        return text
    keep = max(0, REPORT_TEXT_CAP_CHARS - len(REPORT_TRUNCATION_MARKER))
    return text[:keep] + REPORT_TRUNCATION_MARKER


def _render_doctor_report(doctor: dict) -> str:
    """Doctor payload -> per-category OK/WARN/FAIL count lines."""
    checks = doctor.get("checks")
    if not isinstance(checks, list) or not checks:
        return ""
    failures = doctor.get("failures")
    failures = failures if isinstance(failures, int) else "?"
    scope = doctor.get("scope", "full")
    lines = [f"MOTOKO doctor — {scope} scope, {len(checks)} categories, {failures} FAIL"]
    for check in checks:
        if not isinstance(check, dict):
            continue
        counts = check.get("counts") if isinstance(check.get("counts"), dict) else {}
        lines.append("  {}: OK={} WARN={} FAIL={}".format(
            check.get("category") or "?",
            _int_or_0(counts, "OK"), _int_or_0(counts, "WARN"),
            _int_or_0(counts, "FAIL")))
    return "\n".join(lines)


def _render_rules_report(rules: dict) -> str:
    """Rules payload -> totals, severity counts and per-code findings."""
    total = rules.get("rules_total")
    if not isinstance(total, int) or isinstance(total, bool):
        return ""
    fireable = rules.get("fireable")
    fireable = fireable if isinstance(fireable, int) and not isinstance(
        fireable, bool) else "?"
    counts = rules.get("counts") if isinstance(rules.get("counts"), dict) else {}
    lines = [f"MOTOKO rules — {total} total, {fireable} fireable",
             "  severity: HIGH={} MEDIUM={} LOW={}".format(
                 _int_or_0(counts, "HIGH"), _int_or_0(counts, "MEDIUM"),
                 _int_or_0(counts, "LOW"))]
    by_code = rules.get("by_code")
    if isinstance(by_code, dict) and by_code:
        lines.append("  findings by code:")
        for code in sorted(by_code):
            lines.append(f"    {code}: {_int_or_0(by_code, code)}")
    return "\n".join(lines)


def _render_digest_report(digest: dict, eng_id: str) -> str:
    """Digest payload -> per-kind state counts + latest wave projection."""
    if not isinstance(digest, dict):
        return ""
    counts = digest.get("counts")
    if not isinstance(counts, dict) or not counts:
        return ""
    lines = [f"MOTOKO digest — {eng_id}"]
    for kind in sorted(counts):
        states = counts[kind] if isinstance(counts[kind], dict) else {}
        parts = [f"{state}={_int_or_0(states, state)}" for state in sorted(states)]
        if parts:
            lines.append(f"  {kind}: " + " ".join(parts))
    last_event = digest.get("last_event")
    if isinstance(last_event, int) and not isinstance(last_event, bool):
        lines.append(f"  last event seq: {last_event}")
    wave = digest.get("latest_wave")
    if isinstance(wave, dict) and wave:
        current = wave.get("wave")
        current = current if isinstance(current, int) and not isinstance(
            current, bool) else "?"
        lines.append(f"  latest wave: {current} "
                     f"stop_reason={wave.get('stop_reason')}")
    return "\n".join(lines)


def _pick_digest_engagement(files: Sequence[EngagementFiles]) -> str | None:
    """The engagement whose digest is fetched: live first, else the first."""
    for facts in files:
        if facts.live:
            return facts.id
    return files[0].id if files else None


def _reports_from_payloads(adapter: AdapterClient, doctor: dict, rules: dict,
                           files: Sequence[EngagementFiles]) -> dict[str, str]:
    """Build the ``reports`` mapping; every value redacted and capped.

    doctor/rules payloads are shared with the gates projection (fetched once,
    projected twice). The digest is one extra request for the live-or-first
    engagement; an unknown/failed digest (engine exit 2) leaves its key out.
    """
    reports: dict[str, str] = {}
    doctor_text = _render_doctor_report(doctor)
    if doctor_text:
        reports["doctor"] = _cap_report(redact_text(doctor_text))
    rules_text = _render_rules_report(rules)
    if rules_text:
        reports["rules"] = _cap_report(redact_text(rules_text))
    eng_id = _pick_digest_engagement(files)
    if eng_id is not None:
        digest = adapter.digest(eng_id)
        digest_text = _render_digest_report(digest, eng_id) if digest else ""
        if digest_text:
            reports[f"digest:{eng_id}"] = _cap_report(redact_text(digest_text))
    return reports


def _wave_progress(files: EngagementFiles, graph: GraphFacts) -> WaveProgress | None:
    """Merge graph wave events with file-level progress signals.

    The graph knows the current wave number and per-rule run counters; the
    filesystem adds the wave-dir count (total) and the heartbeat
    ``progress:<tool>:<n>/<m>`` counters. ETA is deliberately None here: the
    60s smoothed estimate belongs to the UI's rate windows (design section 6).
    """
    wave = graph.wave
    if wave is not None:
        total = max(wave.total, files.wave_count)
        return WaveProgress(current=wave.current, total=total,
                            tools_done=wave.tools_done,
                            tools_total=wave.tools_total,
                            findings_new=wave.findings_new, eta_s=None)
    if files.progress_total is not None:
        return WaveProgress(current=files.wave_count, total=files.wave_count,
                            tools_done=files.progress_done or 0,
                            tools_total=files.progress_total,
                            findings_new=0, eta_s=None)
    return None


def _assemble(files: EngagementFiles, graph: GraphFacts,
              gates: GatesSummary | None) -> EngagementSnapshot:
    """Merge one engagement's collector outputs into the frozen snapshot."""
    return EngagementSnapshot(
        id=files.id,
        live=files.live,
        sealed=files.sealed,
        heartbeat_age_s=files.heartbeat_age_s,
        heartbeat_msg=files.heartbeat_msg,
        runner_alive=files.runner_alive,
        hyps=graph.hyps,
        findings=graph.findings,
        inflight=graph.inflight,
        cooldowns=files.cooldowns,
        wave=_wave_progress(files, graph),
        legs=files.legs,
        gates=gates,
        events_tail=graph.events_tail,
        events_head_seq=graph.events_head_seq,
        stuck_testing_s=graph.stuck_testing_s,
        canary_tripped=graph.canary_tripped,
        stale=files.stale,
    )


def build_interface_snapshot(root: Path | None, demo: bool, *,
                             use_adapter: bool = True,
                             runtime_root: Path | None = None) -> InterfaceSnapshot:
    """Collect one consistent frame for the whole interface.

    ``demo=True`` ignores ``root`` and returns DemoCollector output.
    Otherwise ``root`` is the installation home. ``runtime_root`` selects
    the engagement directory; absent an override it is ``root/tasks``.
    The CLI always supplies the engine's resolved runtime. ``use_adapter=False``
    skips the subprocess for collector tests. Sessions persist across calls.
    """
    now = time.time()
    if demo:
        return DemoCollector().snapshot(now=now)
    if root is None:
        return InterfaceSnapshot(taken_at=now, engagements=(),
                                 collector_error="no runtime root configured")
    runtime_root = Path(runtime_root) if runtime_root is not None else root / "tasks"
    if not runtime_root.is_dir():
        return InterfaceSnapshot(taken_at=now, engagements=(),
                                 collector_error=f"runtime root unavailable: {runtime_root}")
    key = (str(root), str(runtime_root), use_adapter)
    session = _SESSIONS.get(key)
    if session is None:
        session = _CollectorSession(root, use_adapter, runtime_root)
        _SESSIONS[key] = session

    # Files + graph facts first: the digest target (live-or-first engagement)
    # is only known after discovery. The adapter refresh stays on the x15 TTL
    # lane; its single result is shared by every engagement frame below.
    collected: list[tuple[EngagementFiles, GraphFacts]] = []
    errors: list[str] = []
    engagement_ids = session.file_collector.engagement_ids()
    current_ids = set(engagement_ids)
    session.graph_collector.retain_engagements(current_ids)
    if session.engagement_ids is not None and session.engagement_ids != current_ids:
        # Digest reports belong to the discovered set, not to the cache TTL.
        session.gates_at = float("-inf")
        session.reports = {}
        session.reports_at = None
    session.engagement_ids = current_ids
    for eng_id in engagement_ids:
        files = session.file_collector.collect(eng_id)
        graph = session.graph_collector.collect(eng_id, sealed=files.sealed)
        if graph.error:
            errors.append(f"{eng_id}: {graph.error}")
        collected.append((files, graph))
    gates = session.gates_refresh(now, [files for files, _ in collected])

    engagements = [_assemble(files, graph, gates)
                   for files, graph in collected]
    engagements.sort(key=lambda snap: (not snap.live, not snap.sealed, snap.id))
    reports_age = (max(0.0, now - session.reports_at)
                   if session.reports_at is not None else None)
    return InterfaceSnapshot(
        taken_at=now,
        engagements=tuple(engagements),
        collector_error="; ".join(errors) if errors else None,
        # The mapping object is replaced (never mutated) on each refresh, so
        # sharing it across frozen snapshots is safe.
        reports=session.reports,
        reports_age_s=reports_age,
    )
