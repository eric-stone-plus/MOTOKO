"""GraphCollector — read-only SQLite projection of graph.db.

Open rules (design/DESIGN.md sections 8 and 9 — binding):

- connections are ALWAYS ``file:…?mode=ro`` via the URI interface; a
  read-write handle is never opened, not even incidentally;
- sealed databases add ``immutable=1`` so SQLite skips lock/journal work on
  bytes the engine has frozen;
- ``timeout`` is 0: a database locked by the single writer fails fast and the
  collector returns empty facts. Failure NEVER escalates to a write attempt
  and NEVER raises into the UI (section 9, rule 5);
- a read-only connection can leave a cosmetic 0-byte ``-wal`` sidecar next to
  a sealed database (research/04); STALE logic must not treat that as dirt.

Queries are bounded and cursor-incremental: hypothesis/finding state counts
via GROUP BY, the activity feed via a per-engagement ``seq`` cursor (ascending,
with a cached tail of ``tail_size`` rows), in-flight tool runs by status, and the
stuck_testing age via one bounded ``EXISTS``/``NOT EXISTS`` query mirroring
the engine's own health check. The canary flag is derived from the event
rows already read (latched per session — see ``GraphCollector.__init__``).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from interface.render.redact import origin_label, redact_text, short_id
from interface.snapshot import (
    FINDING_STATES,
    HYP_STATES,
    Event,
    ToolRun,
    WaveProgress,
)

TAIL_SIZE = 200
"""Maximum events carried in one snapshot (newest last, ascending seq)."""

STUCK_TTL_S = 2.0
"""Stuck-testing age is consumed by x2 panels; computing it per x1 frame
doubles an unindexed correlated query for nothing (review-2 #2) — cache it
per engagement for this long on the long-lived collector."""

INFLIGHT_STATUSES = ("pending", "queued", "running")
"""tool_run.status values that count as in-flight (research/04)."""

CANARY_EVENT_KIND = "opsec_canary_skip"
"""Event kind the engine writes on every canary trip (core/orchestrator.py
OPSEC gate 1): both builtin honeypot-token hits and robots.txt
``canary_paths`` prefix hits land here. Verified in engine source; there is
no other canary-flavoured event kind."""

_KIND_PREFIXES = ("hyp", "fnd", "ast", "ev", "acc", "pth", "obs", "act", "srv", "run", "eng")
_KIND_NAMES = {"hyp": "hyp", "fnd": "finding", "ast": "asset"}

# Payload keys that are safe (engine enums / small integers) per event kind.
# Anything not listed here — free text, URLs, entity snapshots — never enters
# a summary. The final string still goes through redact_text as a guard.
_SAFE_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    "entity.transition": ("from", "to"),
    "entity.upsert": ("state",),
    "edge.added": ("rel",),
    "edge.add": ("rel",),  # engine/adapter spelling drift (research/04)
    "finding.duplicate_seen": ("duplicate_count",),
    "scan.wave.completed": ("wave", "cycles", "pending", "stop_reason"),
    "opsec_cooldown_skip": ("reason",),
    # The engine's canary payload is {"tool", "url", "canary"}: the url is
    # the raw target URL and the canary token may be a robots.txt path of
    # the target — neither may enter a summary (P5). Only the tool name
    # (a rule-set enum) is safe to project.
    "opsec_canary_skip": ("tool",),
    "waf_detected": ("reason",),
    "scope.set": ("name",),
}


@dataclass(frozen=True)
class GraphFacts:
    """Everything SQLite contributed for one engagement this tick."""

    id: str
    hyps: dict[str, int] = field(default_factory=dict)
    findings: dict[str, int] = field(default_factory=dict)
    events_tail: tuple[Event, ...] = ()
    events_head_seq: int = 0
    inflight: tuple[ToolRun, ...] = ()
    wave: WaveProgress | None = None
    # Oldest stranded ``testing`` hypothesis in seconds (None = none/no data).
    stuck_testing_s: float | None = None
    # True when a canary trip was observed here or in an earlier tick.
    canary_tripped: bool = False
    error: str | None = None


def _connect(db_path: Path, *, sealed: bool) -> sqlite3.Connection:
    """Open a strictly read-only connection; sealed dbs are immutable."""
    uri = "file:" + quote(str(db_path), safe="/") + "?mode=ro"
    if sealed:
        uri += "&immutable=1"
    conn = sqlite3.connect(uri, uri=True, timeout=0.0)
    conn.execute("PRAGMA query_only = ON")
    return conn


def _entity_ref(entity_id: str | None) -> str:
    """Short, stable display ref for an entity id (``hyp#ab12cd34``).

    Engine ids are ``{prefix}_{epoch_ms}_{uuid8}``; the prefix and uuid tail
    are stable and carry no target data. Anything else collapses to a
    ``short_id`` digest.
    """
    if not entity_id:
        return "-"
    parts = entity_id.split("_")
    if len(parts) >= 3 and parts[0] in _KIND_PREFIXES:
        name = _KIND_NAMES.get(parts[0], parts[0])
        return f"{name}#{parts[-1][-8:]}"
    return f"#{short_id(entity_id)}"


def _scalar(payload: dict, key: str) -> str | None:
    """One whitelisted scalar from an event payload, as display text."""
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    text = str(value)
    return text if len(text) <= 24 else None


def event_summary(kind: str, entity_id: str | None, payload_text: str | None) -> str:
    """Kind-whitelist summary renderer for one events row (already redacted).

    Unknown kinds render as their own name (the adapter would collapse them
    to "other" — that is exactly why the feed reads ro-SQLite instead). The
    result is passed through ``redact_text`` so a URL can never ride along,
    even if a whitelist key someday carries one.
    """
    pieces: list[str] = []
    ref = _entity_ref(entity_id)
    if entity_id:
        pieces.append(ref)
    payload: dict = {}
    if payload_text:
        try:
            parsed = json.loads(payload_text)
            if isinstance(parsed, dict):
                payload = parsed
        except (json.JSONDecodeError, TypeError):
            payload = {}
    for key in _SAFE_PAYLOAD_KEYS.get(kind, ()):
        value = _scalar(payload, key)
        if value is not None:
            if kind == "scope.set" and key == "name":
                value = origin_label(value)
            pieces.append(f"{key}={value}")
    return redact_text(" ".join(pieces) if pieces else kind)


def _parse_iso_ts(text: str | None) -> float | None:
    """Parse an engine ISO timestamp (UTC, often with microseconds)."""
    if not text:
        return None
    candidate = text.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _state_counts(conn: sqlite3.Connection, eng_id: str, kind: str,
                  states: tuple[str, ...]) -> dict[str, int]:
    """GROUP BY state counts, zero-filled over the snapshot state enums.

    States outside the snapshot enum are dropped (the UI funnel only knows
    the contracted keys); they still exist in the database.
    """
    counts = {state: 0 for state in states}
    rows = conn.execute(
        "SELECT state, COUNT(*) FROM entities "
        "WHERE engagement_id = ? AND kind = ? GROUP BY state",
        (eng_id, kind),
    ).fetchall()
    for state, count in rows:
        if state in counts:
            counts[state] = int(count)
    return counts


def _events_tail(conn: sqlite3.Connection, eng_id: str, after: int | None,
                 tail_size: int) -> tuple[tuple[Event, ...], int]:
    """Tail events for one engagement.

    First tick (``after is None``): the newest ``tail_size`` rows, returned
    ascending. Later ticks: only rows with ``seq`` greater than the stored
    cursor, ascending. Returns (events, new_cursor).
    """
    if after is None:
        rows = conn.execute(
            "SELECT seq, at, kind, entity_id, payload FROM events "
            "ORDER BY seq DESC LIMIT ?",
            (tail_size,),
        ).fetchall()
        rows = list(reversed(rows))
    else:
        rows = conn.execute(
            "SELECT seq, at, kind, entity_id, payload FROM events "
            "WHERE seq > ? ORDER BY seq ASC LIMIT ?",
            (after, tail_size),
        ).fetchall()
    events = tuple(
        Event(seq=int(seq), ts=str(at), kind=str(kind),
              summary=event_summary(str(kind), entity_id, payload))
        for seq, at, kind, entity_id, payload in rows
    )
    cursor = int(rows[-1][0]) if rows else (after or 0)
    return events, cursor


def _inflight(conn: sqlite3.Connection, now: float) -> tuple[ToolRun, ...]:
    """In-flight tool runs (TOOL RUNS panel rows).

    ``command`` is deliberately not selected: it is a secret-masked argv
    summary, but the panel only needs tool/state/duration, so the column is
    never even read.
    """
    placeholders = ",".join("?" for _ in INFLIGHT_STATUSES)
    rows = conn.execute(
        "SELECT tool, hypothesis_id, status, started_at FROM tool_run "
        f"WHERE status IN ({placeholders}) ORDER BY started_at",
        INFLIGHT_STATUSES,
    ).fetchall()
    runs: list[ToolRun] = []
    for tool, hypothesis_id, status, started_at in rows:
        started = _parse_iso_ts(started_at)
        duration = max(0.0, now - started) if started is not None else None
        if isinstance(hypothesis_id, str) and hypothesis_id:
            if hypothesis_id.isdigit():
                hyp_ref: int | str | None = int(hypothesis_id)
            else:
                hyp_ref = _entity_ref(hypothesis_id)
        else:
            hyp_ref = None
        runs.append(ToolRun(tool=str(tool), hypothesis_id=hyp_ref,
                            state=str(status), duration_s=duration))
    return tuple(runs)


def _wave_progress(conn: sqlite3.Connection) -> WaveProgress | None:
    'Wave progress from the newest ``scan.wave.completed`` event payload.'
    row = conn.execute(
        "SELECT payload FROM events WHERE kind = 'scan.wave.completed' "
        "ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if row is None or not row[0]:
        return None
    try:
        payload = json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    current = payload.get("wave")
    if not isinstance(current, int) or isinstance(current, bool):
        return None
    tools_done = tools_total = findings_new = 0
    rules = payload.get("rules")
    if isinstance(rules, dict):
        for stats in rules.values():
            if not isinstance(stats, dict):
                continue
            tools_done += stats.get("done", 0) if isinstance(stats.get("done"), int) else 0
            tools_total += stats.get("runs", 0) if isinstance(stats.get("runs"), int) else 0
            findings_new += (stats.get("discoveries", 0)
                             if isinstance(stats.get("discoveries"), int) else 0)
    return WaveProgress(current=current, total=current, tools_done=tools_done,
                        tools_total=tools_total, findings_new=findings_new,
                        eta_s=None)


def _stuck_testing_age(conn: sqlite3.Connection, eng_id: str,
                       now: float) -> float | None:
    """Age (seconds) of the oldest stranded ``testing`` hypothesis.

    Mirrors the engine's own definition (core/graph_health.py
    ``_check_stuck_testing``): the hypothesis is in ``testing``, HAS at least
    one tool_run, and NONE of its tool_runs is in flight
    (``pending``/``queued``/``running`` — engine terminal statuses are
    ``done``/``error``/``timeout``). A hypothesis that was never dispatched
    is legitimately testing and must not count.

    The age anchor is ``entities.updated_at`` — the engine's only per-entity
    timestamp; a stranded hypothesis sees no further writes, so it
    approximates "how long since anything last happened to it". Rows are
    ordered lexicographically (engine ISO timestamps sort correctly).
    """
    placeholders = ",".join("?" for _ in INFLIGHT_STATUSES)
    row = conn.execute(
        "SELECT h.updated_at FROM entities h "
        "WHERE h.kind = 'hypothesis' AND h.state = 'testing' "
        "AND h.engagement_id = ? "
        "AND EXISTS (SELECT 1 FROM tool_run tr WHERE tr.hypothesis_id = h.id) "
        "AND NOT EXISTS (SELECT 1 FROM tool_run tr WHERE tr.hypothesis_id = h.id "
        f"AND tr.status IN ({placeholders})) "
        "ORDER BY h.updated_at ASC LIMIT 1",
        (eng_id, *INFLIGHT_STATUSES),
    ).fetchone()
    if row is None:
        return None
    updated = _parse_iso_ts(row[0])
    if updated is None:
        return None  # unageable: honest "no data", never a fake 0
    return max(0.0, now - updated)


class GraphCollector:
    """Read-only SQLite facts per engagement, with per-engagement cursors."""

    def __init__(self, root: Path, *, now: float | None = None,
                 runtime_root: Path | None = None,
                 tail_size: int = TAIL_SIZE) -> None:
        self.root = Path(root)
        self.runtime_root = Path(runtime_root) if runtime_root is not None else self.root / "tasks"
        self._now = now
        self._tail_size = tail_size
        self._cursors: dict[str, int] = {}
        self._tails: dict[str, tuple[Event, ...]] = {}
        self._stuck_cache: dict[str, tuple[float, float | None]] = {}
        # Sticky per-engagement canary latch: True once an
        # ``opsec_canary_skip`` row has been read for the engagement. The
        # feed is cursor-incremental (a canary row is read exactly once), so
        # the flag must latch or it would flicker off on the next tick.
        # Honesty boundary: the latch covers this collector session only —
        # a restart rescans the newest TAIL_SIZE events, so a trip older
        # than that window resets the flag (documented v1 gap, not faked).
        self._canary: dict[str, bool] = {}

    def retain_engagements(self, engagement_ids: set[str]) -> None:
        """Forget streams removed from the task root before reusing their ids."""
        for cache in (self._cursors, self._tails, self._stuck_cache, self._canary):
            for gone in cache.keys() - engagement_ids:
                del cache[gone]

    def _stuck_age(self, conn: sqlite3.Connection, eng_id: str,
                   now: float) -> float | None:
        """``STUCK_TTL_S``-cached wrapper: the query is correlated and runs
        per engagement per frame on the long-lived collector instance."""
        cached = self._stuck_cache.get(eng_id)
        if cached is not None and now - cached[0] < STUCK_TTL_S:
            return cached[1]
        age = _stuck_testing_age(conn, eng_id, now)
        self._stuck_cache[eng_id] = (now, age)
        return age

    def collect(self, eng_id: str, *, sealed: bool) -> GraphFacts:
        """Collect one engagement; any SQLite failure yields empty facts."""
        db_path = self.runtime_root / eng_id / "graph.db"
        if not db_path.is_file():
            # A directory without graph.db is a fresh engagement, not an
            # error condition — the file appears when the engine first writes.
            return GraphFacts(id=eng_id,
                              canary_tripped=self._canary.get(eng_id, False))
        try:
            conn = _connect(db_path, sealed=sealed)
        except sqlite3.Error as exc:
            return GraphFacts(id=eng_id,
                              error=f"open failed: {type(exc).__name__}",
                              canary_tripped=self._canary.get(eng_id, False))
        try:
            return self._collect_connected(conn, eng_id)
        except sqlite3.Error as exc:
            # Locked, corrupted, or schema drift: degrade to empty, never raise.
            # The canary latch survives: a trip already observed stays lit
            # while the database is momentarily unreadable.
            return GraphFacts(id=eng_id, error=f"{type(exc).__name__}",
                              canary_tripped=self._canary.get(eng_id, False))
        finally:
            conn.close()

    def _collect_connected(self, conn: sqlite3.Connection, eng_id: str) -> GraphFacts:
        now = self._now if self._now is not None else datetime.now(
            UTC).timestamp()
        hyps = _state_counts(conn, eng_id, "hypothesis", HYP_STATES)
        findings = _state_counts(conn, eng_id, "finding", FINDING_STATES)
        events, cursor = _events_tail(conn, eng_id, self._cursors.get(eng_id),
                                      self._tail_size)
        # Keep history for engagements the UI has not selected yet, and for
        # idle ticks. SQLite still reads only rows after the per-stream cursor.
        tail = (self._tails.get(eng_id, ()) + events)[-self._tail_size:]
        inflight = _inflight(conn, now)
        wave = _wave_progress(conn)
        stuck_age = self._stuck_age(conn, eng_id, now)
        # Advance only after every query succeeds, so a transient read failure
        # cannot consume events that never reached a complete snapshot.
        self._cursors[eng_id] = cursor
        self._tails[eng_id] = tail
        tripped = (self._canary.get(eng_id, False)
                   or any(event.kind == CANARY_EVENT_KIND for event in events))
        self._canary[eng_id] = tripped
        return GraphFacts(
            id=eng_id,
            hyps=hyps,
            findings=findings,
            events_tail=tail,
            events_head_seq=cursor,
            inflight=inflight,
            wave=wave,
            stuck_testing_s=stuck_age,
            canary_tripped=tripped,
        )
