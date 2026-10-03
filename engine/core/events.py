"""Strict read path over the append-only event log.

``events`` is the source of truth and every materialized table is a view of
it, so the log has to be readable on its own terms. This module is that read,
and the gate that keeps the claim honest:

* ``insert_row`` — the single write funnel. ``db.Database._insert_event``,
  ``db.Database.append_event``, seal's pre-hash insert and the failure path's
  timeout stamp all land here, so the declared vocabulary in
  ``schema.EVENT_KINDS`` is enforced at every write site instead of by
  convention. An undeclared kind raises rather than widening the log.
* ``read_events`` — the strict read. No row is trusted: a payload that does
  not parse becomes a reported violation carrying its raw text, never an
  exception out of a query and never a silently skipped row.
* ``fold`` — replay. Snapshot-bearing kinds carry the post-image of the row
  they mutated, so folding the log in seq order reconstructs every materialized
  table; the two delta kinds (priority, duplicate count) carry their changed
  value and apply over the last snapshot.
* ``verify`` — the invariants behind ``motoko events --verify``: sequence
  continuity, the kind vocabulary, each kind's declared reference domain,
  payload integrity, state-machine legality and transition-chain continuity,
  edge parity in both directions, and fold-equals-materialized for every
  sourced table. A violation fails the command. Rows written before the
  absorbed tables joined the log are graded by ``event_sourcing_since_at``
  and reported as warnings, because a version-2 database cannot have events
  it was never asked to write.
* ``rebuild`` — crash recovery as an executable claim: copy the log verbatim,
  materialize every table from the fold, then verify the result. It writes a
  NEW database in an empty destination and refuses an occupied one; nothing
  in this module ever writes to a live engagement.

``scan_cache`` is the one table outside the log, by design — ``schema.py``
names it in ``EVENT_UNSOURCED_TABLES``. A TTL-bounded memo is disposable
state that a re-scan reproduces, and an append-only log must not carry rows
that are meant to expire.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import schema, state_machine, util

#: Reference domain -> (table, primary key column) for the id an event's
#: ``entity_id`` column holds. The log has no engagement column, so the domain
#: is per kind and declared in ``schema.EVENT_ENTITY_DOMAINS``.
_DOMAIN_TABLES: dict[str, tuple[str, str]] = {
    "entity": ("entities", "id"),
    "entity_or_none": ("entities", "id"),
    "edge": ("edges", "id"),
    "observation": ("observations", "id"),
    "service": ("services", "id"),
    "tool_run": ("tool_run", "id"),
}

#: Tables a fold materializes, with their primary key column. ``scope`` is
#: keyed by engagement, everything else by id.
SOURCED_TABLES: dict[str, str] = {
    "entities": "id",
    "edges": "id",
    "services": "id",
    "observations": "id",
    "tool_run": "id",
    "scope": "engagement_id",
}

#: Columns compared between a folded row and the materialized one. ``at``-style
#: writer-clock columns are excluded where the log cannot reproduce them: a
#: delta event carries no post-image, so ``updated_at`` is only comparable up
#: to the entity's last snapshot (see ``EVENT_DELTA_KINDS``).
_ENTITY_COLUMNS = ("kind", "engagement_id", "state", "confidence", "priority",
                   "dedup_key", "created_at")


class EventVocabularyError(ValueError):
    """A writer tried to append a kind the schema does not declare."""


class RebuildRefused(RuntimeError):
    """The rebuild destination is not empty; nothing was written."""


# ---------------------------------------------------------------------------
# write funnel
# ---------------------------------------------------------------------------
def insert_row(conn: sqlite3.Connection, kind: str, entity_id: str | None,
               payload: dict | None, *, at: str | None = None) -> None:
    'Insert one event row on ``conn`` WITHOUT committing.'
    if kind not in schema.EVENT_KINDS:
        raise EventVocabularyError(
            f"undeclared event kind {kind!r} — the vocabulary lives in "
            f"schema.EVENT_ENTITY_DOMAINS; declare the kind with its entity_id "
            f"domain before appending it, or the log widens silently and no "
            f"reader can interpret the row")
    conn.execute(
        "INSERT INTO events(at, kind, entity_id, payload) VALUES(?,?,?,?)",
        (at or util.now_iso(), kind, entity_id,
         json.dumps(payload, ensure_ascii=False)))


# ---------------------------------------------------------------------------
# strict read
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Event:
    """One log row, parsed. ``corrupt`` is set instead of raising."""

    seq: int
    at: str
    kind: str
    entity_id: str | None
    payload: object
    raw: str | None = None
    corrupt: str | None = None

    @property
    def dict_payload(self) -> dict:
        """The payload when it is a JSON object, else an empty dict."""
        return self.payload if isinstance(self.payload, dict) else {}


def read_events(conn: sqlite3.Connection, *, since_seq: int = 0,
                kinds: frozenset[str] | set[str] | list[str] | None = None,
                entity_id: str | None = None, limit: int | None = None,
                descending: bool = False) -> list[Event]:
    """Read the log in seq order, parsing every payload strictly.

    A payload that does not parse is returned with ``corrupt`` set and its raw
    text preserved: the caller decides whether that is a report line or a
    gate failure, but no row is dropped and no query dies.
    """
    sql = "SELECT seq, at, kind, entity_id, payload FROM events WHERE seq > ?"
    args: list[object] = [int(since_seq)]
    if kinds:
        ordered = sorted(set(kinds))
        sql += f" AND kind IN ({','.join('?' * len(ordered))})"
        args.extend(ordered)
    if entity_id is not None:
        sql += " AND entity_id = ?"
        args.append(entity_id)
    sql += " ORDER BY seq " + ("DESC" if descending else "ASC")
    if limit is not None:
        sql += " LIMIT ?"
        args.append(int(limit))
    out: list[Event] = []
    for row in conn.execute(sql, args):
        raw = row["payload"]
        payload: object = None
        corrupt: str | None = None
        if raw is not None:
            try:
                payload = json.loads(raw)
            except (ValueError, TypeError) as exc:
                corrupt = f"{type(exc).__name__}: {exc}"
        out.append(Event(seq=row["seq"], at=row["at"], kind=row["kind"],
                         entity_id=row["entity_id"], payload=payload,
                         raw=raw, corrupt=corrupt))
    return out


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------
@dataclass
class Fold:
    """Materialized state reconstructed from the log alone."""

    rows: dict[str, dict[str, dict]] = field(default_factory=dict)
    edges: dict[str, dict] = field(default_factory=dict)
    #: (table, pk) -> seq of the last snapshot-bearing event, so a comparison
    #: knows whether the writer-clock column is reproducible
    snapshot_seq: dict[tuple[str, str], int] = field(default_factory=dict)
    #: (table, pk) -> True once a delta event applied over the last snapshot,
    #: which makes ``updated_at`` underivable from the log
    delta_after_snapshot: dict[tuple[str, str], bool] = field(default_factory=dict)
    transitions: dict[str, list[Event]] = field(default_factory=dict)
    #: edges folded from a pre-version-3 payload, which carries no post-image:
    #: only their four payload fields are comparable, and a rebuild restores
    #: them approximately
    legacy_edges: set[str] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    def table(self, name: str) -> dict[str, dict]:
        return self.rows.setdefault(name, {})


def fold(events: list[Event]) -> Fold:
    """Replay the log into materialized state.

    A snapshot-bearing event replaces the row wholesale — the post-image is
    the row as stored, so the fold is exact and ``rebuild`` can write it back.
    Two older shapes still have to replay, because the log is append-only and
    a version-2 database is still a database: an ``edge.added`` from before
    version 3 carries only its four payload fields, and an ``entity.priority``
    or ``finding.duplicate_seen`` from the same era carries only the changed
    value, which folds over the entity's last post-image. Every other kind
    describes an operational fact and mutates nothing.
    """
    f = Fold()
    for ev in events:
        f.counts[ev.kind] = f.counts.get(ev.kind, 0) + 1
        if ev.corrupt is not None:
            continue            # verify reports it; a fold cannot use it
        payload = ev.dict_payload
        if ev.kind == "entity.transition" and ev.entity_id:
            # collected whatever shape the payload has: a transition is the
            # state machine's evidence, and a snapshot-less one is exactly the
            # case the chain check has to be able to see
            f.transitions.setdefault(str(ev.entity_id), []).append(ev)
        table = schema.EVENT_TABLE_BY_KIND.get(ev.kind)
        if table is None:
            continue            # operational record: describes, does not mutate
        pk = SOURCED_TABLES[table]
        snap = payload.get("snapshot")
        if isinstance(snap, dict) and snap.get(pk) is not None:
            key = str(snap[pk])
            destination = f.edges if table == "edges" else f.table(table)
            destination[key] = dict(snap)
            f.snapshot_seq[(table, key)] = ev.seq
            f.delta_after_snapshot.pop((table, key), None)
            continue
        if ev.kind == "edge.added":
            if not ev.entity_id:
                f.problems.append(f"seq {ev.seq}: edge.added without an edge id")
                continue
            f.edges[ev.entity_id] = {
                "id": ev.entity_id,
                "from_id": payload.get("from"),
                "to_id": payload.get("to"),
                "rel": payload.get("rel"),
                "engagement_id": payload.get("engagement_id", ""),
                "created_at": ev.at,
            }
            f.legacy_edges.add(ev.entity_id)
            continue
        if ev.kind in schema.EVENT_DELTA_KINDS and ev.entity_id:
            row = f.table("entities").setdefault(ev.entity_id, {"id": ev.entity_id})
            if ev.kind == "entity.priority":
                priority = payload.get("priority")
                if isinstance(priority, (int, float)) and not isinstance(priority, bool):
                    row["priority"] = float(priority)
            else:
                count = payload.get("duplicate_count")
                if isinstance(count, int) and not isinstance(count, bool):
                    data = dict(row.get("data") or {})
                    data["duplicate_count"] = count
                    row["data"] = data
            f.delta_after_snapshot[("entities", ev.entity_id)] = True
            continue
        if ev.kind not in schema.EVENT_SNAPSHOT_KINDS:
            continue
        # No post-image, so the fold places nothing for this row; verify grades
        # the omission (a pre-version-3 writer was never asked for one) and
        # _check_tables reports the consequence.
    return f


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Issue:
    """One finding of the gate: a violated invariant or a graded warning."""

    check: str
    seq: int | None
    detail: str

    def to_dict(self) -> dict:
        return {"check": self.check, "seq": self.seq, "detail": self.detail}


@dataclass
class VerificationReport:
    """Result of ``verify`` — machine-readable, never raises on a dirty log."""

    graph: str
    engagement_id: str | None = None
    events: int = 0
    first_seq: int | None = None
    last_seq: int | None = None
    kinds: dict[str, int] = field(default_factory=dict)
    folded: dict[str, int] = field(default_factory=dict)
    materialized: dict[str, int] = field(default_factory=dict)
    violations: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "graph": self.graph,
            "engagement_id": self.engagement_id,
            "events": self.events,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "kinds": dict(sorted(self.kinds.items())),
            "folded": dict(sorted(self.folded.items())),
            "materialized": dict(sorted(self.materialized.items())),
            "violations": [i.to_dict() for i in self.violations],
            "warnings": [i.to_dict() for i in self.warnings],
        }


def _id_set(conn: sqlite3.Connection, table: str, column: str = "id") -> set[str]:
    assert table in SOURCED_TABLES or table == "events"
    return {r[0] for r in conn.execute(f"SELECT {column} FROM {table}") if r[0] is not None}


def _meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute(
        "SELECT value FROM schema_meta WHERE key = ?", (key,)).fetchone()
    return None if row is None else str(row[0])


def _rows(conn: sqlite3.Connection, table: str) -> list[dict]:
    assert table in SOURCED_TABLES
    return [dict(r) for r in conn.execute(f"SELECT * FROM {table}")]


def verify(conn: sqlite3.Connection, *, graph: str = "",
           engagement_id: str | None = None) -> VerificationReport:
    """Check every invariant the event-sourcing claim depends on.

    Read-only: it opens no writer lock and creates no sidecar, so it is safe
    against a live engagement and against a sealed artifact.
    """
    rep = VerificationReport(graph=graph, engagement_id=engagement_id)
    events = read_events(conn)
    rep.events = len(events)
    if events:
        rep.first_seq, rep.last_seq = events[0].seq, events[-1].seq
    folded = fold(events)
    rep.kinds = dict(sorted(folded.counts.items()))
    since = _since(conn)

    _check_sequence(events, rep)
    _check_vocabulary_and_payloads(events, since, rep)
    known = _reference_index(conn, rep)
    _check_references(events, known, engagement_id, rep)
    rep.folded = {t: len(folded.table(t)) for t in SOURCED_TABLES if t != "edges"}
    rep.folded["edges"] = len(folded.edges)
    for problem in folded.problems:
        rep.violations.append(Issue("replay", None, problem))
    _check_tables(conn, folded, since, rep)
    _check_edges(conn, folded, rep)
    _check_transitions(conn, folded, rep)
    _check_time_order(events, rep)
    return rep


def _check_sequence(events: list[Event], rep: VerificationReport) -> None:
    """seq is an AUTOINCREMENT primary key and rows are never deleted, so a
    contiguous run from 1 is the only shape a complete log has."""
    if not events:
        return
    if events[0].seq != 1:
        rep.violations.append(Issue(
            "seq_continuity", events[0].seq,
            f"the log starts at seq {events[0].seq}, not 1 — rows are missing "
            f"from the front (the tree never deletes, so this is a truncated "
            f"or reassembled database)"))
    expected = events[0].seq
    for ev in events:
        if ev.seq != expected:
            rep.violations.append(Issue(
                "seq_continuity", ev.seq,
                f"expected seq {expected}, found {ev.seq} — "
                f"{'a gap' if ev.seq > expected else 'a duplicate or reorder'}"))
            expected = ev.seq
        expected += 1


def _check_vocabulary_and_payloads(events: list[Event], since: str | None,
                                   rep: VerificationReport) -> None:
    for ev in events:
        if ev.kind not in schema.EVENT_KINDS:
            rep.violations.append(Issue(
                "kind_vocabulary", ev.seq,
                f"kind {ev.kind!r} is not declared in schema.EVENT_ENTITY_DOMAINS "
                f"— no reader can interpret this row"))
        if ev.corrupt is not None:
            rep.violations.append(Issue(
                "payload_integrity", ev.seq,
                f"payload does not parse ({ev.corrupt}); raw={str(ev.raw)[:200]!r}"))
            continue
        if ev.kind in schema.EVENT_SNAPSHOT_KINDS:
            table = schema.EVENT_TABLE_BY_KIND.get(ev.kind)
            snap = ev.dict_payload.get("snapshot")
            detail = (f"{ev.kind} must carry a snapshot post-image; got "
                      f"{type(snap).__name__}" if not isinstance(snap, dict)
                      else f"{ev.kind} snapshot has no {SOURCED_TABLES[table or '']} "
                           f"key — the row cannot be placed")
            if isinstance(snap, dict) and table and snap.get(SOURCED_TABLES[table]) is not None:
                continue
            if (ev.kind in schema.EVENT_SNAPSHOT_SINCE_V3 and since
                    and _earlier(ev.at, since)):
                rep.warnings.append(Issue("pre_event_sourcing", ev.seq, detail))
            else:
                rep.violations.append(Issue("payload_integrity", ev.seq, detail))


def _reference_index(conn: sqlite3.Connection,
                     rep: VerificationReport) -> dict[str, set[str]]:
    known: dict[str, set[str]] = {}
    for domain, (table, column) in _DOMAIN_TABLES.items():
        key = f"{table}.{column}"
        if key not in known:
            known[key] = _id_set(conn, table, column)
    engagements = set()
    for table in ("entities", "observations"):
        engagements |= {r[0] for r in conn.execute(
            f"SELECT DISTINCT engagement_id FROM {table}") if r[0]}
    engagements |= {r[0] for r in conn.execute(
        "SELECT engagement_id FROM scope") if r[0]}
    known["engagement"] = engagements
    return known


def _check_references(events: list[Event], known: dict[str, set[str]],
                      engagement_id: str | None, rep: VerificationReport) -> None:
    """Every row's ``entity_id`` must resolve in the table its kind declares.

    This is the entity-to-event half of the consistency claim: an event that
    points at nothing describes a subject the graph does not have, and an
    event pointing at ANOTHER engagement's subject means the log and the
    materialized view disagree about which campaign the row belongs to.
    """
    for ev in events:
        if ev.kind not in schema.EVENT_KINDS:
            continue                    # already reported by the vocabulary check
        domain = schema.EVENT_ENTITY_DOMAINS[ev.kind]
        if domain is None:
            if ev.entity_id is not None:
                rep.violations.append(Issue(
                    "reference_domain", ev.seq,
                    f"{ev.kind} is a log-wide marker and must carry no subject; "
                    f"got {ev.entity_id!r}"))
            continue
        if domain == "engagement":
            if not ev.entity_id:
                rep.violations.append(Issue(
                    "reference_domain", ev.seq,
                    f"{ev.kind} must name its engagement"))
            elif engagement_id and ev.entity_id != engagement_id:
                rep.violations.append(Issue(
                    "engagement_scope", ev.seq,
                    f"{ev.kind} belongs to engagement {ev.entity_id!r}, not the "
                    f"{engagement_id!r} under verification"))
            elif ev.entity_id not in known["engagement"]:
                rep.warnings.append(Issue(
                    "reference_domain", ev.seq,
                    f"{ev.kind} names engagement {ev.entity_id!r}, which has no "
                    f"entity, observation or scope row — an engagement that was "
                    f"initialized and then used for nothing"))
            continue
        table, column = _DOMAIN_TABLES[domain]
        if ev.entity_id is None:
            if domain != "entity_or_none":
                rep.violations.append(Issue(
                    "reference_domain", ev.seq,
                    f"{ev.kind} must reference a {table}.{column}; got NULL"))
            continue
        if ev.entity_id not in known[f"{table}.{column}"]:
            rep.violations.append(Issue(
                "reference_domain", ev.seq,
                f"{ev.kind} references {table}.{column}={ev.entity_id!r}, which "
                f"does not exist"))


def _parse_like(row: dict, column: str):
    """Parse a JSON TEXT column the way the reader does, for comparison."""
    raw = row.get(column)
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


def _check_tables(conn: sqlite3.Connection, folded: Fold, since: str | None,
                  rep: VerificationReport) -> None:
    """fold == materialized, both directions, for every sourced table."""
    for table, pk in SOURCED_TABLES.items():
        if table == "edges":
            continue                    # parity has its own check
        materialized = {str(r[pk]): r for r in _rows(conn, table) if r.get(pk)}
        rep.materialized[table] = len(materialized)
        replayed = folded.table(table)
        for key, row in materialized.items():
            got = replayed.get(key)
            if got is None:
                _report_unsourced(table, row, since, rep)
                continue
            _compare(table, key, row, got, folded, rep)
        for key in replayed.keys() - materialized.keys():
            rep.violations.append(Issue(
                "fold_materialized", None,
                f"{table} row {key!r} exists in the log but not in the table — "
                f"a materialized row was deleted, which this tree never does"))


def _since(conn: sqlite3.Connection) -> str | None:
    """The instant the absorbed tables joined the log (``db._migrate``)."""
    return _meta(conn, "event_sourcing_since_at")


def _instant(text: object) -> datetime | None:
    """Parse a stored timestamp into a comparable instant.

    The engine writes ``util.now_iso()`` everywhere, but a log can also hold a
    row from a dump, a restore or a hand edit — sqlite's own ``datetime('now')``
    spells the same instant with a space instead of a ``T`` and no offset at
    all. Comparing those as strings grades a row by its spelling rather than by
    its age (a space sorts before ``T``, so every such row looks older than
    every engine-written one). Both sides get parsed; an unparseable stamp
    yields None and the caller falls back to text order, which is the honest
    answer when one side cannot be read as a time.
    """
    if not isinstance(text, str) or not text:
        return None
    candidate = text.strip().replace("Z", "+00:00")
    if "T" not in candidate and " " in candidate:
        candidate = candidate.replace(" ", "T", 1)
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _earlier(left: object, right: object) -> bool:
    """True when ``left`` precedes ``right``; text order when either is unreadable."""
    first, second = _instant(left), _instant(right)
    if first is not None and second is not None:
        return first < second
    return bool(left) and bool(right) and str(left) < str(right)


def _report_unsourced(table: str, row: dict, since: str | None,
                      rep: VerificationReport) -> None:
    """A materialized row the log knows nothing about.

    For ``entities`` that is always a violation: the graph has been
    event-sourced since the first schema version, so a row without an event
    means a writer bypassed the log. For the absorbed tables it depends on
    when the row was written — before ``event_sourcing_since_at`` the engine
    did not ask for an event, and failing a database for that would be a gate
    measuring its own age.

    The boundary is a timestamp comparison, so it is only as precise as the
    stamps on both sides. The engine writes microseconds; a row written by
    something else (sqlite's own ``datetime('now')``, a dump, a hand edit) may
    carry whole seconds only, and such a row landing in the SAME second as the
    migration grades as pre-sourcing. That is the conservative direction — a
    row this gate cannot date precisely is reported, not failed — and it is
    not the anti-tamper boundary: ``seal``'s sha256 over graph.db is. A writer
    with raw SQL access to the graph can rewrite the stamp itself, so nothing
    here should be read as defending against one.
    """
    created = str(row.get("created_at") or "")
    if table == "entities":
        rep.violations.append(Issue(
            "fold_materialized", None,
            f"entities row {row.get('id')!r} has no event — a writer mutated "
            f"the materialized view outside the log"))
        return
    if since and created and _earlier(created, since):
        rep.warnings.append(Issue(
            "pre_event_sourcing", None,
            f"{table} row {row.get('id') or row.get('engagement_id')!r} predates "
            f"event sourcing of that table ({since}); it cannot be replayed"))
        return
    rep.violations.append(Issue(
        "fold_materialized", None,
        f"{table} row {row.get('id') or row.get('engagement_id')!r} has no "
        f"event — a writer mutated the table outside the log"))


def _compare(table: str, key: str, row: dict, got: dict, folded: Fold,
             rep: VerificationReport) -> None:
    """Field-wise comparison of one materialized row against its replay."""
    differs: list[str] = []
    if table == "entities":
        for column in _ENTITY_COLUMNS:
            if row.get(column) != got.get(column):
                differs.append(f"{column}: table={row.get(column)!r} log={got.get(column)!r}")
        if _parse_like(row, "data") != got.get("data"):
            differs.append("data differs")
        # A delta event carries no post-image, so the writer's updated_at is
        # not in the log; compare it only up to the last snapshot.
        if not folded.delta_after_snapshot.get(("entities", key)):
            if row.get("updated_at") != got.get("updated_at"):
                differs.append(
                    f"updated_at: table={row.get('updated_at')!r} "
                    f"log={got.get('updated_at')!r}")
    else:
        # Absorbed tables snapshot the row AS STORED, so every column
        # compares directly — including a JSON one, whose text the writer
        # produced and the fold preserved byte for byte.
        for column in row:
            if row.get(column) != got.get(column):
                differs.append(f"{column}: table={row.get(column)!r} log={got.get(column)!r}")
    if differs:
        rep.violations.append(Issue(
            "fold_materialized", folded.snapshot_seq.get((table, key)),
            f"{table} row {key!r} drifted from its replay: "
            + "; ".join(differs)))


def _check_edges(conn: sqlite3.Connection, folded: Fold,
                 rep: VerificationReport) -> None:
    """Both directions: no edge row without an event, no event without a row.

    An edge folded from a version-3 post-image compares on every column; one
    folded from an older payload compares on the four fields that payload
    carries, because the log genuinely does not hold the rest.
    """
    materialized = {str(r["id"]): r for r in _rows(conn, "edges")}
    rep.materialized["edges"] = len(materialized)
    for eid, row in materialized.items():
        got = folded.edges.get(eid)
        if got is None:
            rep.violations.append(Issue(
                "edge_parity", None,
                f"edges row {eid!r} has no edge.added event"))
            continue
        columns = (("from_id", "to_id", "rel", "engagement_id")
                   if eid in folded.legacy_edges else tuple(row))
        differs = [f"{c}: table={row.get(c)!r} log={got.get(c)!r}"
                   for c in columns if row.get(c) != got.get(c)]
        if differs:
            rep.violations.append(Issue(
                "edge_parity", folded.snapshot_seq.get(("edges", eid)),
                f"edge {eid!r} drifted from its replay: " + "; ".join(differs)))
    for eid in folded.edges.keys() - materialized.keys():
        rep.violations.append(Issue(
            "edge_parity", None,
            f"the log records edge {eid!r} but the table has no such row"))


def _check_transitions(conn: sqlite3.Connection, folded: Fold,
                       rep: VerificationReport) -> None:
    """A finding's recorded transitions must be a legal, contiguous path.

    Only findings are checked: the state machine in ``state_machine.py`` owns
    their vocabulary, while hypotheses and assets carry states no machine
    declares. The chain check runs for every kind, because a transition whose
    ``from`` is not the previous ``to`` means the log and the view disagree
    about history even when each step looks legal alone.
    """
    legal = state_machine.legal_transitions()
    kinds = {str(r["id"]): str(r["kind"]) for r in conn.execute(
        "SELECT id, kind FROM entities")}
    for entity_id, transitions in folded.transitions.items():
        previous_to = None
        for ev in sorted(transitions, key=lambda e: e.seq):
            payload = ev.dict_payload
            src, dst = payload.get("from"), payload.get("to")
            if previous_to is not None and src != previous_to:
                rep.violations.append(Issue(
                    "transition_chain", ev.seq,
                    f"{entity_id}: transition starts at {src!r} but the previous "
                    f"one ended at {previous_to!r} — the recorded history is not "
                    f"a path"))
            previous_to = dst
            if kinds.get(entity_id) != "finding":
                continue
            verdict = payload.get("verdict")
            name = verdict.get("event") if isinstance(verdict, dict) else None
            if name:
                try:
                    expected = state_machine.transition(str(src), str(name))
                except state_machine.InvalidTransition:
                    rep.violations.append(Issue(
                        "transition_legality", ev.seq,
                        f"{entity_id}: the machine has no ({src!r}, {name!r}) "
                        f"transition, yet the log records one"))
                    continue
                if expected != dst:
                    rep.violations.append(Issue(
                        "transition_legality", ev.seq,
                        f"{entity_id}: ({src!r}, {name!r}) yields {expected!r}, "
                        f"but the row records {dst!r}"))
            elif src != dst and (src, dst) not in legal:
                rep.violations.append(Issue(
                    "transition_legality", ev.seq,
                    f"{entity_id}: {src!r} -> {dst!r} is not a transition the "
                    f"machine declares, and the event names no driving signal"))


def _check_time_order(events: list[Event], rep: VerificationReport) -> None:
    """Timestamps come from one clock in one process, so they never go back.

    A warning, not a violation: the log's ordering authority is ``seq``, and a
    stepped host clock does not make the history wrong.
    """
    previous: Event | None = None
    for ev in events:
        if previous is not None and _earlier(ev.at, previous.at):
            rep.warnings.append(Issue(
                "time_order", ev.seq,
                f"seq {ev.seq} is stamped {ev.at}, earlier than seq "
                f"{previous.seq} at {previous.at}"))
        previous = ev


# ---------------------------------------------------------------------------
# rebuild: crash recovery as an executable claim
# ---------------------------------------------------------------------------
def rebuild(dest: Path | str, conn: sqlite3.Connection, *,
            engagement_id: str | None = None) -> dict:
    """Materialize a NEW graph.db from the log alone, then verify it.

    The log is copied verbatim (seq preserved, so the restored engagement
    keeps its audit trail and its continuity), every sourced table is written
    from the fold, and the result is passed back through ``verify`` — a
    rebuild that does not verify is a failure, not a database.

    Refuses an occupied destination: this restores INTO a fresh directory and
    never overwrites a live or sealed engagement.
    """
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise RebuildRefused(
            f"{dest} exists and is not empty — rebuild writes a NEW database "
            f"and never overwrites one; pick an empty destination")
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / "graph.db"
    if target.exists():
        raise RebuildRefused(f"{target} already exists")

    events = read_events(conn)
    folded = fold(events)
    out = sqlite3.connect(str(target))
    out.row_factory = sqlite3.Row
    try:
        with out:
            for stmt in schema.schema_statements():
                out.execute(stmt)
            for ev in events:
                out.execute(
                    "INSERT INTO events(seq, at, kind, entity_id, payload) "
                    "VALUES(?,?,?,?,?)",
                    (ev.seq, ev.at, ev.kind, ev.entity_id, ev.raw))
            written = _materialize(out, folded)
            out.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES(?,?)",
                ("schema_version", str(schema.SCHEMA_VERSION)))
            for key in ("event_sourcing_since_at",):
                value = _meta(conn, key)
                if value is not None:
                    out.execute(
                        "INSERT OR REPLACE INTO schema_meta(key, value) VALUES(?,?)",
                        (key, value))
            out.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES(?,?)",
                ("rebuilt_from_events", str(len(events))))
            out.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES(?,?)",
                ("rebuilt_at", util.now_iso()))
        report = verify(out, graph=str(target), engagement_id=engagement_id)
    finally:
        out.close()
    return {
        "path": str(target),
        "events": len(events),
        "written": written,
        "ok": report.ok,
        "violations": [i.to_dict() for i in report.violations],
        "warnings": len(report.warnings),
        "unsourced_tables": sorted(schema.EVENT_UNSOURCED_TABLES),
    }


def _materialize(out: sqlite3.Connection, folded: Fold) -> dict[str, int]:
    """Write every folded row back. Column lists come from the destination's
    own schema, so a column the log does not carry stays NULL rather than
    failing the insert.

    A value is written as the log holds it: text stays text, and a parsed
    structure is re-serialized the way the writer serialized it (same
    ``ensure_ascii=False``, same key order, because parsing preserved it). NULL
    stays NULL — coercing it to ``'{}'`` would invent a column value the log
    never witnessed, which is the one thing a restore must not do.
    """
    written: dict[str, int] = {}
    for table, pk in SOURCED_TABLES.items():
        rows = folded.edges if table == "edges" else folded.table(table)
        columns = [r["name"] for r in out.execute(f"PRAGMA table_info({table})")]
        assert pk in columns, f"{table} has no {pk} column"
        if not rows:
            written[table] = 0
            continue
        placeholders = ",".join("?" * len(columns))
        stmt = (f"INSERT OR REPLACE INTO {table}({','.join(columns)}) "
                f"VALUES({placeholders})")
        count = 0
        for row in rows.values():
            values = []
            for column in columns:
                value = row.get(column)
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)
                values.append(value)
            out.execute(stmt, values)
            count += 1
        written[table] = count
    return written
