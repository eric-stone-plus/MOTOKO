"""Single-writer database layer for the MOTOKO attack graph.

The orchestrator process is the ONLY writer. Everything else (digest,
queries, inspection) opens the DB read-only. WAL + a long busy_timeout make
concurrent readers safe against the single writer.

State lives on disk here — never in the LLM context. ``events`` is the
append-only source of truth; ``entities`` is a materialized view updated by
the writer, so crash recovery = replay ``events``.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from . import schema, state_machine, util


def default_root() -> Path:
    """Data root for engagements.

    Honors ``MOTOKO_HOME``; otherwise ``<motoko_root>/engagements``, which
    stays inside the authorized Development tree (this host is zero-write
    outside it). On a headless deploy server, set MOTOKO_HOME to the
    persistent engagement root.

    The root is derived from the package location (see ``util.motoko_root``),
    not hardcoded: the 2026-09-13 tree move broke the previous absolute
    default, and it failed silently as a missing directory.
    """
    env = os.environ.get("MOTOKO_HOME")
    if env:
        return Path(env).expanduser()
    return util.motoko_root() / "engagements"


def engagement_dir(root: Path, engagement_id: str) -> Path:
    return root / engagement_id


def _connect(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        uri = f"file:{path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=30.0)
    else:
        conn = sqlite3.connect(str(path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_engagement(
    root: Path,
    engagement_id: str,
    *,
    name: str = "",
    in_scope: list[str] | None = None,
    out_of_scope: list[str] | None = None,
    intensity: str = "normal",
    max_depth: int = 3,
    concurrency: int = 4,
    oob_domain: str | None = None,
    config: dict | None = None,
) -> Path:
    """Create an engagement directory + graph.db, seed the scope row.

    Returns the path to the engagement directory. Idempotent: calling twice
    with the same id returns the existing directory without clobbering.
    """
    edir = engagement_dir(root, engagement_id)
    edir.mkdir(parents=True, exist_ok=True)
    for sub in ("obs", "evidence"):
        (edir / sub).mkdir(exist_ok=True)

    db_path = edir / "graph.db"
    db = Database(db_path)
    db.init_schema()
    db.set_scope(
        engagement_id,
        name=name,
        in_scope=in_scope or [],
        out_of_scope=out_of_scope or [],
        intensity=intensity,
        max_depth=max_depth,
        concurrency=concurrency,
        oob_domain=oob_domain,
        config=config or {},
    )
    db.close()
    return edir


class Database:
    """Single-writer handle over one ``graph.db``."""

    # Typed metadata columns. Everything else in an entity dict is a domain
    # field and is serialized into the ``data`` column.
    META_KEYS = frozenset({
        "id", "kind", "engagement_id", "state", "confidence",
        "priority", "dedup_key", "created_at", "updated_at",
    })

    def __init__(self, db_path: Path | str, *, read_only: bool = False):
        self.path = Path(db_path)
        self.read_only = read_only
        self.conn = _connect(self.path, read_only=read_only)

    # -- lifecycle ------------------------------------------------------
    def init_schema(self) -> None:
        if self.read_only:
            raise RuntimeError("cannot init schema on a read-only connection")
        with self.conn:
            for stmt in schema.schema_statements():
                self.conn.execute(stmt)
            self._migrate()
            self.conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(schema.SCHEMA_VERSION),),
            )

    def _migrate(self) -> None:
        """Additive migrations for a DB created by an older schema version.

        CREATE TABLE IF NOT EXISTS never alters an existing table, so new
        columns are added here. Runs inside ``init_schema``'s transaction.
        """
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(observations)")}
        for name, decl in (("url", "TEXT"), ("host", "TEXT"), ("processed_at", "TEXT")):
            if name not in cols:
                self.conn.execute(f"ALTER TABLE observations ADD COLUMN {name} {decl}")

    def close(self) -> None:
        self.conn.close()

    def commit(self) -> None:
        if self.read_only:
            raise RuntimeError("cannot commit on a read-only connection")
        self.conn.commit()

    # -- events (source of truth) --------------------------------------
    def _insert_event(self, kind: str, entity_id: str | None, payload: dict | None) -> None:
        """Insert one event row on the CURRENT connection (no commit).

        Every graph mutation MUST call this inside the same ``with self.conn:``
        block as the entity/edge write (F07): the materialized view and the
        append-only log can never drift, a crash rolls back both.
        """
        self.conn.execute(
            "INSERT INTO events(at, kind, entity_id, payload) VALUES(?,?,?,?)",
            (util.now_iso(), kind, entity_id, json.dumps(payload, ensure_ascii=False)),
        )

    def append_event(self, kind: str, entity_id: str | None, payload: dict | None = None) -> None:
        """Standalone event append (own transaction). Use ``_insert_event``
        when the event must be atomic with a graph write."""
        if self.read_only:
            raise RuntimeError("append_event requires the writer connection")
        with self.conn:
            self._insert_event(kind, entity_id, payload)

    def _row_snapshot(self, entity_id: str) -> dict:
        """Full entity snapshot for the event log (F08).

        Carries every typed column plus the parsed ``data`` fields, so
        replaying the events alone can rebuild the entity — including its
        domain data (class/url/tech/...), not just {kind, state}.
        """
        row = self.conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if row is None:
            return {}
        return {
            "id": row["id"],
            "kind": row["kind"],
            "engagement_id": row["engagement_id"],
            "state": row["state"],
            "confidence": row["confidence"],
            "priority": row["priority"],
            "dedup_key": row["dedup_key"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "data": json.loads(row["data"]) if row["data"] else {},
        }

    # -- entities (materialized view) -----------------------------------
    def upsert_entity(self, data: dict) -> str:
        """Insert or update an entity and record the event.

        ``data`` is the full flat entity dict. Typed metadata (id/kind/
        engagement_id/state/confidence/priority/dedup_key) goes into columns
        (single source of truth for state); everything else — the domain
        fields — is serialized into the ``data`` column.
        """
        if self.read_only:
            raise RuntimeError("upsert_entity requires the writer connection")
        eid = data["id"]
        kind = data["kind"]
        now = util.now_iso()
        created = data.get("created_at", now)
        with self.conn:
            row = self.conn.execute(
                "SELECT kind, state FROM entities WHERE id = ?", (eid,)).fetchone()
            # F50 / R3 P0-2: an entity's kind is frozen once written. Without
            # this, an upsert carrying an existing id under another kind
            # (e.g. a proposal aimed at a finding id) re-purposes the row and
            # the append-only log stops describing what happened.
            if row is not None and row["kind"] != kind:
                raise ValueError(
                    f"entity {eid!r} already exists as kind {row['kind']!r}; "
                    f"refusing to change it to {kind!r} (kind is frozen)")
            # F06: a finding's state is owned by ``advance_and_persist``. An
            # upsert may create it as 'candidate'; it may NEVER promote it.
            if kind == "finding":
                data = dict(data)
                incoming = data.get("state")
                if row is None:
                    if incoming not in (None, "candidate"):
                        raise ValueError(
                            f"finding {eid!r} must be created as 'candidate', not {incoming!r}; "
                            f"promotions go through advance_and_persist")
                    data["state"] = incoming or "candidate"
                else:
                    if incoming is not None and incoming != row["state"]:
                        raise ValueError(
                            f"finding {eid!r} state change {row['state']!r} -> {incoming!r} "
                            f"must go through advance_and_persist")
                    data["state"] = row["state"] if incoming is None else incoming
            domain = {k: v for k, v in data.items() if k not in self.META_KEYS}
            self.conn.execute(
                """
                INSERT INTO entities(id, kind, engagement_id, state, confidence,
                                     priority, dedup_key, data, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    state=excluded.state,
                    confidence=excluded.confidence,
                    priority=excluded.priority,
                    dedup_key=excluded.dedup_key,
                    data=excluded.data,
                    updated_at=excluded.updated_at
                """,
                (
                    eid,
                    kind,
                    data.get("engagement_id", ""),
                    data.get("state"),
                    data.get("confidence"),
                    data.get("priority"),
                    data.get("dedup_key"),
                    json.dumps(domain, ensure_ascii=False),
                    created,
                    now,
                ),
            )
            # F07: the event goes in the SAME transaction as the write.
            snapshot = self._row_snapshot(eid)
            self._insert_event("entity.upsert", eid, {
                "kind": kind,
                "state": snapshot.get("state"),
                "snapshot": snapshot,   # F08: full entity, not just {kind, state}
            })
        return eid

    def get_entity(self, entity_id: str) -> dict | None:
        """Return the full flat entity dict (domain fields + typed metadata).

        ``data`` column holds domain fields only; typed columns are merged
        back on read so ``state`` has a single source of truth.
        """
        row = self.conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if row is None:
            return None
        return self._hydrate(row)

    def query_entities(self, *, kind: str | None = None, state: str | None = None,
                       engagement_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM entities WHERE 1=1"
        args: list = []
        if kind is not None:
            sql += " AND kind = ?"
            args.append(kind)
        if state is not None:
            sql += " AND state = ?"
            args.append(state)
        if engagement_id is not None:
            sql += " AND engagement_id = ?"
            args.append(engagement_id)
        return [self._hydrate(r) for r in self.conn.execute(sql, args)]

    @staticmethod
    def _hydrate(row: sqlite3.Row) -> dict:
        d = json.loads(row["data"]) if row["data"] else {}
        d.update({
            "id": row["id"],
            "kind": row["kind"],
            "engagement_id": row["engagement_id"],
            "state": row["state"],
            "confidence": row["confidence"],
            "priority": row["priority"],
            "dedup_key": row["dedup_key"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
        return d

    def advance_and_persist(self, entity_id: str, event: str, *,
                            actor: str = "validator", verdict=None,
                            payload: dict | None = None) -> tuple[bool, str]:
        """THE state-change entry point for findings (F06).

        Loads the entity, runs it through ``state_machine``, then persists the
        new state + signals + confidence and the transition event (full
        snapshot, F08) in ONE transaction. Returns ``(ok, reason)`` — an
        illegal event or a missing row reports failure instead of raising, so
        the main loop can record it and move on (F30).

        F29: the row is checked first; nothing is written for a missing id.
        """
        if self.read_only:
            raise RuntimeError("advance_and_persist requires the writer connection")
        row = self.conn.execute(
            "SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if row is None:
            return False, f"no such entity: {entity_id}"
        entity = self._hydrate(row)
        if entity.get("kind") != "finding":
            return False, (f"no finding state machine for kind "
                           f"{entity.get('kind')!r} ({entity_id})")
        try:
            state_machine.advance(entity, event, actor=actor, verdict=verdict)
        except (state_machine.InvalidTransition, state_machine.ForbiddenActor,
                ValueError) as e:
            return False, str(e)

        with self.conn:
            domain = {k: v for k, v in entity.items() if k not in self.META_KEYS}
            cur = self.conn.execute(
                "UPDATE entities SET state=?, confidence=?, data=?, updated_at=? "
                "WHERE id=? AND state IS ?",
                (entity["state"], entity.get("confidence"),
                 json.dumps(domain, ensure_ascii=False), util.now_iso(),
                 entity_id, row["state"]),
            )
            if cur.rowcount != 1:
                return False, "entity state changed under the transition; aborted"
            snapshot = self._row_snapshot(entity_id)
            self._insert_event("entity.transition", entity_id, {
                **(payload or {}),
                "from": row["state"],
                "to": entity["state"],
                "by": actor,
                "verdict": self._verdict_payload(verdict),
                "snapshot": snapshot,
            })
        return True, ""

    @staticmethod
    def _verdict_payload(verdict) -> dict | None:
        """Audit form of a validator Verdict (never taken as a signal source)."""
        if verdict is None:
            return None
        return {
            "event": getattr(verdict, "event", None),
            "detail": getattr(verdict, "detail", ""),
            "signals": list(getattr(verdict, "signals", []) or []),
            "evidence": dict(getattr(verdict, "evidence", {}) or {}),
        }

    def set_priority(self, entity_id: str, priority: float, *,
                     event_kind: str = "entity.priority") -> bool:
        """Update ONLY the priority column (proposal path for the reflector).

        Deliberately cannot touch ``state`` or domain data; records its own
        event in the same transaction.
        """
        if self.read_only:
            raise RuntimeError("set_priority requires the writer connection")
        with self.conn:
            row = self.conn.execute(
                "SELECT priority FROM entities WHERE id = ?", (entity_id,)).fetchone()
            if row is None:
                return False
            self.conn.execute(
                "UPDATE entities SET priority=?, updated_at=? WHERE id=?",
                (float(priority), util.now_iso(), entity_id),
            )
            self._insert_event(event_kind, entity_id,
                               {"priority": float(priority), "previous": row["priority"]})
        return True

    # -- edges ----------------------------------------------------------
    def add_edge(self, from_id: str, to_id: str, rel: str, *,
                 engagement_id: str = "", action_id: str | None = None,
                 data: dict | None = None) -> str:
        if rel not in schema.EDGE_RELS:
            raise ValueError(f"unknown edge rel: {rel}")
        if self.read_only:
            raise RuntimeError("add_edge requires the writer connection")
        eid = util.new_id("edge")
        with self.conn:
            self.conn.execute(
                "INSERT INTO edges(id, engagement_id, from_id, to_id, rel, action_id, data, created_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (eid, engagement_id, from_id, to_id, rel, action_id,
                 json.dumps(data, ensure_ascii=False) if data else None, util.now_iso()),
            )
            # F07: event and edge in one transaction.
            self._insert_event("edge.added", eid,
                               {"from": from_id, "to": to_id, "rel": rel,
                                "engagement_id": engagement_id})
        return eid

    def get_edges(self, from_id: str | None = None, to_id: str | None = None,
                  rel: str | None = None) -> list[dict]:
        sql = "SELECT * FROM edges WHERE 1=1"
        args: list = []
        if from_id is not None:
            sql += " AND from_id = ?"
            args.append(from_id)
        if to_id is not None:
            sql += " AND to_id = ?"
            args.append(to_id)
        if rel is not None:
            sql += " AND rel = ?"
            args.append(rel)
        return [dict(r) for r in self.conn.execute(sql, args)]

    # -- services -------------------------------------------------------
    def add_service(self, data: dict) -> str:
        sid = data.get("id") or util.new_id("service")
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO services(id, asset_id, port, protocol, service_name, "
                "product, version, cpe, banner, fingerprint, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (sid, data.get("asset_id", ""), data.get("port"), data.get("protocol"),
                 data.get("service_name"), data.get("product"), data.get("version"),
                 data.get("cpe"), data.get("banner"), data.get("fingerprint"),
                 data.get("created_at", util.now_iso())),
            )
        return sid

    def get_services(self, asset_id: str | None = None) -> list[dict]:
        if asset_id is None:
            return [dict(r) for r in self.conn.execute("SELECT * FROM services")]
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM services WHERE asset_id = ?", (asset_id,))]

    # -- scope ----------------------------------------------------------
    def set_scope(self, engagement_id: str, *, name: str, in_scope: list[str],
                  out_of_scope: list[str], intensity: str, max_depth: int,
                  concurrency: int, oob_domain: str | None, config: dict) -> None:
        if self.read_only:
            raise RuntimeError("set_scope requires the writer connection")
        now = util.now_iso()
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO scope(engagement_id, name, in_scope, out_of_scope, "
                "intensity, max_depth, concurrency, oob_domain, config, created_at, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (engagement_id, name, json.dumps(in_scope), json.dumps(out_of_scope),
                 intensity, max_depth, concurrency, oob_domain, json.dumps(config), now, now),
            )
            # R3 H1: the event goes in the SAME transaction as the scope row
            # (F07) — a crash between the two must roll both back, never
            # leave a row the append-only log does not know about.
            self._insert_event("scope.set", engagement_id, {"name": name})

    def get_scope(self, engagement_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM scope WHERE engagement_id = ?", (engagement_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["in_scope"] = json.loads(d["in_scope"])
        d["out_of_scope"] = json.loads(d["out_of_scope"])
        d["config"] = json.loads(d["config"]) if d["config"] else {}
        return d

    # -- tool_run -------------------------------------------------------
    def tool_run_hypothesis(self, run_id: str) -> str | None:
        """The hypothesis a tool_run belongs to (R7-3 source stamping)."""
        row = self.conn.execute(
            "SELECT hypothesis_id FROM tool_run WHERE id = ?", (run_id,)).fetchone()
        return row["hypothesis_id"] if row else None

    def start_tool_run(self, *, tool: str, command: str, hypothesis_id: str | None = None,
                       action_id: str | None = None) -> str:
        rid = util.new_id("tool_run")
        with self.conn:
            self.conn.execute(
                "INSERT INTO tool_run(id, hypothesis_id, action_id, tool, command, "
                "status, started_at, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (rid, hypothesis_id, action_id, tool, command, "running", util.now_iso(), util.now_iso()),
            )
        return rid

    def finish_tool_run(self, run_id: str, *, status: str, exit_code: int | None,
                        stdout_ref: str | None = None, stderr_ref: str | None = None) -> None:
        if status not in schema.TOOL_RUN_STATES:
            raise ValueError(f"bad tool_run status: {status}")
        with self.conn:
            self.conn.execute(
                "UPDATE tool_run SET status=?, exit_code=?, stdout_ref=?, stderr_ref=?, "
                "finished_at=? WHERE id=?",
                (status, exit_code, stdout_ref, stderr_ref, util.now_iso(), run_id),
            )

    def set_tool_run_pid(self, run_id: str, pid: int) -> None:
        with self.conn:
            self.conn.execute("UPDATE tool_run SET pid=? WHERE id=?", (pid, run_id))

    # -- scan_cache -----------------------------------------------------
    def cache_lookup(self, cache_key: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM scan_cache WHERE cache_key = ?", (cache_key,)).fetchone()
        return dict(row) if row else None

    def cache_put(self, cache_key: str, *, asset_id: str, tool: str,
                  result_hash: str, ttl_hours: int = 72) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO scan_cache(cache_key, asset_id, tool, result_hash, scanned_at, ttl_hours) "
                "VALUES(?,?,?,?,?,?)",
                (cache_key, asset_id, tool, result_hash, util.now_iso(), ttl_hours),
            )

    # -- observations ---------------------------------------------------
    def record_observation(self, *, tool: str, engagement_id: str, raw_path: str | None,
                           parsed_summary: str, new_asset_ids: list[str] | None = None,
                           new_finding_ids: list[str] | None = None, exit_code: int | None = None,
                           duration_s: float | None = None, action_id: str | None = None,
                           url: str | None = None, host: str | None = None) -> str:
        """Record one tool invocation. ``url``/``host`` carry the action's
        target context so a parser that sees no URL in the output can still
        tie its findings to a target (F13). ``processed_at`` stays NULL until
        ``_sync`` ingests it (F12)."""
        oid = util.new_id("observation")
        with self.conn:
            self.conn.execute(
                "INSERT INTO observations(id, engagement_id, action_id, tool, raw_path, "
                "parsed_summary, new_asset_ids, new_finding_ids, exit_code, duration_s, "
                "url, host, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (oid, engagement_id, action_id, tool, raw_path, parsed_summary,
                 json.dumps(new_asset_ids or []), json.dumps(new_finding_ids or []),
                 exit_code, duration_s, url, host, util.now_iso()),
            )
        return oid

    def unprocessed_observations(self, engagement_id: str) -> list[dict]:
        """Observations not yet ingested (F12)."""
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM observations WHERE engagement_id = ? AND processed_at IS NULL "
            "ORDER BY created_at", (engagement_id,))]

    def mark_observation_processed(self, obs_id: str) -> bool:
        """Flag an observation as ingested so the next cycle skips it (F12)."""
        if self.read_only:
            raise RuntimeError("mark_observation_processed requires the writer connection")
        with self.conn:
            cur = self.conn.execute(
                "UPDATE observations SET processed_at = ? WHERE id = ? AND processed_at IS NULL",
                (util.now_iso(), obs_id))
        return cur.rowcount == 1

    def update_observation_summary(self, obs_id: str, summary: str) -> None:
        """R6-1: write the parser's summary back to the observation row so the
        loop can tell 'tool produced nothing' from 'parser dropped it'."""
        with self.conn:
            self.conn.execute(
                "UPDATE observations SET parsed_summary = ? WHERE id = ?",
                (summary[:2000], obs_id))

    def bump_duplicate_count(self, entity_id: str, *,
                              event_kind: str = "finding.duplicate_seen") -> int | None:
        """Increment a finding's duplicate counter (F15).

        Touches domain data only — never the state — and records the event in
        the same transaction. Returns the new count, or None if the row is gone.
        """
        if self.read_only:
            raise RuntimeError("bump_duplicate_count requires the writer connection")
        with self.conn:
            row = self.conn.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
            if row is None:
                return None
            entity = self._hydrate(row)
            count = int(entity.get("duplicate_count") or 0) + 1
            entity["duplicate_count"] = count
            domain = {k: v for k, v in entity.items() if k not in self.META_KEYS}
            self.conn.execute(
                "UPDATE entities SET data = ?, updated_at = ? WHERE id = ?",
                (json.dumps(domain, ensure_ascii=False), util.now_iso(), entity_id))
            self._insert_event(event_kind, entity_id, {"duplicate_count": count})
        return count
