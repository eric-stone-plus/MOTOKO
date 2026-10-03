'Single-file SQLite schema for the MOTOKO attack graph.\n\nAll JSON is stored as TEXT. IDs are sortable strings from ``util.new_id``.\n'

from __future__ import annotations

SCHEMA_VERSION = 3

# Entity kinds allowed in the `entities.kind` column. Keep in sync with
# util.PREFIX.
ENTITY_KINDS = (
    "asset",
    "finding",
    "hypothesis",
    "evidence",
    "access",
    "path",
)

# Valid `edges.rel` values — the semantic of the arrow.
EDGE_RELS = (
    "discovered_on",   # asset/finding was discovered on another asset
    "evidenced_by",    # finding <- evidence
    "triggered",       # hypothesis triggered by a finding
    "grants_access",   # -> access node (an exploit grants an access level)
    "escalates_to",    # access -> higher access
    "leads_to",        # finding/hypothesis -> next finding (generic chain)
    "duplicate_of",    # finding -> primary finding
    "refutes",         # evidence -> finding (falsification)
)

FINDING_STATES = (
    "candidate",
    "triaged",
    "reproduced",
    "verified",
    "exploitable",
    "confirmed_impact",
    "false_positive",
    "duplicate",
    "out_of_scope",
    "wont_test",
)

# tool_run.status values.
TOOL_RUN_STATES = ("pending", "running", "done", "error", "timeout")

# ---------------------------------------------------------------------------
# The event vocabulary — part of the schema, not a per-module convention
# ---------------------------------------------------------------------------
# `events` is the append-only source of truth and `entities`/`edges` are
# materialized views, so the set of kinds a writer may append is a contract.
# Two gates keep this table honest, one in each direction:
#
# * WRITE — `events.insert_row` (the single funnel behind
#   `db.Database._insert_event`, `db.Database.append_event` and seal's
#   pre-hash insert) refuses an undeclared kind, so a typo or a new marker
#   fails at the call site instead of silently widening the log.
# * READ — `motoko events --verify` (`core/events.py`) re-checks every stored
#   row against this table, which is how a database written by an older
#   engine, restored from a dump, or edited in place gets caught. A static
#   test derives the literals actually written in `core/` and fails on drift
#   in either direction.
#
# The value names what the row's `entity_id` column holds. The log has no
# engagement column, so the reference domain is per kind and `events.verify`
# resolves each row against the table that owns it:
#
#   "entity"          -> entities.id, required
#   "entity_or_none"  -> entities.id when present; NULL means the subject id
#                        was itself unavailable on an error path
#   "edge"            -> edges.id, required
#   "observation"     -> observations.id, required
#   "service"         -> services.id, required
#   "tool_run"        -> tool_run.id, required
#   "engagement"      -> the engagement id, required
#   None              -> always NULL (a log-wide marker)
EVENT_ENTITY_DOMAINS: dict[str, str | None] = {
    # -- graph mutations: the only writers of the materialized view --------
    "entity.upsert": "entity",
    "entity.transition": "entity",
    "entity.priority": "entity",
    "finding.duplicate_seen": "entity",
    "edge.added": "edge",
    # -- absorbed tables, event-sourced since schema version 3 ------------
    "service.upsert": "service",
    "observation.recorded": "observation",
    "observation.processed": "observation",
    "tool_run.transition": "tool_run",
    # -- engagement-wide markers ------------------------------------------
    "scope.set": "engagement",
    "scan.wave.completed": "engagement",
    "egress.rotate_required": "engagement",
    "graph_health": "engagement",
    "failure_recovery": "engagement",
    "reflector.error": "engagement",
    "reflector.proposal_refused": "engagement",
    "opsec_cooldown_restore_error": "engagement",
    "opsec_cooldown_persist_error": "engagement",
    # -- observation contract ---------------------------------------------
    "observation_dead_letter": "observation",
    "completeness_stamp_withheld": "observation",
    # -- log-wide markers, no single subject -------------------------------
    "engagement_sealed": None,
    "tool_run.broken_wrapper": None,
    # -- operational records on an entity ----------------------------------
    "act.dedup": "entity",
    "act.dependency_blocked": "entity",
    "act.dependency_invalid": "entity",
    "act.executor_error": "entity",
    "act.placeholder_refused": "entity",
    "act.template_invalid": "entity",
    "mint.placeholder_unsatisfiable": "entity",
    "mint.tool_broken_skip": "entity",
    "opsec_canary_skip": "entity",
    "opsec_cooldown_skip": "entity",
    "rule_hit_class": "entity",
    "rule_hit_class_skipped": "entity",
    "sync_runs_failed": "entity",
    "validation_error": "entity",
    "verification_unblocked": "entity",
    "waf_detected": "entity",
    # Error paths that fire precisely when the subject row is unusable, so
    # the id may legitimately be absent — but when present it must resolve.
    "hypothesis_retire_error": "entity_or_none",
    "rule_attempts_bump_error": "entity_or_none",
    "rule_hit_class_error": "entity_or_none",
    "scope_blocked": "entity_or_none",
    "verification_blocked": "entity_or_none",
}

#: Every kind a writer may append. `frozenset` so a membership test is O(1)
#: and an accidental mutation is impossible.
EVENT_KINDS = frozenset(EVENT_ENTITY_DOMAINS)

EVENT_SNAPSHOT_KINDS = frozenset({
    "entity.upsert", "entity.transition", "edge.added",
    "service.upsert", "observation.recorded", "observation.processed",
    "tool_run.transition", "scope.set",
})

EVENT_SNAPSHOT_SINCE_V3 = frozenset({
    "edge.added", "service.upsert", "observation.recorded",
    "observation.processed", "tool_run.transition", "scope.set",
})

#: Kinds that mutate an entity and, in a log written before schema version 3,
#: carried only the changed value. A payload like that is enough to fold but
#: not enough to reproduce the writer's `updated_at`, so `events.verify`
#: compares that column only up to the entity's last full post-image. Since
#: version 3 both writers attach a snapshot as well — the delta path survives
#: to read the old logs, not because the new ones need it.
EVENT_DELTA_KINDS = frozenset({"entity.priority", "finding.duplicate_seen"})

#: Kind -> the table its post-image rebuilds. This is what makes
#: `events.rebuild` a complete restore rather than a graph-only one. The two
#: delta kinds map here too: a post-image wins over the delta when present,
#: and the delta is the fallback for a pre-version-3 row.
EVENT_TABLE_BY_KIND: dict[str, str] = {
    "entity.upsert": "entities",
    "entity.transition": "entities",
    "entity.priority": "entities",
    "finding.duplicate_seen": "entities",
    "edge.added": "edges",
    "service.upsert": "services",
    "observation.recorded": "observations",
    "observation.processed": "observations",
    "tool_run.transition": "tool_run",
    "scope.set": "scope",
}

#: `scan_cache` is deliberately NOT event-sourced. It is a derived, TTL-bounded
#: memo of "this asset+tool+template was already scanned" — disposable state
#: that a re-scan reproduces, not part of what happened. Sourcing it would put
#: expiring rows into an append-only log that is never allowed to shrink.
EVENT_UNSOURCED_TABLES = frozenset({"scan_cache"})

_STATEMENTS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS entities (
        id            TEXT PRIMARY KEY,
        kind          TEXT NOT NULL,
        engagement_id TEXT NOT NULL,
        state         TEXT,
        confidence    REAL,
        priority      REAL,
        dedup_key     TEXT,
        data          TEXT NOT NULL,          -- full entity JSON
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_entities_kind_state ON entities(kind, state)",
    "CREATE INDEX IF NOT EXISTS idx_entities_dedup ON entities(dedup_key)",
    "CREATE INDEX IF NOT EXISTS idx_entities_engagement ON entities(engagement_id)",
    """
    CREATE TABLE IF NOT EXISTS edges (
        id            TEXT PRIMARY KEY,
        engagement_id TEXT NOT NULL,
        from_id       TEXT NOT NULL,
        to_id         TEXT NOT NULL,
        rel           TEXT NOT NULL,
        action_id     TEXT,
        data          TEXT,                   -- JSON metadata
        created_at    TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_id)",
    "CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_id)",
    """
    CREATE TABLE IF NOT EXISTS events (
        seq       INTEGER PRIMARY KEY AUTOINCREMENT,
        at        TEXT NOT NULL,
        kind      TEXT NOT NULL,              -- e.g. finding.transition, edge.added
        entity_id TEXT,
        payload   TEXT                        -- JSON
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS services (
        id          TEXT PRIMARY KEY,
        asset_id    TEXT NOT NULL,
        port        INTEGER,
        protocol    TEXT,
        service_name TEXT,
        product     TEXT,
        version     TEXT,
        cpe         TEXT,
        banner      TEXT,
        fingerprint TEXT,
        created_at  TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_services_asset ON services(asset_id)",
    """
    CREATE TABLE IF NOT EXISTS scope (
        engagement_id TEXT PRIMARY KEY,
        name          TEXT,
        in_scope      TEXT NOT NULL,          -- JSON list of domain/cidr
        out_of_scope  TEXT NOT NULL,          -- JSON list
        intensity     TEXT NOT NULL DEFAULT 'normal',  -- normal|aggressive|stealth
        max_depth     INTEGER NOT NULL DEFAULT 3,
        concurrency   INTEGER NOT NULL DEFAULT 4,
        oob_domain    TEXT,
        config        TEXT,                   -- JSON global config
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tool_run (
        id            TEXT PRIMARY KEY,
        hypothesis_id TEXT,
        action_id     TEXT,
        tool          TEXT NOT NULL,
        command       TEXT NOT NULL,
        pid           INTEGER,
        status        TEXT NOT NULL DEFAULT 'pending',
        started_at    TEXT,
        finished_at   TEXT,
        exit_code     INTEGER,
        stdout_ref    TEXT,
        stderr_ref    TEXT,
        created_at    TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_tool_run_status ON tool_run(status)",
    """
    CREATE TABLE IF NOT EXISTS scan_cache (
        cache_key    TEXT PRIMARY KEY,        -- sha256(asset+tool+template_version)
        asset_id     TEXT,
        tool         TEXT,
        result_hash  TEXT,
        scanned_at   TEXT,
        ttl_hours    INTEGER DEFAULT 72
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS observations (
        id              TEXT PRIMARY KEY,
        engagement_id   TEXT NOT NULL,
        action_id       TEXT,
        tool            TEXT NOT NULL,
        raw_path        TEXT,                 -- on-disk raw output
        parsed_summary  TEXT,                 -- <=10 line human summary
        new_asset_ids   TEXT,                 -- JSON list
        new_finding_ids TEXT,                 -- JSON list
        exit_code       INTEGER,
        duration_s      REAL,
        url             TEXT,                 -- action target context (F13)
        host            TEXT,                 -- action target context (F13)
        processed_at    TEXT,                 -- NULL = not yet ingested (F12)
        created_at      TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_observations_engagement ON observations(engagement_id)",
    # ------------------------------------------------------------------
    # Meta
    # ------------------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
]


def schema_statements() -> list[str]:
    return list(_STATEMENTS)
