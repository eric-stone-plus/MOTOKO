"""Single-file SQLite schema for the MOTOKO attack graph.

Base (kimi review) + absorbed tables (qwen review), per the grok merge
verdict: ONE database ``graph.db``, not two. ``entities``/``edges``/
``events`` model the graph; ``services``/``scope``/``tool_run``/
``scan_cache``/``observations`` are first-class tables, not a second DB.

All JSON is stored as TEXT. IDs are sortable strings from ``util.new_id``.
"""

from __future__ import annotations

SCHEMA_VERSION = 2

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

# Finding state machine states (kimi + triaged budget gate). See
# state_machine.py for transitions.
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

_STATEMENTS: list[str] = [
    # ------------------------------------------------------------------
    # Graph core (kimi)
    # ------------------------------------------------------------------
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
    # ------------------------------------------------------------------
    # Absorbed tables (qwen)
    # ------------------------------------------------------------------
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
    # ------------------------------------------------------------------
    # Observation contract (grok P0 requirement)
    # ------------------------------------------------------------------
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
