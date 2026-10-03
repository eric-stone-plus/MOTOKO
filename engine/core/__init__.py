"MOTOKO — attack-graph-driven pentest orchestration engine.\n\nSingle-writer, SQLite-backed orchestration layer that replaces the linear\n5-layer pipeline with a hypothesis-driven graph traversal loop.\n\n* ONE writer process owns ``graph.db`` (WAL). The seat supervises; it never\n  drives the hot loop. Digest/query access is read-only.\n* ``events`` is the source of truth (append-only); every other table is a\n  materialized view of it. Crash recovery = replay events, and that is an\n  executable claim, not a docstring: ``motoko events <id> --verify`` folds the\n  log and compares it against every table, ``--rebuild DIR`` materializes a\n  new database from the log alone, and ``core/events.py`` is the read path\n  both run on.\n* State lives on disk, not in the LLM context. A regenerated <=2KB digest is\n  the only thing injected into the seat's context.\n* Only deterministic validators promote a finding; an LLM may propose but\n  never finalize a state.\n"

__version__ = "0.1.0"

from . import db, schema, util

__all__ = ["__version__", "db", "schema", "util"]
