'MOTOKO — attack-graph-driven pentest orchestration engine.\n\nSingle-writer, SQLite-backed orchestration layer that replaces the linear\n5-layer pipeline with a hypothesis-driven graph traversal loop.\n\n* ONE writer process owns ``graph.db`` (WAL). Hermes supervises; it never\n  drives the hot loop. Digest/query access is read-only.\n* ``events`` is the source of truth (append-only); ``entities`` is the\n  materialized view. Crash recovery = replay events.\n* State lives on disk, not in the LLM context. A regenerated <=2KB digest is\n  the only thing injected into Hermes.\n* Only deterministic validators promote a finding; an LLM may propose but\n  never finalize a state.\n'

__version__ = "0.1.0"

from . import db, schema, util

__all__ = ["__version__", "db", "schema", "util"]
