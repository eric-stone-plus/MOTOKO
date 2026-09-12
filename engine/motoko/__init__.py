"""MOTOKO — attack-graph-driven pentest orchestration engine.

Single-writer, SQLite-backed orchestration layer that replaces the linear
5-layer pipeline with a hypothesis-driven graph traversal loop.

Design contract (from the kimi/grok architecture review, 2026-09-11):

* ONE writer process owns ``graph.db`` (WAL). Hermes supervises; it never
  drives the hot loop. Digest/query access is read-only.
* ``events`` is the source of truth (append-only); ``entities`` is the
  materialized view. Crash recovery = replay events.
* State lives on disk, not in the LLM context. A regenerated <=2KB digest is
  the only thing injected into Hermes.
* Only deterministic validators promote a finding; an LLM may propose but
  never finalize a state.
"""

__version__ = "0.1.0"

from . import db, schema, util  # noqa: F401

__all__ = ["__version__", "db", "schema", "util"]
