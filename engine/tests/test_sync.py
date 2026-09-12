"""_sync incremental ingest, duplicate handling, and parser context tests
(F12 + F15 + F13).

Run:  python3 tests/test_sync.py
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
RULES = Path(__file__).resolve().parents[1] / "rules"
FIX = Path(__file__).parent / "fixtures"

from motoko import db  # noqa: E402
from motoko import orchestrator as orchestrator_mod  # noqa: E402
from motoko.orchestrator import Orchestrator  # noqa: E402


class SyncCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="motoko-sync-"))
        self.eng = "eng-sync"
        db.init_engagement(self.tmp, self.eng, name="sync",
                           in_scope=["example.com"], out_of_scope=[])
        self.orch = Orchestrator(self.eng, root=self.tmp, rules_dir=RULES,
                                 resolver=lambda h: [])

    def tearDown(self):
        self.orch.close()

    def _stage_raw(self, name: str, fixture: str) -> str:
        dst = self.orch.artifacts / name
        shutil.copyfile(FIX / fixture, dst)
        return str(dst)

    def _findings(self) -> list[dict]:
        return self.orch.writer.query_entities(
            kind="finding", engagement_id=self.eng)

    def _obs(self, oid: str) -> dict:
        return dict(self.orch.writer.conn.execute(
            "SELECT * FROM observations WHERE id = ?", (oid,)).fetchone())


class TestIncrementalSync(SyncCase):
    def test_schema_has_the_processed_marker(self):
        cols = {r["name"] for r in self.orch.writer.conn.execute(
            "PRAGMA table_info(observations)")}
        self.assertIn("processed_at", cols)
        self.assertIn("url", cols)

    def test_processed_observation_is_not_reingested(self):
        raw = self._stage_raw("s1.txt", "sqlmap.txt")
        oid = self.orch.writer.record_observation(
            tool="sqlmap", engagement_id=self.eng, raw_path=raw,
            parsed_summary="1 injectable", url="https://example.com/search?q=1",
        )
        real = orchestrator_mod.parse_tool
        calls: list = []

        def counting(*args, **kwargs):
            calls.append(args)
            return real(*args, **kwargs)

        with mock.patch.object(orchestrator_mod, "parse_tool", counting):
            self.orch._sync()
            self.orch._sync()
            self.orch._sync()

        self.assertEqual(len(calls), 1, "_sync re-parsed an already processed observation")
        self.assertIsNotNone(self._obs(oid)["processed_at"])
        self.assertEqual(len(self._findings()), 1)
        self.assertEqual(len(self._findings()), 1, "second sync created a new generation")

    def test_observation_without_raw_output_is_marked_processed(self):
        oid = self.orch.writer.record_observation(
            tool="nuclei", engagement_id=self.eng, raw_path=None,
            parsed_summary="skeleton")
        self.orch._sync()
        self.assertIsNotNone(self._obs(oid)["processed_at"])

    def test_unreadable_raw_path_is_marked_processed_with_an_event(self):
        oid = self.orch.writer.record_observation(
            tool="nuclei", engagement_id=self.eng, raw_path="/nonexistent/raw.txt",
            parsed_summary="gone")
        self.orch._sync()
        self.assertIsNotNone(self._obs(oid)["processed_at"])
        n = self.orch.writer.conn.execute(
            "SELECT COUNT(*) c FROM events WHERE kind='observation_dead_letter'").fetchone()["c"]
        self.assertEqual(n, 1)

    def test_new_observation_is_ingested_on_the_next_sync(self):
        raw = self._stage_raw("s2.txt", "sqlmap.txt")
        self.orch._sync()   # nothing yet
        oid = self.orch.writer.record_observation(
            tool="sqlmap", engagement_id=self.eng, raw_path=raw,
            parsed_summary="x", url="https://example.com/a?q=1")
        self.orch._sync()
        self.assertIsNotNone(self._obs(oid)["processed_at"])
        self.assertEqual(len(self._findings()), 1)


class TestIngestContext(SyncCase):
    """F13: the observation's action/url/host context reaches the parser, so a
    tool that prints no URL still yields a finding tied to its target."""

    def test_sqlmap_finding_url_comes_from_the_observation_context(self):
        raw = self._stage_raw("s3.txt", "sqlmap.txt")
        self.orch.writer.record_observation(
            tool="sqlmap", engagement_id=self.eng, raw_path=raw,
            parsed_summary="1 injectable",
            url="https://example.com/search?q=1", host="example.com",
        )
        self.orch._sync()
        findings = self._findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["url"], "https://example.com/search?q=1")
        self.assertEqual(findings[0]["param"], "q")
        self.assertEqual(findings[0]["state"], "triaged")

    def test_sqlmap_without_context_yields_a_url_less_finding(self):
        # documents the raw kill chain: no context -> no url -> the validator
        # must return inconclusive instead of replay_fail (F27).
        raw = (FIX / "sqlmap.txt").read_text()
        parsed = orchestrator_mod.parse_tool("sqlmap", raw)
        self.assertEqual(parsed.findings[0]["url"], "")

    def test_sqlmap_parser_takes_url_from_the_action_context(self):
        raw = (FIX / "sqlmap.txt").read_text()
        parsed = orchestrator_mod.parse_tool(
            "sqlmap", raw, "", {"url": "https://example.com/search?q=1"})
        self.assertEqual(parsed.findings[0]["url"], "https://example.com/search?q=1")


class TestDuplicateHandling(SyncCase):
    """F15: a dedup hit must not mint a new finding row."""

    def _finding_dict(self, fid: str) -> dict:
        return {
            "id": fid, "kind": "finding", "engagement_id": self.eng,
            "state": "candidate", "class": "sqli",
            "url": "https://example.com/search?q=1", "param": "q",
            "detector": "sqlmap", "signals": [], "confidence": 0.75,
        }

    def test_duplicate_does_not_create_a_new_entity(self):
        first = self.orch._ingest_finding(self._finding_dict("fnd_dup_1"))
        second = self.orch._ingest_finding(self._finding_dict("fnd_dup_2"))
        self.assertEqual(first, "fnd_dup_1")
        self.assertEqual(second, first, "dedup hit must return the primary id")
        self.assertEqual(len(self._findings()), 1, "duplicate minted a new finding row")
        self.assertIsNone(self.orch.writer.get_entity("fnd_dup_2"))
        edges = self.orch.writer.get_edges(from_id="fnd_dup_2", rel="duplicate_of")
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["to_id"], first)

    def test_duplicate_count_accumulates_on_the_primary(self):
        self.orch._ingest_finding(self._finding_dict("fnd_dup_3"))
        self.orch._ingest_finding(self._finding_dict("fnd_dup_4"))
        self.orch._ingest_finding(self._finding_dict("fnd_dup_5"))
        primary = self.orch.writer.get_entity("fnd_dup_3")
        self.assertEqual(primary["duplicate_count"], 2)
        self.assertEqual(len(self._findings()), 1)

    def test_duplicate_keeps_the_primary_in_triaged(self):
        self.orch._ingest_finding(self._finding_dict("fnd_dup_6"))
        self.orch._ingest_finding(self._finding_dict("fnd_dup_7"))
        self.assertEqual(self.orch.writer.get_entity("fnd_dup_6")["state"], "triaged")

    def test_distinct_findings_still_get_their_own_rows(self):
        a = self._finding_dict("fnd_uniq_1")
        self.orch._ingest_finding(a)
        b = self._finding_dict("fnd_uniq_2")
        b["url"] = "https://example.com/other?q=1"
        b["param"] = "other"
        self.orch._ingest_finding(b)
        self.assertEqual(len(self._findings()), 2)


class TestMalformedOutput(SyncCase):
    """R3 H4: malformed tool output must not kill run() — the parser's dead
    letter catches it and the observation is still marked processed."""

    def test_non_numeric_status_does_not_kill_the_loop(self):
        raw = self.orch.artifacts / "bad_ffuf.json"
        raw.write_text('{"results": [{"status": "not-a-number", '
                       '"url": "https://example.com/x"}]}')
        oid = self.orch.writer.record_observation(
            tool="ffuf", engagement_id=self.eng, raw_path=str(raw),
            parsed_summary="malformed")
        summary = self.orch.run(max_cycles=1)      # must not raise
        self.assertIsNotNone(self._obs(oid)["processed_at"])
        self.assertIn("cycle", summary)

    def test_parser_exception_is_dead_lettered_and_marked_processed(self):
        raw = self._stage_raw("boom.txt", "sqlmap.txt")
        oid = self.orch.writer.record_observation(
            tool="sqlmap", engagement_id=self.eng, raw_path=raw,
            parsed_summary="boom")
        with mock.patch.object(orchestrator_mod, "parse_tool",
                               side_effect=RuntimeError("parser blew up")):
            self.orch.run(max_cycles=1)            # must not raise
        self.assertIsNotNone(self._obs(oid)["processed_at"],
                             "a crashing parser left the observation unprocessed")
        n = self.orch.writer.conn.execute(
            "SELECT COUNT(*) c FROM events WHERE kind='observation_dead_letter'"
        ).fetchone()["c"]
        self.assertEqual(n, 1)


class TestSchemaMigration(unittest.TestCase):
    def test_v1_observations_table_is_migrated_in_place(self):
        tmp = Path(tempfile.mkdtemp(prefix="motoko-mig-"))
        path = tmp / "graph.db"
        conn = sqlite3.connect(str(path))
        conn.execute("""
            CREATE TABLE observations (
                id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, action_id TEXT,
                tool TEXT NOT NULL, raw_path TEXT, parsed_summary TEXT,
                new_asset_ids TEXT, new_finding_ids TEXT, exit_code INTEGER,
                duration_s REAL, created_at TEXT NOT NULL)
        """)
        conn.execute("INSERT INTO observations(id, engagement_id, tool, created_at) "
                     "VALUES('obs_old','eng','nuclei','2026-01-01')")
        conn.commit()
        conn.close()

        d = db.Database(path)
        d.init_schema()
        cols = {r["name"] for r in d.conn.execute("PRAGMA table_info(observations)")}
        self.assertTrue({"processed_at", "url", "host"} <= cols,
                        f"migration missed columns: {cols}")
        # the pre-existing row is still there AND still unprocessed
        pending = d.unprocessed_observations("eng")
        self.assertEqual(len(pending), 1)
        d.close()

    def test_schema_version_is_bumped(self):
        from motoko import schema
        self.assertGreaterEqual(schema.SCHEMA_VERSION, 2)


class TestFindingAssetBackfill(SyncCase):
    """R5 M7: findings without an asset_id are linked back to the asset with
    the same value or host — per-asset class rules read facts['class'], so
    an unlinked finding is invisible to the rule engine."""

    def test_ingest_finding_backfills_asset_id_on_host_match(self):
        aid = self.orch.writer.upsert_entity({
            "id": "ast_bk", "kind": "asset", "engagement_id": self.eng,
            "state": "active", "type": "url", "value": "https://example.com",
        })
        f = {"id": "fnd_bk", "kind": "finding", "engagement_id": self.eng,
             "state": "candidate", "class": "sqli",
             "url": "https://example.com/search?q=1",
             "detector": "sqlmap", "signals": [], "confidence": 0.75}
        self.orch._ingest_finding(f)
        got = self.orch.writer.get_entity("fnd_bk")
        self.assertEqual(got.get("asset_id"), aid,
                         "finding was not linked to its asset")

    def test_ingest_finding_backfills_from_a_bare_domain_asset(self):
        aid = self.orch.writer.upsert_entity({
            "id": "ast_dom", "kind": "asset", "engagement_id": self.eng,
            "state": "active", "type": "domain", "value": "example.com",
        })
        f = {"id": "fnd_dom", "kind": "finding", "engagement_id": self.eng,
             "state": "candidate", "class": "sqli",
             "url": "https://example.com/search?q=1",
             "detector": "sqlmap", "signals": [], "confidence": 0.75}
        self.orch._ingest_finding(f)
        self.assertEqual(self.orch.writer.get_entity("fnd_dom").get("asset_id"), aid)

    def test_ingest_finding_keeps_an_explicit_asset_id(self):
        self.orch.writer.upsert_entity({
            "id": "ast_x", "kind": "asset", "engagement_id": self.eng,
            "state": "active", "type": "url", "value": "https://example.com",
        })
        f = {"id": "fnd_keep", "kind": "finding", "engagement_id": self.eng,
             "state": "candidate", "class": "sqli", "asset_id": "ast_chosen",
             "url": "https://example.com/search?q=1",
             "detector": "sqlmap", "signals": [], "confidence": 0.75}
        self.orch._ingest_finding(f)
        self.assertEqual(self.orch.writer.get_entity("fnd_keep").get("asset_id"),
                         "ast_chosen")

    def test_sync_backfills_asset_id_for_parser_findings(self):
        # end-to-end through _sync: parser finding -> graph with a link
        aid = self.orch.writer.upsert_entity({
            "id": "ast_sync_bk", "kind": "asset", "engagement_id": self.eng,
            "state": "active", "type": "url", "value": "https://example.com",
        })
        raw = self._stage_raw("s7.txt", "sqlmap.txt")
        self.orch.writer.record_observation(
            tool="sqlmap", engagement_id=self.eng, raw_path=raw,
            parsed_summary="1 injectable",
            url="https://example.com/search?q=1", host="example.com")
        self.orch._sync()
        findings = self._findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].get("asset_id"), aid,
                         "parser finding entered the graph without an asset link")


if __name__ == "__main__":
    unittest.main(verbosity=2)
