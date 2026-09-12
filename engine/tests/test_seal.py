"""seal_engagement — product-unit contract tests.

A sealed engagement = engine commit + checkpointed graph.db +
engagement.manifest.json (ARCHITECTURE.md). These tests pin the parts
that make the artifact trustworthy: busy refusal, WAL removal, hash
coverage of the seal event, idempotent re-seal.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import db, seal  # noqa: E402

ENG = "eng-seal"


def _entity(eid: str, kind: str, state: str) -> dict:
    return {"id": eid, "kind": kind, "engagement_id": ENG,
            "state": state, "type": "url", "value": f"https://{eid}.example.com",
            "source": "test"}


class TestSealHappyPath(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-seal-"))
        db.init_engagement(self.root, ENG, name="seal", in_scope=["example.com"])
        w = db.Database(self.root / ENG / "graph.db")
        try:
            w.upsert_entity(_entity("asset-1", "asset", "active"))
            # F06: findings are created as 'candidate'; promotion only via
            # advance_and_persist — the test walks the real ladder.
            w.upsert_entity(_entity("find-1", "finding", "candidate"))
            w.upsert_entity(_entity("find-2", "finding", "candidate"))
            w.advance_and_persist("find-1", "dedup_pass", actor="validator")
            w.advance_and_persist("find-2", "dedup_pass", actor="validator")
            w.advance_and_persist("find-2", "noise_rule", actor="validator")
            w.upsert_entity(_entity("hyp-1", "hypothesis", "testing"))
        finally:
            w.close()
        self.edir = self.root / ENG

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _seal(self):
        return seal.seal_engagement(ENG, root=self.root)

    def test_manifest_is_written_and_consistent(self):
        m = self._seal()
        path = self.edir / "engagement.manifest.json"
        self.assertTrue(path.exists())
        on_disk = json.loads(path.read_text())
        self.assertEqual(on_disk["engagement_id"], ENG)
        self.assertEqual(on_disk["graph_db"]["bytes"],
                         (self.edir / "graph.db").stat().st_size)
        self.assertNotEqual(m["engine_commit"], "unknown",
                            "tests run inside the engine repo; HEAD must resolve")

    def test_wal_sidecars_are_gone_after_seal(self):
        self._seal()
        self.assertFalse((self.edir / "graph.db-wal").exists(),
                         "checkpoint(TRUNCATE) + clean close must remove -wal")
        self.assertFalse((self.edir / "graph.db-shm").exists())

    def test_seal_event_is_inside_the_hashed_state(self):
        self._seal()
        ro = db.Database(self.edir / "graph.db", read_only=True)
        try:
            kinds = [r["kind"] for r in ro.conn.execute(
                "SELECT kind FROM events WHERE kind = 'engagement_sealed'")]
        finally:
            ro.close()
        self.assertEqual(len(kinds), 1)

    def test_census_counts_match_entities(self):
        m = self._seal()
        c = m["census"]
        self.assertEqual(c["entities_by_kind_state"].get("finding/triaged"), 1)
        self.assertEqual(c["findings_total"], 2)
        self.assertEqual(c["findings_terminal"], 1)
        self.assertEqual(c["findings_open"], 1)
        self.assertEqual(c["hypotheses_testing"], 1)

    def test_reseal_is_idempotent_and_keeps_history(self):
        first = self._seal()
        second = self._seal()
        self.assertEqual(second["previously_sealed_at"], first["sealed_at"])


class TestSealRefusals(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-sealbusy-"))
        db.init_engagement(self.root, ENG, name="busy", in_scope=["example.com"])
        self.edir = self.root / ENG

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_refuses_while_another_writer_holds_the_db(self):
        holder = sqlite3.connect(str(self.edir / "graph.db"), timeout=5.0)
        try:
            # BEGIN IMMEDIATE alone takes the write lock — no valid write
            # needed, the lock is the point.
            holder.execute("BEGIN IMMEDIATE")
            with self.assertRaises(seal.SealError):
                seal.seal_engagement(ENG, root=self.root)
            self.assertFalse((self.edir / "engagement.manifest.json").exists(),
                             "a refused seal must not leave a manifest")
        finally:
            holder.rollback()
            holder.close()
        # once the writer releases, the same seal succeeds
        seal.seal_engagement(ENG, root=self.root)

    def test_refuses_missing_engagement(self):
        with self.assertRaises(seal.SealError):
            seal.seal_engagement("no-such-eng", root=self.root)


class TestSealCLI(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-sealcli-"))
        db.init_engagement(self.root, ENG, name="cli", in_scope=["example.com"])

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_cli_seal_returns_zero_and_prints_manifest(self):
        from motoko import cli

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["seal", ENG, "--root", str(self.root)])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["engagement_id"], ENG)

    def test_cli_seal_missing_returns_two(self):
        from motoko import cli

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cli.main(["seal", "ghost", "--root", str(self.root)])
        self.assertEqual(rc, 2)
        self.assertIn("seal refused", err.getvalue())


if __name__ == "__main__":
    unittest.main()
