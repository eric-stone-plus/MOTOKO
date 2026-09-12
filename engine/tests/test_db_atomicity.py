"""db.py contracts — one transaction per graph mutation, replayable event
payloads, and no state change against a missing row (F07 + F08 + F29).

Run:  python3 tests/test_db_atomicity.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import db  # noqa: E402


class CrashDuringEvent(db.Database):
    """A writer whose event append explodes on demand.

    Simulates a crash exactly between the entity write and the event write:
    if both live in one transaction the entity write must roll back too.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.crash_events = False

    def _insert_event(self, kind, entity_id, payload):
        if self.crash_events:
            raise RuntimeError("simulated crash while appending the event")
        return super()._insert_event(kind, entity_id, payload)


def _fresh_db(tmp: Path, name: str = "graph.db") -> db.Database:
    d = db.Database(tmp / name)
    d.init_schema()
    return d


def _replay_entities(conn) -> dict[str, dict]:
    """Fold entity.upsert / entity.transition events into a view.

    This is the crash-recovery contract: replaying ``events`` must rebuild
    every entity the materialized ``entities`` table holds.
    """
    view: dict[str, dict] = {}
    for row in conn.execute("SELECT seq, kind, entity_id, payload FROM events ORDER BY seq"):
        if row["kind"] not in ("entity.upsert", "entity.transition"):
            continue
        payload = json.loads(row["payload"] or "{}")
        snap = payload.get("snapshot")
        if not isinstance(snap, dict):
            continue
        merged = dict(snap.get("data") or {})
        merged.update({k: v for k, v in snap.items() if k != "data"})
        view[row["entity_id"]] = merged
    return view


class TestSameTransaction(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="motoko-db-atomic-"))

    def test_entity_upsert_and_event_roll_back_together(self):
        d = CrashDuringEvent(self.tmp / "graph.db")
        d.init_schema()
        d.crash_events = True
        with self.assertRaises(RuntimeError):
            d.upsert_entity({
                "id": "ast_x", "kind": "asset", "engagement_id": "eng",
                "state": "active", "value": "example.com",
            })
        d.crash_events = False
        self.assertIsNone(d.get_entity("ast_x"), "entity write survived a failed event append")
        n = d.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        self.assertEqual(n, 0)
        d.close()

    def test_edge_add_and_event_roll_back_together(self):
        d = CrashDuringEvent(self.tmp / "graph.db")
        d.init_schema()
        d.crash_events = True
        with self.assertRaises(RuntimeError):
            d.add_edge("ast_a", "fnd_b", "discovered_on", engagement_id="eng")
        d.crash_events = False
        self.assertEqual(d.get_edges(), [])
        n = d.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        self.assertEqual(n, 0)
        d.close()

    def test_successful_write_leaves_entity_and_event(self):
        d = _fresh_db(self.tmp)
        d.upsert_entity({
            "id": "ast_ok", "kind": "asset", "engagement_id": "eng",
            "state": "active", "value": "example.com",
        })
        self.assertIsNotNone(d.get_entity("ast_ok"))
        n = d.conn.execute("SELECT COUNT(*) c FROM events WHERE kind='entity.upsert'").fetchone()["c"]
        self.assertEqual(n, 1)
        d.close()

    def test_set_scope_and_event_roll_back_together(self):
        # R3 H1: the scope row and its scope.set event must share ONE
        # transaction — a crash during the append rolls both back (F07).
        d = CrashDuringEvent(self.tmp / "graph.db")
        d.init_schema()
        d.crash_events = True
        with self.assertRaises(RuntimeError):
            d.set_scope("eng", name="x", in_scope=["example.com"],
                        out_of_scope=[], intensity="normal", max_depth=3,
                        concurrency=4, oob_domain=None, config={})
        d.crash_events = False
        self.assertIsNone(d.get_scope("eng"),
                          "scope row survived a failed event append")
        n = d.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        self.assertEqual(n, 0)
        d.close()

    def test_set_scope_writes_row_and_event_together(self):
        d = _fresh_db(self.tmp)
        d.set_scope("eng", name="x", in_scope=["example.com"],
                    out_of_scope=[], intensity="normal", max_depth=3,
                    concurrency=4, oob_domain=None, config={"k": 1})
        scope = d.get_scope("eng")
        self.assertIsNotNone(scope)
        self.assertEqual(scope["in_scope"], ["example.com"])
        self.assertEqual(scope["config"], {"k": 1})
        n = d.conn.execute(
            "SELECT COUNT(*) c FROM events WHERE kind='scope.set'").fetchone()["c"]
        self.assertEqual(n, 1)
        d.close()


class TestEntitySnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="motoko-db-snap-"))
        self.d = _fresh_db(self.tmp)

    def tearDown(self):
        self.d.close()

    def _last_payload(self, kind: str) -> dict:
        row = self.d.conn.execute(
            "SELECT payload FROM events WHERE kind = ? ORDER BY seq DESC LIMIT 1",
            (kind,)).fetchone()
        self.assertIsNotNone(row, f"no {kind} event recorded")
        return json.loads(row["payload"])

    def test_upsert_event_carries_full_entity_snapshot(self):
        self.d.upsert_entity({
            "id": "fnd_1", "kind": "finding", "engagement_id": "eng",
            "state": "candidate", "confidence": 0.42, "dedup_key": "k",
            "class": "sqli", "url": "https://example.com/?q=1", "signals": [],
        })
        p = self._last_payload("entity.upsert")
        snap = p.get("snapshot")
        self.assertIsInstance(snap, dict, "entity.upsert payload has no snapshot")
        # every typed column present
        for col in ("id", "kind", "engagement_id", "state", "confidence",
                    "priority", "dedup_key", "created_at", "updated_at"):
            self.assertIn(col, snap)
        # and the domain fields under `data`
        self.assertIn("data", snap)
        self.assertEqual(snap["data"].get("class"), "sqli")
        self.assertEqual(snap["data"].get("url"), "https://example.com/?q=1")
        self.assertEqual(snap["state"], "candidate")

    def test_transition_event_carries_full_entity_snapshot(self):
        self.d.upsert_entity({
            "id": "fnd_2", "kind": "finding", "engagement_id": "eng",
            "state": "candidate", "confidence": 0.3, "class": "xss.reflected",
        })
        ok, reason = self.d.advance_and_persist("fnd_2", "dedup_pass")
        self.assertTrue(ok, reason)
        p = self._last_payload("entity.transition")
        self.assertEqual(p.get("to"), "triaged")
        snap = p.get("snapshot")
        self.assertIsInstance(snap, dict)
        self.assertEqual(snap["state"], "triaged")
        self.assertEqual(snap["data"].get("class"), "xss.reflected")

    def test_events_replay_to_the_materialized_view(self):
        self.d.upsert_entity({
            "id": "ast_r", "kind": "asset", "engagement_id": "eng",
            "state": "active", "value": "https://example.com", "tech": ["nginx"],
        })
        self.d.upsert_entity({
            "id": "fnd_r", "kind": "finding", "engagement_id": "eng",
            "state": "candidate", "confidence": 0.5, "class": "ssrf.basic",
            "url": "https://example.com/f?u=1", "signals": [], "detector": "nuclei",
        })
        self.d.advance_and_persist("fnd_r", "dedup_pass")
        self.d.advance_and_persist("fnd_r", "replay_ok")

        view = _replay_entities(self.d.conn)
        for eid in ("ast_r", "fnd_r"):
            live = self.d.get_entity(eid)
            self.assertIn(eid, view, f"{eid} missing from the replayed view")
            self.assertEqual(view[eid]["state"], live["state"])
            self.assertEqual(view[eid]["kind"], live["kind"])
        # domain field survived replay
        self.assertEqual(view["ast_r"]["tech"], ["nginx"])
        self.assertEqual(view["fnd_r"]["signals"], ["replay_ok"])
        # and the replayed state is the final one, not an intermediate
        self.assertEqual(view["fnd_r"]["state"], "reproduced")


class TestNoGhostTransition(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="motoko-db-ghost-"))
        self.d = _fresh_db(self.tmp)

    def tearDown(self):
        self.d.close()

    def test_transition_against_missing_row_records_no_event(self):
        before = self.d.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        ok, reason = self.d.advance_and_persist("fnd_does_not_exist", "dedup_pass")
        after = self.d.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
        self.assertFalse(ok, "transition on a missing row must report failure")
        self.assertIn("no such entity", reason)
        self.assertEqual(before, after, "a transition against a missing row wrote an event")

    def test_transition_against_existing_row_still_works(self):
        self.d.upsert_entity({
            "id": "fnd_ok", "kind": "finding", "engagement_id": "eng",
            "state": "candidate", "class": "sqli",
        })
        ok, reason = self.d.advance_and_persist("fnd_ok", "dedup_pass")
        self.assertTrue(ok, reason)
        self.assertEqual(self.d.get_entity("fnd_ok")["state"], "triaged")


if __name__ == "__main__":
    unittest.main(verbosity=2)
