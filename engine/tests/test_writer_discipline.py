"""Writer discipline tests — the state ladder has ONE door (F06) and the
reflector only ever sees a propose-only handle (F04).

Run:  python3 tests/test_writer_discipline.py
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
RULES = Path(__file__).resolve().parents[1] / "rules"

from motoko import confidence, db  # noqa: E402
from motoko.orchestrator import Orchestrator  # noqa: E402
from motoko.writer_views import ProposeOnlyView  # noqa: E402

FINDING = {
    "id": "fnd_wd_1", "kind": "finding", "engagement_id": "eng-wd",
    "state": "candidate", "confidence": 0.75, "detector": "sqlmap",
    "class": "sqli", "url": "https://example.com/?q=1", "signals": [],
}


class WriteCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="motoko-wd-"))
        self.eng = "eng-wd"
        db.init_engagement(self.tmp, self.eng, name="wd", in_scope=["example.com"])
        self.w = db.Database(db.engagement_dir(self.tmp, self.eng) / "graph.db")

    def tearDown(self):
        self.w.close()

    def _event_count(self) -> int:
        return self.w.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]


class TestProposeOnlyView(WriteCase):
    def setUp(self):
        super().setUp()
        self.view = ProposeOnlyView(self.w, self.eng)

    def test_no_write_paths_exist_on_the_view(self):
        for name in ("upsert_entity", "transition_entity", "advance_and_persist",
                     "append_event", "commit", "conn", "set_priority", "add_edge",
                     "record_observation", "cache_put", "start_tool_run"):
            self.assertFalse(hasattr(self.view, name),
                             f"ProposeOnlyView exposes the write path {name!r}")

    def test_proposal_and_read_methods_exist(self):
        for name in ("propose_hypothesis", "adjust_priority",
                     "get_entity", "query_entities", "get_edges", "get_scope"):
            self.assertTrue(hasattr(self.view, name),
                            f"ProposeOnlyView is missing {name!r}")

    def test_writer_handle_is_sealed_off_the_view(self):
        # R3 P0-1: the raw Database must not be reachable through the handle
        # the reflector receives. `view._writer.advance_and_persist(...)`
        # forged hard evidence before this.
        self.assertFalse(hasattr(self.view, "_writer"),
                         "ProposeOnlyView still exposes the writer handle")
        with self.assertRaises(AttributeError):
            self.view._writer
        self.assertFalse(hasattr(self.view, "_ProposeOnlyView__writer"),
                         "the writer is stored under an unmangled attribute name")

    def test_sealed_view_still_proposes_and_reads(self):
        eid = self.view.propose_hypothesis({"statement": "still works"})
        self.assertIsNotNone(self.view.get_entity(eid))
        self.assertTrue(self.view.adjust_priority(eid, 3.0))

    def test_propose_hypothesis_forces_the_proposal_shape(self):
        eid = self.view.propose_hypothesis({
            "id": "hyp_wd_1", "kind": "finding", "state": "verified",
            "engagement_id": "somewhere-else", "statement": "try SSRF",
        })
        got = self.w.get_entity(eid)
        self.assertEqual(got["kind"], "hypothesis")
        self.assertEqual(got["state"], "proposed")
        self.assertEqual(got["engagement_id"], self.eng)
        self.assertEqual(got["statement"], "try SSRF")

    def test_propose_hypothesis_persists_readable_entity(self):
        eid = self.view.propose_hypothesis({"id": "hyp_wd_2", "statement": "x"})
        self.assertIsNotNone(self.view.get_entity(eid))
        self.assertEqual(len(self.view.query_entities(kind="hypothesis")), 1)

    def test_adjust_priority_only_touches_priority(self):
        self.w.upsert_entity(dict(FINDING, id="fnd_wd_p", state="candidate"))
        self.assertTrue(self.view.adjust_priority("fnd_wd_p", 42.0))
        got = self.w.get_entity("fnd_wd_p")
        self.assertEqual(got["priority"], 42.0)
        self.assertEqual(got["state"], "candidate", "priority change altered the state")
        self.assertEqual(got["class"], "sqli", "priority change clobbered domain data")

    def test_adjust_priority_missing_entity_reports_failure(self):
        self.assertFalse(self.view.adjust_priority("nope", 1.0))


class TestAdvanceAndPersist(WriteCase):
    def test_walks_the_state_machine_and_persists(self):
        self.w.upsert_entity(dict(FINDING, id="fnd_wd_a"))
        ok, reason = self.w.advance_and_persist("fnd_wd_a", "dedup_pass")
        self.assertTrue(ok, reason)
        self.assertEqual(self.w.get_entity("fnd_wd_a")["state"], "triaged")

        ok, reason = self.w.advance_and_persist("fnd_wd_a", "replay_ok",
                                                verdict=None)
        self.assertTrue(ok, reason)
        got = self.w.get_entity("fnd_wd_a")
        self.assertEqual(got["state"], "reproduced")
        self.assertEqual(got["signals"], ["replay_ok"])
        self.assertAlmostEqual(got["confidence"],
                               confidence.score("sqlmap", ["replay_ok"]), places=6)
        # transition event + snapshot recorded
        row = self.w.conn.execute(
            "SELECT payload FROM events WHERE kind='entity.transition' ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertIn('"to": "reproduced"', row["payload"])
        self.assertIn('"snapshot"', row["payload"])

    def test_rejects_an_illegal_event_without_touching_state(self):
        self.w.upsert_entity(dict(FINDING, id="fnd_wd_b"))
        before = self._event_count()
        ok, reason = self.w.advance_and_persist("fnd_wd_b", "poc_success")
        self.assertFalse(ok)
        self.assertIn("no transition", reason)
        self.assertEqual(self.w.get_entity("fnd_wd_b")["state"], "candidate")
        self.assertEqual(self._event_count(), before)

    def test_rejects_a_missing_entity(self):
        ok, reason = self.w.advance_and_persist("fnd_ghost", "dedup_pass")
        self.assertFalse(ok)
        self.assertIn("no such entity", reason)

    def test_rejects_llm_actor(self):
        self.w.upsert_entity(dict(FINDING, id="fnd_wd_c"))
        ok, reason = self.w.advance_and_persist("fnd_wd_c", "dedup_pass", actor="llm")
        self.assertFalse(ok)
        self.assertIn("LLM", reason)
        self.assertEqual(self.w.get_entity("fnd_wd_c")["state"], "candidate")

    def test_bare_transition_entity_is_gone(self):
        self.assertFalse(hasattr(db.Database, "transition_entity"),
                         "the raw transition_entity door is still open (F06)")


class TestUpsertCannotPromote(WriteCase):
    def test_existing_finding_state_change_is_refused(self):
        self.w.upsert_entity(dict(FINDING, id="fnd_wd_d"))
        with self.assertRaises(ValueError):
            self.w.upsert_entity(dict(FINDING, id="fnd_wd_d", state="verified"))
        self.assertEqual(self.w.get_entity("fnd_wd_d")["state"], "candidate")

    def test_new_finding_cannot_be_born_promoted(self):
        with self.assertRaises(ValueError):
            self.w.upsert_entity(dict(FINDING, id="fnd_wd_e", state="exploitable"))

    def test_domain_only_update_is_still_allowed(self):
        self.w.upsert_entity(dict(FINDING, id="fnd_wd_f"))
        self.w.upsert_entity(dict(FINDING, id="fnd_wd_f", title="SQLi confirmed"))
        got = self.w.get_entity("fnd_wd_f")
        self.assertEqual(got["state"], "candidate")
        self.assertEqual(got["title"], "SQLi confirmed")


class TestProposalCannotOverwrite(WriteCase):
    """R3 P0-2: propose_hypothesis cannot take over an existing row, and an
    entity's kind is frozen once written (F50)."""

    def setUp(self):
        super().setUp()
        self.view = ProposeOnlyView(self.w, self.eng)

    def test_propose_ignores_a_colliding_caller_id(self):
        self.w.upsert_entity(dict(FINDING, id="fnd_p0_2"))
        ok, reason = self.w.advance_and_persist("fnd_p0_2", "dedup_pass")
        self.assertTrue(ok, reason)
        hid = self.view.propose_hypothesis({"id": "fnd_p0_2", "statement": "collide"})
        self.assertNotEqual(hid, "fnd_p0_2", "propose adopted the caller-supplied id")
        victim = self.w.get_entity("fnd_p0_2")
        self.assertEqual(victim["kind"], "finding",
                         "a verified row was re-purposed as a hypothesis")
        self.assertEqual(victim["state"], "triaged")
        fresh = self.w.get_entity(hid)
        self.assertEqual(fresh["kind"], "hypothesis")
        self.assertEqual(fresh["state"], "proposed")

    def test_two_proposals_get_distinct_ids_and_both_persist(self):
        a = self.view.propose_hypothesis({"statement": "a"})
        b = self.view.propose_hypothesis({"statement": "b"})
        self.assertNotEqual(a, b)
        self.assertEqual(self.w.get_entity(a)["kind"], "hypothesis")
        self.assertEqual(self.w.get_entity(b)["kind"], "hypothesis")
        self.assertEqual(len(self.w.query_entities(kind="hypothesis")), 2)

    def test_upsert_entity_cannot_flip_the_kind_of_an_existing_row(self):
        self.w.upsert_entity(dict(FINDING, id="fnd_kind_frozen"))
        with self.assertRaises(ValueError):
            self.w.upsert_entity({
                "id": "fnd_kind_frozen", "kind": "hypothesis",
                "engagement_id": self.eng, "state": "proposed",
                "statement": "hijack the row",
            })
        got = self.w.get_entity("fnd_kind_frozen")
        self.assertEqual(got["kind"], "finding", "kind was not frozen")
        self.assertEqual(got["state"], "candidate")
        self.assertEqual(got["class"], "sqli")


class TestReflectorHandle(WriteCase):
    def test_reflector_receives_a_propose_only_handle(self):
        seen = {}

        def reflector(handle, engagement_id):
            seen["handle"] = handle
            seen["engagement_id"] = engagement_id

        orch = Orchestrator(self.eng, root=self.tmp, rules_dir=RULES,
                            reflector=reflector)
        try:
            orch._reflect_if_needed(force=True)
        finally:
            orch.close()

        handle = seen["handle"]
        self.assertFalse(isinstance(handle, db.Database),
                         "reflector still gets the full writer handle")
        for name in ("upsert_entity", "transition_entity", "advance_and_persist",
                     "append_event", "conn", "commit"):
            self.assertFalse(hasattr(handle, name),
                             f"reflector handle exposes {name!r}")
        self.assertTrue(hasattr(handle, "propose_hypothesis"))
        self.assertEqual(seen["engagement_id"], self.eng)


if __name__ == "__main__":
    unittest.main(verbosity=2)
