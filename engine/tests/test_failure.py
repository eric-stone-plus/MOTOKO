"""R3: failure taxonomy + recovery tests.

The last class runs against a COPY of a real engagement graph, which is the
guard that matters most: a hand-built fixture happily accepts whatever columns
the test author assumed, so the first version of ``failure.py`` passed its own
tests while querying a ``props`` column that does not exist in the real schema
(``entities`` keeps ``state``/``priority`` as columns and domain fields in
``data``). Only production data catches that.

Run:  python3 tests/test_failure.py
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unittest import mock as _mock  # noqa: F401
from motoko import db, failure, orchestrator  # noqa: E402

ENG = "eng-fail"


def _mk(root: Path, eng: str = ENG) -> db.Database:
    db.init_engagement(root, eng, name="fail", in_scope=["example.com"])
    return db.Database(db.engagement_dir(root, eng) / "graph.db")


def _hyp(w: db.Database, hid: str, *, state: str = "testing", priority: float = 60.0,
         tool: str = "nuclei", timeout: int | None = None, **extra) -> str:
    actions = [{"tool": tool, "cmd": f"{tool} -u https://example.com"}]
    if timeout:
        actions[0]["timeout"] = timeout
    return w.upsert_entity({
        "id": hid, "kind": "hypothesis", "engagement_id": ENG, "state": state,
        "priority": priority, "statement": f"probe {hid}", "actions": actions,
        **extra,
    })


def _run(w: db.Database, hid: str, *, tool: str = "nuclei", status: str = "error",
         exit_code: int | None = 1, stderr: str | None = None) -> str:
    rid = w.start_tool_run(tool=tool, command=f"{tool} -u https://example.com",
                           hypothesis_id=hid)
    ref = None
    if stderr is not None:
        p = Path(tempfile.mkdtemp(prefix="motoko-err-")) / "stderr.txt"
        p.write_text(stderr, encoding="utf-8")
        ref = str(p)
    w.finish_tool_run(rid, status=status, exit_code=exit_code, stderr_ref=ref)
    return rid


class TestClassify(unittest.TestCase):
    """Pure taxonomy: each signal maps to one class with one policy."""

    def test_scope_block_is_never_retryable(self):
        f = failure.classify(status="error", exit_code=2, tool="nuclei",
                             stderr_text="scope_blocked: target not authorized")
        self.assertEqual(f.cls, "scope_blocked")
        self.assertFalse(f.retryable)
        self.assertEqual(f.max_attempts, 0)
        self.assertIn("scope_blocked", failure.NEVER_RETRY)

    def test_missing_binary_is_deterministic(self):
        # executor writes 127 for `tool binary not found` and missing podman
        for tool in ("dalfox", "podman"):
            f = failure.classify(status="error", exit_code=127, tool=tool)
            self.assertEqual(f.cls, "tool_missing", tool)
            self.assertFalse(f.retryable)

    def test_spawn_codes_are_rule_authoring_defects(self):
        # -1 bad action shape, -2 non-str argv, 126 spawn OSError
        for code in (-1, -2, 126):
            f = failure.classify(status="error", exit_code=code, tool="ffuf")
            self.assertEqual(f.cls, "spawn_error", code)
            self.assertFalse(f.retryable, f"exit {code} must not be retried")
            self.assertEqual(f.max_attempts, 0)

    def test_cheap_timeout_retries_once(self):
        f = failure.classify(status="timeout", exit_code=124, tool="katana",
                             tool_timeout=300)
        self.assertEqual(f.cls, "tool_timeout")
        self.assertTrue(f.retryable)
        self.assertEqual(f.max_attempts, 1)

    def test_expensive_timeout_is_not_blind_retried(self):
        # strix -m deep declares timeout=7200 and strix is the only token
        # consumer: a second attempt costs more than the information returns.
        f = failure.classify(status="timeout", exit_code=124, tool="strix",
                             tool_timeout=7200)
        self.assertEqual(f.cls, "tool_timeout")
        self.assertFalse(f.retryable)
        self.assertEqual(f.max_attempts, 0)
        self.assertIn("expensive", f.reason)

    def test_timeout_at_the_expense_boundary(self):
        self.assertFalse(failure.classify(
            status="timeout", exit_code=124, tool="x",
            tool_timeout=failure.EXPENSIVE_TIMEOUT_S).retryable)
        self.assertTrue(failure.classify(
            status="timeout", exit_code=124, tool="x",
            tool_timeout=failure.EXPENSIVE_TIMEOUT_S - 1).retryable)

    def test_transient_tool_error_is_retryable_with_a_cap(self):
        f = failure.classify(status="error", exit_code=1, tool="subfinder",
                             stderr_text="429 Too Many Requests")
        self.assertEqual(f.cls, "tool_error")
        self.assertTrue(f.retryable)
        self.assertEqual(f.max_attempts, 2)
        self.assertIn("transient", f.reason)

    def test_plain_nonzero_exit_still_gets_one_budget(self):
        f = failure.classify(status="error", exit_code=3, tool="arjun")
        self.assertEqual(f.cls, "tool_error")
        self.assertTrue(f.retryable)

    def test_deterministic_classes_outright_never_retry(self):
        # scope outranks everything, even a transient-looking stderr
        f = failure.classify(status="error", exit_code=1, tool="nuclei",
                             stderr_text="scope_blocked (also: connection reset)")
        self.assertEqual(f.cls, "scope_blocked")
        self.assertFalse(f.retryable)

    def test_deterministic_beats_timeout_on_exit_code(self):
        # 127 is missing-binary, not a timeout, whatever the status says
        f = failure.classify(status="timeout", exit_code=127, tool="dalfox")
        self.assertEqual(f.cls, "tool_missing")


class TestRecycle(unittest.TestCase):
    """The R7-era gap: testing -> proposed (or rejected), never stranded."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-fail-"))
        self.w = _mk(self.root)

    def tearDown(self):
        try:
            self.w.close()
        finally:
            shutil.rmtree(self.root, ignore_errors=True)

    def _state(self, hid: str) -> dict:
        return self.w.get_entity(hid)

    def test_stranded_hypothesis_returns_to_proposed(self):
        hid = _hyp(self.w, "hyp_strand", state="testing", priority=60.0)
        _run(self.w, hid, status="error", exit_code=1)
        self.w.commit()

        recycled, abandoned = failure.recycle_stuck_hypotheses(self.w, ENG)
        self.assertEqual((recycled, abandoned), (1, 0))
        e = self._state(hid)
        self.assertEqual(e["state"], "proposed")
        self.assertEqual(e["priority"], 35.0)      # 60 - 25 penalty
        self.assertEqual(e["attempts"], 1)
        self.assertEqual(e["failure_class"], "strategy_error")
        self.assertEqual(e["recycled_from"], "testing")

    def test_attempts_exhausted_rejects_instead_of_looping(self):
        hid = _hyp(self.w, "hyp_doomed", state="testing", priority=60.0)
        _run(self.w, hid, status="error", exit_code=1)
        self.w.commit()
        for expected in (1, 2):
            r, a = failure.recycle_stuck_hypotheses(self.w, ENG)
            self.assertEqual((r, a), (1, 0))
            # the orchestrator would re-dispatch; simulate it going back to testing
            e = self._state(hid); e["state"] = "testing"; self.w.upsert_entity(e)
        r, a = failure.recycle_stuck_hypotheses(self.w, ENG)
        self.assertEqual((r, a), (0, 1))           # third attempt -> abandoned
        e = self._state(hid)
        self.assertEqual(e["state"], "rejected")
        self.assertIn("abandoned after 3 attempts", e["reject_reason"])

    def test_inflight_run_is_never_recycled(self):
        # Re-planning a live run would double-fire it; for strix that is quota.
        hid = _hyp(self.w, "hyp_live", state="testing")
        self.w.start_tool_run(tool="strix", command="strix -m deep", hypothesis_id=hid)
        self.w.commit()                            # left status='running'
        self.assertEqual(failure.recycle_stuck_hypotheses(self.w, ENG), (0, 0))
        self.assertEqual(self._state(hid)["state"], "testing")

    def test_never_dispatched_is_not_a_failure(self):
        hid = _hyp(self.w, "hyp_idle", state="testing")
        self.w.commit()
        self.assertEqual(failure.recycle_stuck_hypotheses(self.w, ENG), (0, 0))
        self.assertEqual(self._state(hid)["state"], "testing")

    def test_proposed_and_done_are_left_alone(self):
        for st in ("proposed", "done", "rejected"):
            _hyp(self.w, f"hyp_{st}", state=st)
        self.w.commit()
        self.assertEqual(failure.recycle_stuck_hypotheses(self.w, ENG), (0, 0))

    def test_other_engagements_are_untouched(self):
        hid = _hyp(self.w, "hyp_other", state="testing")
        _run(self.w, hid, status="error", exit_code=1)
        self.w.commit()
        self.assertEqual(failure.recycle_stuck_hypotheses(self.w, "some-other-eng"),
                         (0, 0))
        self.assertEqual(self._state(hid)["state"], "testing")

    def test_recovery_is_event_logged(self):
        # Going through upsert_entity (not a raw UPDATE) keeps the append-only
        # log describing what happened — that is the point of the writer path.
        hid = _hyp(self.w, "hyp_audit", state="testing")
        _run(self.w, hid, status="error", exit_code=1)
        self.w.commit()
        before = self.w.conn.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
        failure.recycle_stuck_hypotheses(self.w, ENG)
        after = self.w.conn.execute("SELECT COUNT(*) n FROM events").fetchone()["n"]
        self.assertGreater(after, before, "recovery wrote no event")

    def test_findings_are_never_recycled(self):
        # db.upsert_entity enforces findings are born 'candidate' (promotions go
        # through advance_and_persist), so a finding can never even reach
        # state='testing'; recycle targets hypotheses only. Belt and braces:
        # assert the state machine AND the query both exclude it.
        self.w.upsert_entity({"id": "fnd_x", "kind": "finding",
                              "engagement_id": ENG, "state": "candidate",
                              "url": "https://example.com"})
        self.w.commit()
        self.assertEqual(failure.recycle_stuck_hypotheses(self.w, ENG), (0, 0))
        self.assertEqual(self.w.get_entity("fnd_x")["kind"], "finding")
        self.assertEqual(self.w.get_entity("fnd_x")["state"], "candidate")

    def test_kind_freeze_blocks_a_recovery_that_would_repurpose_a_node(self):
        # F50 / R3 P0-2. Recovery writes through upsert_entity precisely so this
        # guard applies: a hypothesis id can never be re-purposed as a finding,
        # which would silently corrupt the append-only log.
        _hyp(self.w, "hyp_frozen", state="testing")
        self.w.commit()
        with self.assertRaises(ValueError):
            self.w.upsert_entity({"id": "hyp_frozen", "kind": "finding",
                                  "engagement_id": ENG, "state": "candidate"})
        self.assertEqual(self.w.get_entity("hyp_frozen")["kind"], "hypothesis")


class TestDigest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-dig-"))
        self.w = _mk(self.root)

    def tearDown(self):
        try:
            self.w.close()
        finally:
            shutil.rmtree(self.root, ignore_errors=True)

    def test_counts_by_class_and_names_worst_tools(self):
        for i, (tool, code) in enumerate([("nuclei", 1), ("nuclei", 1), ("dalfox", 127)]):
            hid = _hyp(self.w, f"hyp_{i}", state="testing", tool=tool)
            _run(self.w, hid, tool=tool, status="error", exit_code=code)
        self.w.commit()
        d = failure.build_digest(self.w, ENG)
        self.assertEqual(d.by_class.get("tool_error"), 2)
        self.assertEqual(d.by_class.get("tool_missing"), 1)
        self.assertEqual(d.worst_tools[0], ("nuclei", 2))
        self.assertEqual(d.stuck_testing, 3)

    def test_read_only_by_default(self):
        hid = _hyp(self.w, "hyp_ro", state="testing")
        _run(self.w, hid, status="error", exit_code=1)
        self.w.commit()
        d = failure.build_digest(self.w, ENG)          # recover defaults False
        self.assertEqual((d.recycled, d.abandoned), (0, 0))
        self.assertEqual(self.w.get_entity(hid)["state"], "testing",
                         "read-only digest mutated the graph")

    def test_recover_requires_a_writer_not_a_raw_connection(self):
        hid = _hyp(self.w, "hyp_needs_writer", state="testing")
        _run(self.w, hid, status="error", exit_code=1)
        self.w.commit()
        with self.assertRaises(TypeError):
            failure.build_digest(self.w.conn, ENG, recover=True)

    def test_recover_pass_updates_stuck_count(self):
        hid = _hyp(self.w, "hyp_rec", state="testing")
        _run(self.w, hid, status="error", exit_code=1)
        self.w.commit()
        d = failure.build_digest(self.w, ENG, recover=True)
        self.assertEqual(d.recycled, 1)
        self.assertEqual(d.stuck_testing, 0)

    def test_prompt_lines_warn_about_deterministic_classes(self):
        hid = _hyp(self.w, "hyp_p", state="testing", tool="dalfox")
        _run(self.w, hid, tool="dalfox", status="error", exit_code=127)
        self.w.commit()
        lines = failure.build_digest(self.w, ENG).prompt_lines()
        self.assertTrue(lines)
        joined = "\n".join(lines)
        self.assertIn("tool_missing", joined)
        self.assertIn("Do not re-propose", joined)
        self.assertLess(len(joined), 2048, "digest exceeds the prompt budget")

    def test_empty_graph_yields_no_prompt_lines(self):
        self.assertEqual(failure.build_digest(self.w, ENG).prompt_lines(), [])
        self.assertTrue(failure.build_digest(self.w, ENG).is_empty())

    def test_expensive_timeout_is_judged_on_the_declared_budget(self):
        # The 7200s budget lives on the RULE's action, not on tool_run; the
        # digest must recover it via the hypothesis's actions or strix timeouts
        # would look cheap and get blind-retried.
        hid = _hyp(self.w, "hyp_strix", state="testing", tool="strix", timeout=7200)
        _run(self.w, hid, tool="strix", status="timeout", exit_code=124)
        self.w.commit()
        d = failure.build_digest(self.w, ENG)
        self.assertEqual(d.by_class.get("tool_timeout"), 1)
        fs = failure.scan_tool_runs(self.w, ENG)
        self.assertEqual(len(fs), 1)
        self.assertFalse(fs[0].retryable, "strix 7200s timeout must not blind-retry")


class TestAgainstRealEngagementSchema(unittest.TestCase):
    """Schema-drift guard: run on a COPY of production data.

    ``entities`` has no ``props`` column — ``state``/``priority`` are columns
    and domain fields live in ``data``. The first cut of failure.py queried
    ``h.props`` and its ``except sqlite3.Error: return 0, 0`` turned that into
    a silent no-op indistinguishable from "nothing to recover".
    """

    @classmethod
    def setUpClass(cls):
        cls.real_root = db.default_root()
        cls.src = None
        if cls.real_root and cls.real_root.is_dir():
            for p in sorted(cls.real_root.iterdir()):
                if p.name.startswith("_") or not p.is_dir():
                    continue
                g = p / "graph.db"
                if not g.is_file():
                    continue
                try:
                    con = sqlite3.connect(f"file:{g}?mode=ro", uri=True)
                    n = con.execute("SELECT COUNT(*) FROM entities "
                                    "WHERE kind='hypothesis' AND state='testing'"
                                    ).fetchone()[0]
                    con.close()
                except sqlite3.Error:
                    continue
                if n:
                    cls.src, cls.eng, cls.stranded = g, p.name, n
                    break

    def setUp(self):
        if not self.src:
            self.skipTest("no real engagement with stranded testing hypotheses")
        self.root = Path(tempfile.mkdtemp(prefix="motoko-real-"))
        self.g = self.root / "graph.db"
        # Copy the WAL/SHM sidecars too. Real engagements are left with a
        # graph.db-wal by writers that never cleanly checkpointed, so copying
        # only the main db can yield a snapshot missing its tail — the test
        # would then assert against data the engine never actually had.
        # NEVER touch production data: everything below is a temp copy.
        shutil.copy2(self.src, self.g)
        for suffix in ("-wal", "-shm"):
            side = Path(str(self.src) + suffix)
            if side.exists():
                shutil.copy2(side, Path(str(self.g) + suffix))
        self.w = db.Database(self.g)

    def tearDown(self):
        try:
            self.w.close()
        finally:
            shutil.rmtree(self.root, ignore_errors=True)

    def test_real_schema_has_no_props_column(self):
        cols = {r[1] for r in self.w.conn.execute("PRAGMA table_info(entities)")}
        self.assertNotIn("props", cols)
        self.assertIn("data", cols)
        self.assertIn("state", cols)
        self.assertIn("priority", cols)

    def test_digest_reads_real_data_without_raising(self):
        d = failure.build_digest(self.w, self.eng)
        self.assertEqual(d.read_errors, 0, "digest degraded on the real schema")
        self.assertEqual(d.stuck_testing, self.stranded)

    def test_recovery_actually_acts_on_the_stranded_nodes(self):
        before = self.w.conn.execute(
            "SELECT COUNT(*) n FROM entities WHERE kind='hypothesis' "
            "AND state='testing' AND engagement_id=?", (self.eng,)).fetchone()["n"]
        self.assertGreater(before, 0)
        recycled, abandoned = failure.recycle_stuck_hypotheses(self.w, self.eng)
        after = self.w.conn.execute(
            "SELECT COUNT(*) n FROM entities WHERE kind='hypothesis' "
            "AND state='testing' AND engagement_id=?", (self.eng,)).fetchone()["n"]
        # Either the node moved, or it was legitimately still in flight / never
        # dispatched — but the pass must not be a silent no-op on a graph that
        # graph_health is already reporting as stuck.
        if recycled == abandoned == 0:
            inflight = self.w.conn.execute(
                f"SELECT COUNT(*) n FROM entities h WHERE h.kind='hypothesis' "
                f"AND h.state='testing' AND h.engagement_id=? AND EXISTS "
                f"(SELECT 1 FROM tool_run tr WHERE tr.hypothesis_id=h.id)",
                (self.eng,)).fetchone()["n"]
            self.assertEqual(inflight, 0,
                             "recycle did nothing on a graph with dispatched runs")
        self.assertEqual(after, before - recycled)
        if recycled:
            self.assertEqual(after, before - recycled)

    def test_recycled_node_keeps_its_domain_payload(self):
        # upsert_entity re-serializes domain fields into `data`; a regression
        # here would silently drop actions/rule_id and re-propose an empty node.
        recycled, _ = failure.recycle_stuck_hypotheses(self.w, self.eng)
        if not recycled:
            self.skipTest("nothing recyclable in this engagement")
        e = self.w.conn.execute(
            "SELECT data FROM entities WHERE kind='hypothesis' AND state='proposed' "
            "AND engagement_id=? AND data LIKE '%recycled_from%' LIMIT 1",
            (self.eng,)).fetchone()
        self.assertIsNotNone(e)
        import json
        payload = json.loads(e["data"])
        self.assertEqual(payload.get("recycled_from"), "testing")
        self.assertIn("attempts", payload)
        # the domain payload must survive the round-trip
        self.assertTrue(payload.get("actions") or payload.get("rule_id")
                        or payload.get("statement"),
                        f"domain payload lost on recycle: {sorted(payload)}")

    def test_states_stay_inside_the_known_vocabulary(self):
        failure.recycle_stuck_hypotheses(self.w, self.eng)
        states = {r[0] for r in self.w.conn.execute(
            "SELECT DISTINCT state FROM entities WHERE kind='hypothesis' "
            "AND engagement_id=?", (self.eng,))}
        self.assertTrue(states <= {"proposed", "testing", "done", "error",
                                   "timeout", "rejected"},
                        f"recovery invented states: {states}")


class TestOrchestratorWiring(unittest.TestCase):
    """R3 integration: the recovery pass must actually run inside the loop, and
    the reflector contract must stay backward compatible."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-wire-"))
        db.init_engagement(self.root, ENG, name="wire", in_scope=["example.com"])
        self.rules = Path(__file__).resolve().parents[1] / "rules"

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _orch(self, reflector=None):
        from motoko.orchestrator import Orchestrator
        return Orchestrator(ENG, root=self.root, rules_dir=self.rules,
                            reflector=reflector)

    def _seed_stranded(self):
        w = db.Database(db.engagement_dir(self.root, ENG) / "graph.db")
        hid = _hyp(w, "hyp_stranded", state="testing", priority=60.0)
        _run(w, hid, status="error", exit_code=1)
        w.commit(); w.close()
        return hid

    def test_probe_accepts_only_reflectors_that_take_the_keyword(self):
        from motoko.orchestrator import _accepts_failure_lines

        def two_arg(view, engagement_id): ...
        def kwarg_reflector(view, engagement_id, failure_lines=None): ...
        def varkw(view, engagement_id, **kw): ...

        self.assertFalse(_accepts_failure_lines(None))
        self.assertFalse(_accepts_failure_lines(two_arg))
        self.assertTrue(_accepts_failure_lines(kwarg_reflector))
        self.assertTrue(_accepts_failure_lines(varkw))
        # a builtin/C callable must not blow up construction
        self.assertFalse(_accepts_failure_lines(len))

    def test_recover_failures_unstrands_within_the_same_run(self):
        hid = self._seed_stranded()
        orch = self._orch()
        try:
            orch._recover_failures()
            e = orch.writer.get_entity(hid)
            self.assertEqual(e["state"], "proposed")
            self.assertEqual(e["priority"], 35.0)
            self.assertIsNotNone(orch._failure_digest)
            # the recovery must be auditable in the event log
            kinds = {r["kind"] for r in orch.writer.conn.execute(
                "SELECT kind FROM events")}
            self.assertIn("failure_recovery", kinds)
        finally:
            orch.close()

    def test_recovery_runs_before_prioritize_so_it_helps_this_run(self):
        # The whole point of moving it out of the end-of-run health sweep: the
        # recycled node must be visible to _prioritize in the same cycle.
        hid = self._seed_stranded()
        orch = self._orch()
        try:
            src = Path(orchestrator.__file__).read_text(encoding="utf-8")
            i_recover = src.index("self._recover_failures()")
            i_prio = src.index("batch = self._prioritize()")
            self.assertLess(i_recover, i_prio,
                            "_recover_failures must precede _prioritize in run()")
            orch.run(max_cycles=1)
            self.assertNotEqual(orch.writer.get_entity(hid)["state"], "testing")
        finally:
            orch.close()

    def test_legacy_two_arg_reflector_still_works(self):
        # Backward compat: pre-R3 reflectors (and every existing test stub) take
        # only (view, engagement_id) and must not be passed the new keyword.
        calls = []

        def legacy(view, engagement_id):
            calls.append(("legacy", engagement_id))

        self._seed_stranded()
        orch = self._orch(reflector=legacy)
        try:
            self.assertFalse(orch._reflector_takes_failures)
            orch._recover_failures()
            orch._reflect_if_needed(force=True)      # must not raise TypeError
            self.assertEqual(len(calls), 1)
        finally:
            orch.close()

    def test_modern_reflector_receives_the_failure_digest(self):
        seen = {}

        def modern(view, engagement_id, failure_lines=None):
            seen["lines"] = failure_lines
            seen["view_has_writer"] = hasattr(view, "upsert_entity")

        self._seed_stranded()
        orch = self._orch(reflector=modern)
        try:
            self.assertTrue(orch._reflector_takes_failures)
            orch._recover_failures()
            orch._reflect_if_needed(force=True)
            self.assertIsInstance(seen["lines"], list)
            self.assertTrue(seen["lines"], "reflector got no failure context")
            self.assertIn("Do not re-propose", "\n".join(seen["lines"]))
            # P0-1/F04: the reflector still must not be able to reach the writer
            self.assertFalse(seen["view_has_writer"],
                             "reflector was handed a write-capable view")
        finally:
            orch.close()

    def test_a_raising_recovery_never_takes_the_loop_down(self):
        self._seed_stranded()
        orch = self._orch()
        try:
            with unittest.mock.patch.object(
                    failure, "build_digest", side_effect=RuntimeError("boom")):
                orch._recover_failures()             # must swallow
            self.assertIsNone(orch._failure_digest)
            orch.run(max_cycles=1)                   # loop still runs
        finally:
            orch.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
