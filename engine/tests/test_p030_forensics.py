"""P-030 regression tests — production forensics round (2026-09-11).

Four P0 fixes, each pinned to a live-run failure mode:

1. hypothesis closure: a finished tool_run retires its hypothesis out of
   'testing' (92 hypotheses stalled forever before).
2. dedup key: distinct CVEs must produce distinct keys (10 CVE rows
   collapsed onto one key ffb38c36… before).
3. ingest-strix: findings go through dedup (duplicates bump the primary,
   new ones are kept) instead of a bare upsert.
4. per-tool proxy policy: gau keeps proxy vars, every other tool strips
   them (engine-side P-023).

P-030-R2 (grok round-2 micro-patch) additions: all-blocked retirement
via the production _act path (T-H1a), partial-blocked retirement
(T-H1b, replacing the round-1 stall lock), _act-entry retirement
(T-ACT), duplicate_of as an edge + honest docstring (M1), and the
frozen legacy-key sha1 literal (M2). T-ARGV/T-ASSET live in
tests/test_p030_micro.py.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import db as motoko_db
from motoko import util
from motoko.dedup import compute_dedup_key
from motoko.executor import SubprocessExecutor, _PROXY_TOOLS


class TestDedupKeyCve(unittest.TestCase):
    def test_distinct_cves_get_distinct_keys(self):
        base = {"class": "vuln.cve_reported", "url": "", "param": "", "sink": ""}
        k1 = compute_dedup_key({**base, "cve": "CVE-2022-23137"})
        k2 = compute_dedup_key({**base, "cve": "CVE-2026-44409"})
        self.assertNotEqual(k1, k2)

    def test_same_cve_stable_and_normalized(self):
        k1 = compute_dedup_key({"class": "v", "cve": "CVE-2021-21742"})
        k2 = compute_dedup_key({"class": "v", "cve": " cve-2021-21742 "})
        self.assertEqual(k1, k2)

    def test_cve_absent_matches_legacy_4section_key(self):
        # P-030-R H3 / P-030-R2 M2: a cve-less finding must reuse the legacy
        # key byte for byte. The literal below is sha1("xss|https://h/p|q|s")
        # FROZEN per the round-2 adjudication — recomputing it from
        # endpoint_template at test time would let any drift in the
        # normalizer pass unnoticed.
        f = {"class": "xss", "url": "https://h/p", "param": "q", "sink": "s"}
        self.assertEqual(
            compute_dedup_key(f),
            "2d538afda070bd6937c0cd08b774b496e6292e34")


class TestHypothesisClosure(unittest.TestCase):
    """P-030-R: aggregated retirement via Orchestrator method — the
    production path _act calls after its action loop."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.w = motoko_db.Database(self.root / "graph.db")
        self.w.init_schema()
        self.w.set_scope("t-eng", name="t", in_scope=["example.com.cn"],
                         out_of_scope=[], intensity="normal", max_depth=3,
                         concurrency=4, oob_domain=None, config={})
        from motoko.orchestrator import Orchestrator
        self.orch = Orchestrator.__new__(Orchestrator)   # no __init__ side effects
        self.orch.writer = self.w
        self.orch.engagement_id = "t-eng"

    def _hyp(self, n_actions=2):
        hyp = {"id": util.new_id("hypothesis"), "kind": "hypothesis",
               "engagement_id": "t-eng", "state": "testing",
               "rule_id": "R-RECON-SUB-001",
               "actions": [{"tool": t} for t in
                           ("subfinder", "amass")[:n_actions]]}
        self.w.upsert_entity(hyp)
        return hyp

    def tearDown(self):
        self.w.close()
        self.tmp.cleanup()

    def test_partial_blocked_retires_done(self):
        # P-030-R2 T-H1b (grok): REPLACES the round-1 lock
        # test_two_actions_partial_stays_testing, which pinned the stall
        # the adjudication killed. 2 declared actions, only ONE run ever
        # started and it is done, the second action is blocked (no target
        # / scope refusal) — the blocked action casts no vote, so the
        # hypothesis retires as done instead of staying testing forever.
        hyp = self._hyp(2)
        rid = self.w.start_tool_run(tool="subfinder", command="c1",
                                    hypothesis_id=hyp["id"])
        self.w.finish_tool_run(rid, status="done", exit_code=0)
        self.orch._retire_hypothesis_if_complete(hyp, expected=1)
        self.assertEqual(self.w.get_entity(hyp["id"]).get("state"), "done")

    def test_all_done_retires_done(self):
        hyp = self._hyp(2)
        for tool in ("subfinder", "amass"):
            rid = self.w.start_tool_run(tool=tool, command="c",
                                        hypothesis_id=hyp["id"])
            self.w.finish_tool_run(rid, status="done", exit_code=0)
        self.orch._retire_hypothesis_if_complete(hyp)
        self.assertEqual(self.w.get_entity(hyp["id"]).get("state"), "done")

    def test_any_error_beats_done(self):
        hyp = self._hyp(2)
        r1 = self.w.start_tool_run(tool="subfinder", command="c",
                                   hypothesis_id=hyp["id"])
        self.w.finish_tool_run(r1, status="done", exit_code=0)
        r2 = self.w.start_tool_run(tool="amass", command="c",
                                   hypothesis_id=hyp["id"])
        self.w.finish_tool_run(r2, status="error", exit_code=127)
        self.orch._retire_hypothesis_if_complete(hyp)
        self.assertEqual(self.w.get_entity(hyp["id"]).get("state"), "error")

    def test_timeout_is_own_state_not_error(self):
        hyp = self._hyp(2)
        r1 = self.w.start_tool_run(tool="subfinder", command="c",
                                   hypothesis_id=hyp["id"])
        self.w.finish_tool_run(r1, status="done", exit_code=0)
        r2 = self.w.start_tool_run(tool="amass", command="c",
                                   hypothesis_id=hyp["id"])
        self.w.finish_tool_run(r2, status="timeout", exit_code=-15)
        self.orch._retire_hypothesis_if_complete(hyp)
        # timeout, NOT error — _expand's P-015 re-mint distinguishes them
        self.assertEqual(self.w.get_entity(hyp["id"]).get("state"), "timeout")

    def test_running_run_keeps_testing(self):
        hyp = self._hyp(2)
        self.w.start_tool_run(tool="subfinder", command="c",
                              hypothesis_id=hyp["id"])
        r2 = self.w.start_tool_run(tool="amass", command="c",
                                   hypothesis_id=hyp["id"])
        self.w.finish_tool_run(r2, status="done", exit_code=0)
        # subfinder still 'running' -> stay testing
        self.orch._retire_hypothesis_if_complete(hyp)
        self.assertEqual(self.w.get_entity(hyp["id"]).get("state"), "testing")

    def test_finish_tool_run_does_NOT_retire(self):
        # P-030-R: executor._finish_tool_run must ONLY close the run row
        from motoko.executor import SubprocessExecutor
        hyp = self._hyp(2)
        rid = self.w.start_tool_run(tool="subfinder", command="c",
                                    hypothesis_id=hyp["id"])
        ex = SubprocessExecutor(self.w, "t-eng", self.root / "obs")
        ex._finish_tool_run({"_tool_run_id": rid}, status="done", exit_code=0)
        self.assertEqual(self.w.get_entity(hyp["id"]).get("state"), "testing")


class TestAllBlockedRetiresDone(unittest.TestCase):
    """P-030-R2 T-H1a (grok): an all-blocked hypothesis driven through the
    PRODUCTION _act path retires as done with zero tool_run rows — never
    stuck in testing, never error/timeout (those would re-mint forever
    against a scope that keeps refusing)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.w = motoko_db.Database(self.root / "graph.db")
        self.w.init_schema()
        self.w.set_scope("t-eng", name="t", in_scope=["example.com.cn"],
                         out_of_scope=[], intensity="normal", max_depth=3,
                         concurrency=4, oob_domain=None, config={})
        from motoko.orchestrator import Orchestrator
        self.orch = Orchestrator.__new__(Orchestrator)   # no __init__ side effects
        self.orch.writer = self.w
        self.orch.engagement_id = "t-eng"

    def tearDown(self):
        self.w.close()
        self.tmp.cleanup()

    def _hyp(self, n_actions=2):
        # actions deliberately carry NO url/host/ip/asset_id — every one
        # of them takes the no-structured-target block inside _act.
        hyp = {"id": util.new_id("hypothesis"), "kind": "hypothesis",
               "engagement_id": "t-eng", "state": "proposed",
               "rule_id": "R-RECON-SUB-001",
               "actions": [{"tool": t} for t in
                           ("subfinder", "amass")[:n_actions]]}
        self.w.upsert_entity(hyp)
        return hyp

    def test_all_blocked_via_act_retires_done_zero_runs(self):
        hyp = self._hyp(2)
        self.orch._act([hyp])
        row = self.w.get_entity(hyp["id"])
        self.assertEqual(row.get("state"), "done",
                         "all-blocked hypothesis did not retire as done")
        runs = self.w.conn.execute(
            "SELECT COUNT(*) c FROM tool_run WHERE hypothesis_id = ?",
            (hyp["id"],)).fetchone()["c"]
        self.assertEqual(runs, 0, "a blocked action started a tool_run")
        blocked = self.w.conn.execute(
            "SELECT COUNT(*) c FROM events WHERE kind='scope_blocked'"
        ).fetchone()["c"]
        self.assertEqual(blocked, 2, "each blocked action must be on the log")


class TestActEntryRetirement(unittest.TestCase):
    """P-030-R2 T-ACT (grok, round-1 P0-1 debt): drive a hypothesis
    through the REAL _act entry — one action whose stub executor finishes
    its tool_run as done — and assert the hypothesis is NOT testing after
    _act returns. If _act ever stops calling _retire_hypothesis_if_complete
    (the round-1 bug: tests only covered the direct-call path), this goes
    red."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.w = motoko_db.Database(self.root / "graph.db")
        self.w.init_schema()
        self.w.set_scope("t-eng", name="t", in_scope=["example.com.cn"],
                         out_of_scope=[], intensity="normal", max_depth=3,
                         concurrency=4, oob_domain=None, config={})
        from motoko.orchestrator import Orchestrator
        self.orch = Orchestrator.__new__(Orchestrator)   # no __init__ side effects
        self.orch.writer = self.w
        self.orch.engagement_id = "t-eng"
        # guard stub: example.com.cn is allowed — gate logic only, no DNS
        from motoko.scope import ScopeDecision

        class _Guard:
            def check_url(self, url):
                return ScopeDecision(True, "stub allow",
                                     detail={"bind_ip": "10.0.0.5"})

            def check_host(self, host):
                return ScopeDecision(True, "stub allow")

            def check_ip(self, ip):
                return ScopeDecision(True, "stub allow")

            def check_asset(self, asset):
                return ScopeDecision(True, "stub allow")

        self.orch.guard = _Guard()

    def tearDown(self):
        self.w.close()
        self.tmp.cleanup()

    def test_act_entry_retires_finished_hypothesis(self):
        def stub_executor(hyp, action):
            self.w.finish_tool_run(action["_tool_run_id"],
                                   status="done", exit_code=0)

        self.orch.executor = stub_executor
        hyp = {"id": util.new_id("hypothesis"), "kind": "hypothesis",
               "engagement_id": "t-eng", "state": "proposed",
               "rule_id": "R-RECON-SUB-001",
               "url": "https://www.example.com.cn/",
               "actions": [{"tool": "subfinder",
                            "cmd": "subfinder -d {url}"}]}
        self.w.upsert_entity(hyp)
        self.orch._act([hyp])
        row = self.w.get_entity(hyp["id"])
        self.assertNotEqual(row.get("state"), "testing",
                            "_act returned with the hypothesis still "
                            "testing — retirement call is missing from "
                            "the production path")


class TestIngestDuplicateEdge(unittest.TestCase):
    """P-030-R2 M1 (grok): a duplicate is an EDGE + counter, never a new
    finding row, and the docstring must not claim parity it does not
    have."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.w = motoko_db.Database(self.root / "graph.db")
        self.w.init_schema()
        self.w.set_scope("t-eng", name="t", in_scope=["example.com.cn"],
                         out_of_scope=[], intensity="normal", max_depth=3,
                         concurrency=4, oob_domain=None, config={})
        from motoko.cli import ingest_strix_findings
        self.ingest = ingest_strix_findings

    def tearDown(self):
        self.w.close()
        self.tmp.cleanup()

    def _finding(self, title="t"):
        return {"class": "vuln.strix_confirmed", "title": title,
                "url": "https://job.example.com.cn", "severity": "medium"}

    def test_duplicate_is_edge_not_event_and_no_new_row(self):
        kept, dups = self.ingest(self.w,
                                 [self._finding(title="A"),
                                  self._finding(title="A-dup")], "t-eng")
        self.assertEqual((kept, dups), (1, 1))
        rows = self.w.query_entities(kind="finding", engagement_id="t-eng")
        self.assertEqual(len(rows), 1, "a duplicate created a second row")
        self.assertEqual(rows[0].get("duplicate_count"), 1)
        self.assertEqual(rows[0].get("state"), "triaged")
        # the duplicate_of link is an EDGE from the dup's minted id
        edges = self.w.get_edges(rel="duplicate_of")
        self.assertEqual(len(edges), 1,
                         "no duplicate_of edge was written for the dup")
        self.assertEqual(edges[0]["to_id"], rows[0]["id"])
        self.assertNotEqual(edges[0]["from_id"], rows[0]["id"],
                            "the edge must not loop onto the primary")
        n = self.w.conn.execute(
            "SELECT COUNT(*) c FROM events WHERE kind='duplicate_of'"
        ).fetchone()["c"]
        self.assertEqual(n, 0, "duplicate_of was also written as an event")

    def test_docstring_admits_remaining_deltas(self):
        import inspect
        from motoko import cli as _cli
        doc = inspect.getdoc(_cli.ingest_strix_findings) or ""
        self.assertNotIn("identical", doc,
                         "docstring still claims parity it does not have")
        self.assertIn("_asset_id_for_url", doc,
                      "docstring no longer names the asset-link delta")


class TestIngestStrixFindings(unittest.TestCase):
    """P-030-R H2/H5: tests call the PRODUCTION ingest_strix_findings —
    no more re-implemented gate loops that stay green while production
    drifts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.w = motoko_db.Database(self.root / "graph.db")
        self.w.init_schema()
        self.w.set_scope("t-eng", name="t", in_scope=["example.com.cn"],
                         out_of_scope=[], intensity="normal", max_depth=3,
                         concurrency=4, oob_domain=None, config={})
        from motoko.cli import ingest_strix_findings
        self.ingest = ingest_strix_findings

    def tearDown(self):
        self.w.close()
        self.tmp.cleanup()

    def _finding(self, cve=None, title="t"):
        f = {"class": "vuln.strix_confirmed", "title": title,
             "url": "https://job.example.com.cn", "severity": "medium"}
        if cve:
            f["cve"] = cve
        return f

    def test_duplicate_bumps_primary_not_new_row(self):
        kept, dups = self.ingest(self.w,
                                 [self._finding(title="A"),
                                  self._finding(title="A-dup")], "t-eng")
        self.assertEqual((kept, dups), (1, 1))
        rows = self.w.query_entities(kind="finding", engagement_id="t-eng")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("duplicate_count"), 1)
        self.assertEqual(rows[0].get("state"), "triaged")

    def test_new_finding_advances_to_triaged(self):
        # P-030-R H5: dedup_pass must be wired — the a production graph graph had
        # 25/25 findings stuck at candidate with entity.transition = 0.
        kept, dups = self.ingest(self.w, [self._finding(title="X")], "t-eng")
        self.assertEqual((kept, dups), (1, 0))
        row = self.w.query_entities(kind="finding", engagement_id="t-eng")[0]
        self.assertEqual(row.get("state"), "triaged")
        n = self.w.conn.execute(
            "SELECT COUNT(*) c FROM events WHERE kind='entity.transition'"
        ).fetchone()["c"]
        self.assertGreaterEqual(n, 1)

    def test_distinct_cves_both_kept(self):
        kept, dups = self.ingest(self.w, [
            self._finding(cve="CVE-2022-23137", title="c1"),
            self._finding(cve="CVE-2026-44409", title="c2")], "t-eng")
        self.assertEqual((kept, dups), (2, 0))


class TestProxyPolicy(unittest.TestCase):
    def test_gau_is_proxy_tool(self):
        self.assertIn("gau", _PROXY_TOOLS)

    def test_domestic_tools_not_proxy(self):
        for t in ("subfinder", "amass", "httpx", "nuclei", "nmap", "katana"):
            self.assertNotIn(t, _PROXY_TOOLS, t)

    def test_env_stripping_in_executor(self):
        # run printenv through the real executor with proxy vars inherited:
        # a DIRECT tool must NOT see them in its child environment.
        os.environ["http_proxy"] = "http://127.0.0.1:18080"
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:18080"
        tmp = tempfile.TemporaryDirectory()
        try:
            w = motoko_db.Database(Path(tmp.name) / "g.db")
            w.init_schema()
            w.set_scope("t-eng", name="t", in_scope=["example.com.cn"],
                        out_of_scope=[], intensity="normal", max_depth=3,
                        concurrency=4, oob_domain=None, config={})
            ex = SubprocessExecutor(w, "t-eng", Path(tmp.name) / "obs",
                                    tool_timeout=10)
            action = {"tool": "printenv", "url": "https://job.example.com.cn",
                      "host": "job.example.com.cn", "argv": ["printenv"]}
            action["_tool_run_id"] = w.start_tool_run(
                tool="printenv", command="printenv")
            ex({}, action)
            row = w.conn.execute(
                "SELECT raw_path FROM observations ORDER BY created_at DESC"
            ).fetchone()
            child_env = Path(row["raw_path"]).read_text()
            self.assertNotIn("http_proxy", child_env)
            self.assertNotIn("HTTPS_PROXY", child_env)
        finally:
            tmp.cleanup()
            del os.environ["http_proxy"]
            del os.environ["HTTPS_PROXY"]

    def test_env_policy_matrix(self):
        # direct: matrix of proxy vars present -> stripped for non-proxy tools
        import subprocess as sp
        env = dict(os.environ)
        env["http_proxy"] = "http://127.0.0.1:18080"
        env["https_proxy"] = "http://127.0.0.1:18080"
        # emulate the executor's strip for a non-proxy tool
        stripped = dict(env)
        for k in list(stripped):
            if k.lower() in ("http_proxy", "https_proxy", "all_proxy"):
                del stripped[k]
        out = sp.run(["printenv"], env=stripped, capture_output=True, text=True)
        self.assertNotIn("http_proxy", out.stdout)
        self.assertNotIn("https_proxy", out.stdout)
        # proxy tool keeps them
        out2 = sp.run(["printenv"], env=env, capture_output=True, text=True)
        self.assertIn("http_proxy", out2.stdout)


if __name__ == "__main__":
    unittest.main()
