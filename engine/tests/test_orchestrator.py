"""Hypothesis engine + orchestrator tests.

Run:  python3 tests/test_orchestrator.py
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
RULES = Path(__file__).resolve().parents[1] / "rules"

from motoko import db  # noqa: E402
from motoko.hypothesis_engine import HypothesisEngine  # noqa: E402
from motoko.orchestrator import Orchestrator  # noqa: E402


class TestHypothesisEngine(unittest.TestCase):
    def test_rule_count(self):
        e = HypothesisEngine(RULES)
        self.assertGreaterEqual(e.rule_count(), 30)
        # all five categories present
        ids = " ".join(r["id"] for r in e.rules)
        self.assertIn("R-TECH", ids)
        self.assertIn("R-VULN", ids)
        self.assertIn("R-ACC", ids)
        self.assertIn("R-CHAIN", ids)
        self.assertIn("R-CTX", ids)

    def test_spring_rule_fires(self):
        e = HypothesisEngine(RULES)
        hyps = e.generate({"tech": ["spring", "nginx"]})
        self.assertTrue(any(h["rule_id"] == "R-TECH-SPRING-001" for h in hyps))

    def test_ssrf_rule_fires(self):
        e = HypothesisEngine(RULES)
        hyps = e.generate({"class": "ssrf.basic"})
        self.assertTrue(any(h["rule_id"] == "R-VULN-SSRF-VERIFY-001" for h in hyps))

    def test_no_condition_no_fire(self):
        e = HypothesisEngine(RULES)
        hyps = e.generate({"tech": ["unknown_stack"]})
        # no rule should fire on an unknown stack with no class/service
        self.assertEqual(hyps, [])

    def test_chain_requires_cloud(self):
        e = HypothesisEngine(RULES)
        # SSRF without cloud: verify fires, cloud-chain does not
        hyps = e.generate({"class": "ssrf.basic"})
        self.assertFalse(any(h["rule_id"] == "R-CHAIN-SSRF-CLOUD" for h in hyps))
        hyps = e.generate({"class": "ssrf.basic", "cloud": True})
        self.assertTrue(any(h["rule_id"] == "R-CHAIN-SSRF-CLOUD" for h in hyps))


class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-orch-"))
        self.eng = "eng-orch"
        db.init_engagement(
            self.root, self.eng, name="orch",
            in_scope=["example.com", "10.0.0.0/24"],
            out_of_scope=["partner.example.com"],
        )

    def test_run_seeds_and_expands(self):
        # seed an asset + service so tech rules can fire
        w = db.Database(db.engagement_dir(self.root, self.eng) / "graph.db")
        aid = w.upsert_entity({
            "id": "ast_seed", "kind": "asset", "engagement_id": self.eng,
            "state": "active", "type": "url", "value": "https://api.example.com",
            "tech": ["spring", "nginx"], "frontier": True,
        })
        w.add_service({"asset_id": aid, "port": 443, "service_name": "https"})
        w.commit()
        w.close()

        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES)
        try:
            summary = orch.run(max_cycles=3)
        finally:
            orch.close()

        # a hypothesis should have been proposed by the spring rule
        self.assertGreaterEqual(summary["hypotheses"], 1)

    def test_scope_block_recorded(self):
        w = db.Database(db.engagement_dir(self.root, self.eng) / "graph.db")
        aid = w.upsert_entity({
            "id": "ast_seed", "kind": "asset", "engagement_id": self.eng,
            "state": "active", "type": "url", "value": "https://evil.com",
            "tech": ["spring"], "frontier": True,
        })
        w.commit()
        w.close()

        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES)
        try:
            orch.run(max_cycles=3)
            # scope_blocked events should exist for the out-of-scope URL
            blocked = orch.writer.conn.execute(
                "SELECT COUNT(*) c FROM events WHERE kind='scope_blocked'").fetchone()["c"]
        finally:
            orch.close()
        self.assertGreaterEqual(blocked, 1)


class TestTargetGuard(unittest.TestCase):
    """F01: ACT refuses actions without a structured target, and non-HTTP
    targets are resolved to the guard's host/ip/asset checks."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-act-"))
        self.eng = "eng-act"
        db.init_engagement(
            self.root, self.eng, name="act",
            in_scope=["example.com", "10.0.0.0/24"],
            out_of_scope=["partner.example.com"],
        )

    def _orch(self, calls):
        # resolver stubbed empty: gate logic only, no live DNS in tests
        return Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            executor=lambda h, a: calls.append(a),
                            resolver=lambda h: [])

    def _counts(self, orch):
        blocked = orch.writer.conn.execute(
            "SELECT COUNT(*) c FROM events WHERE kind='scope_blocked'").fetchone()["c"]
        runs = orch.writer.conn.execute(
            "SELECT COUNT(*) c FROM tool_run").fetchone()["c"]
        return blocked, runs

    def test_guard_bind_ip_is_handed_to_the_executor(self):
        # R3 H3: the address the guard cleared travels with the action.
        calls: list = []
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            executor=lambda h, a: calls.append(a),
                            resolver=lambda h: ["10.0.0.5"])
        try:
            hyp = {"id": "hyp_bind", "kind": "hypothesis", "engagement_id": self.eng,
                   "state": "proposed", "url": "https://app.example.com/x",
                   "actions": [{"tool": "nuclei", "cmd": "nuclei -u {url}"}]}
            orch.writer.upsert_entity(hyp)
            orch._act([hyp])
        finally:
            orch.close()
        self.assertEqual(len(calls), 1, "the in-scope action did not run")
        self.assertEqual(calls[0].get("bind_ip"), "10.0.0.5",
                         "the guard's bind_ip did not reach the executor")

    def test_action_without_state_target_is_rejected(self):
        calls: list = []
        orch = self._orch(calls)
        try:
            hyp = {"id": "hyp_notarget", "kind": "hypothesis",
                   "engagement_id": self.eng, "state": "proposed",
                   "actions": [{"tool": "shell", "cmd": "id"}]}
            orch.writer.upsert_entity(hyp)
            orch._act([hyp])
            blocked, runs = self._counts(orch)
        finally:
            orch.close()
        self.assertEqual(blocked, 1, "no target should have been recorded as scope_blocked")
        self.assertEqual(runs, 0, "action without a target was executed")
        self.assertEqual(calls, [], "executor ran without a target")

    def test_non_http_action_goes_through_the_asset_check(self):
        calls: list = []
        orch = self._orch(calls)
        try:
            w = orch.writer
            w.upsert_entity({"id": "ast_in", "kind": "asset", "engagement_id": self.eng,
                             "state": "active", "type": "domain", "value": "app.example.com"})
            w.upsert_entity({"id": "ast_out", "kind": "asset", "engagement_id": self.eng,
                             "state": "active", "type": "domain", "value": "evil.com"})
            hyp_in = {"id": "hyp_in", "kind": "hypothesis", "engagement_id": self.eng,
                      "state": "proposed", "asset_id": "ast_in",
                      "actions": [{"tool": "enum4linux", "cmd": "enum4linux -a app.example.com"}]}
            hyp_out = {"id": "hyp_out", "kind": "hypothesis", "engagement_id": self.eng,
                       "state": "proposed", "asset_id": "ast_out",
                       "actions": [{"tool": "enum4linux", "cmd": "enum4linux -a evil.com"}]}
            w.upsert_entity(hyp_in)
            w.upsert_entity(hyp_out)
            orch._act([hyp_in, hyp_out])
            blocked, runs = self._counts(orch)
        finally:
            orch.close()
        self.assertEqual(runs, 1, "exactly the in-scope asset action should run")
        self.assertEqual(len(calls), 1)
        self.assertEqual(blocked, 1, "the out-of-scope asset must be blocked")

    def test_non_http_target_without_asset_is_refused(self):
        calls: list = []
        orch = self._orch(calls)
        try:
            hyp = {"id": "hyp_ghostasset", "kind": "hypothesis", "engagement_id": self.eng,
                   "state": "proposed", "asset_id": "ast_missing",
                   "actions": [{"tool": "nuclei", "cmd": "nuclei -u http://x"}]}
            orch.writer.upsert_entity(hyp)
            orch._act([hyp])
            blocked, runs = self._counts(orch)
        finally:
            orch.close()
        self.assertEqual(runs, 0)
        self.assertEqual(blocked, 1)

    def test_act_persists_only_the_masked_command(self):
        calls: list = []
        orch = self._orch(calls)
        try:
            hyp = {"id": "hyp_secret", "kind": "hypothesis", "engagement_id": self.eng,
                   "state": "proposed", "url": "https://api.example.com/x",
                   "ak": "AKIAIOSFODNN7EXAMPLE", "sk": "SecretValue456",
                   "token": "SessionToken789",
                   "actions": [{"tool": "enumerate_iam",
                                "cmd": "enumerate-iam --access-key {ak} --secret-key {sk} "
                                       "--session-token {token} {url}"}]}
            orch.writer.upsert_entity(hyp)
            orch._act([hyp])
            row = orch.writer.conn.execute("SELECT command FROM tool_run").fetchone()
        finally:
            orch.close()
        command = row["command"]
        for secret in ("AKIAIOSFODNN7EXAMPLE", "SecretValue456", "SessionToken789"):
            self.assertNotIn(secret, command, "credential persisted into tool_run.command")
        self.assertIn("***", command)
        self.assertIn("api.example.com", command)
        # the executor gets argv + env, never a shell string
        emitted = calls[0]
        self.assertIsInstance(emitted["argv"], list)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", " ".join(emitted["argv"]))
        self.assertEqual(emitted["env"]["MOTOKO_SECRET_AK"], "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(emitted["env"]["MOTOKO_SECRET_SK"], "SecretValue456")
        self.assertEqual(emitted["env"]["MOTOKO_SECRET_TOKEN"], "SessionToken789")


class TestValidatorEntryGuard(unittest.TestCase):
    """F02: the validator entry point is guarded before any request."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-vg-"))
        self.eng = "eng-vg"
        db.init_engagement(
            self.root, self.eng, name="vg",
            in_scope=["example.com"], out_of_scope=[],
        )

    def _triaged_finding(self, orch, fid, url):
        orch.writer.upsert_entity({
            "id": fid, "kind": "finding", "engagement_id": self.eng,
            "state": "candidate", "class": "sqli", "url": url,
            "detector": "sqlmap", "signals": [], "confidence": 0.75,
        })
        ok, reason = orch.writer.advance_and_persist(fid, "dedup_pass")
        self.assertTrue(ok, reason)

    def test_out_of_scope_finding_is_blocked_before_validation(self):
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            resolver=lambda h: [])
        try:
            self._triaged_finding(orch, "fnd_bad", "https://evil.com/?q=1")
            orch._validate()
            state = orch.writer.get_entity("fnd_bad")["state"]
            blocked = orch.writer.conn.execute(
                "SELECT COUNT(*) c FROM events WHERE kind='scope_blocked'").fetchone()["c"]
            errors = orch.writer.conn.execute(
                "SELECT COUNT(*) c FROM events WHERE kind='validation_error'").fetchone()["c"]
        finally:
            orch.close()
        self.assertEqual(state, "triaged", "a blocked finding must not be falsified or promoted")
        self.assertGreaterEqual(blocked, 1, "scope_blocked not recorded for the validator path")
        self.assertEqual(errors, 0)

    def test_verdict_for_blocked_target_is_inconclusive_not_false(self):
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            resolver=lambda h: [])
        try:
            verdict = orch._run_validator("replay", {"id": "fnd_x", "class": "sqli",
                                                     "url": "https://evil.com/?q=1"})
        finally:
            orch.close()
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.event, "inconclusive")

    def test_in_scope_finding_is_not_blocked(self):
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            resolver=lambda h: [])
        try:
            self._triaged_finding(orch, "fnd_ok", "https://api.example.com/?q=1")
            orch._validate()
            blocked = orch.writer.conn.execute(
                "SELECT COUNT(*) c FROM events WHERE kind='scope_blocked'").fetchone()["c"]
        finally:
            orch.close()
        self.assertEqual(blocked, 0, "an in-scope finding was blocked")


class TestBootstrapAndFrontier(unittest.TestCase):
    """R5 H1: a bare seed must bootstrap, and a rule miss must not
    permanently extinguish the frontier. R5 M11: hypotheses without actions
    stay on the graph but never reach the ACT beat."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-boot-"))
        self.eng = "eng-boot"
        db.init_engagement(self.root, self.eng, name="boot",
                           in_scope=["example.com", "10.0.0.0/24"],
                           out_of_scope=[])

    def test_bootstrap_rule_fires_on_a_bare_url(self):
        e = HypothesisEngine(RULES)
        hyps = e.generate({"url": "https://bare.example.com"})
        hits = [h for h in hyps if h["rule_id"] == "R-BOOT-URL-001"]
        self.assertEqual(len(hits), 1, "no bootstrap rule fired for a bare url")
        actions = hits[0]["actions"]
        self.assertEqual(actions[0]["tool"], "httpx")
        self.assertIn("httpx", actions[0]["cmd"])

    def test_rule_miss_keeps_the_frontier_open(self):
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            resolver=lambda h: [])
        try:
            orch.writer.upsert_entity({
                "id": "ast_bare", "kind": "asset", "engagement_id": self.eng,
                "state": "active", "type": "domain", "value": "db.example.com",
                "frontier": True,
            })
            orch._expand()
            got = orch.writer.get_entity("ast_bare")
            self.assertTrue(got.get("frontier", True),
                            "frontier extinguished after a single rule miss")
            self.assertEqual(got.get("expansion_count"), 1)
            orch._expand()
            self.assertTrue(orch.writer.get_entity("ast_bare").get("frontier", True),
                            "frontier extinguished after two rule misses")
            orch._expand()
            got = orch.writer.get_entity("ast_bare")
            self.assertFalse(got.get("frontier"),
                             "frontier never gave up after 3 consecutive misses")
            self.assertEqual(got.get("expansion_count"), 3)
        finally:
            orch.close()

    def test_bare_seed_produces_a_bootstrap_hypothesis(self):
        calls: list = []
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            executor=lambda h, a: calls.append(a),
                            resolver=lambda h: ["10.0.0.5"])
        try:
            orch.writer.upsert_entity({
                "id": "ast_seed", "kind": "asset", "engagement_id": self.eng,
                "state": "active", "type": "url",
                "value": "https://bare.example.com", "frontier": True,
            })
            orch.run(max_cycles=2)
            hyps = orch.writer.query_entities(kind="hypothesis",
                                              engagement_id=self.eng)
            self.assertTrue(
                any(h.get("rule_id") == "R-BOOT-URL-001" for h in hyps),
                "cardinality: a bare seed must produce a bootstrap hypothesis")
            self.assertGreaterEqual(len(calls), 1,
                                    "bootstrap action never reached the executor")
            # R6-4 category quotas + new recon rules (SUB pri 80) may order
            # other tools first — bootstrap must EXECUTE, not necessarily first.
            tools = {c.get("tool") for c in calls}
            self.assertIn("httpx", tools)
            self.assertTrue(
                any("https://bare.example.com" in c.get("argv", []) for c in calls
                    if c.get("tool") == "httpx"),
                "bootstrap httpx never ran against the seed URL")
        finally:
            orch.close()

    def test_prioritize_skips_hypotheses_without_actions(self):
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            resolver=lambda h: [])
        try:
            orch.writer.upsert_entity({
                "id": "hyp_noactions", "kind": "hypothesis",
                "engagement_id": self.eng, "state": "proposed",
                "statement": "LLM idea", "priority": 99.0,
            })
            orch.writer.upsert_entity({
                "id": "hyp_with", "kind": "hypothesis",
                "engagement_id": self.eng, "state": "proposed",
                "statement": "actionable", "priority": 1.0,
                "actions": [{"tool": "httpx", "cmd": "httpx -u {url}"}],
            })
            batch = orch._prioritize()
            # the action-less hypothesis is still on the graph, but not work
            self.assertIsNotNone(orch.writer.get_entity("hyp_noactions"))
        finally:
            orch.close()
        self.assertEqual([h["id"] for h in batch], ["hyp_with"],
                         "an action-less hypothesis was prioritized for ACT")


class TestActRecheck(unittest.TestCase):
    """R5 H4: ACT re-checks the target right before execution and records
    what the guard cleared — without claiming a subprocess tool pins it."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-r5h4-"))
        self.eng = "eng-r5h4"
        db.init_engagement(self.root, self.eng, name="r5h4",
                           in_scope=["example.com"], out_of_scope=[])

    class Guard:
        """Sequence of decisions; counts calls."""

        def __init__(self, decisions):
            from motoko.scope import ScopeDecision
            self._d = [ScopeDecision(**d) for d in decisions]
            self.calls = 0

        def check_url(self, url):
            d = self._d[min(self.calls, len(self._d) - 1)]
            self.calls += 1
            return d

    def test_comment_does_not_claim_the_tool_connects_to_the_checked_ip(self):
        src = (RULES.parent / "motoko" / "orchestrator.py").read_text()
        self.assertNotIn("connects to what the guard checked", src,
                         "the ACT comment still makes the false TOCTOU claim")
        self.assertNotIn("the tool connects to what the guard checked", src)

    def test_recheck_blocked_target_is_not_executed(self):
        calls: list = []
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            executor=lambda h, a: calls.append(a))
        try:
            orch.guard = self.Guard([
                {"allowed": True, "reason": "first ok",
                 "detail": {"bind_ip": "10.0.0.5"}},
                {"allowed": False, "reason": "rebound to out-of-scope address"},
            ])
            hyp = {"id": "hyp_recheck", "kind": "hypothesis",
                   "engagement_id": self.eng, "state": "proposed",
                   "url": "https://app.example.com/x",
                   "actions": [{"tool": "nuclei", "cmd": "nuclei -u {url}"}]}
            orch.writer.upsert_entity(hyp)
            orch._act([hyp])
            blocked = orch.writer.conn.execute(
                "SELECT payload FROM events WHERE kind='scope_blocked'").fetchall()
        finally:
            orch.close()
        self.assertEqual(calls, [], "an action executed after the re-check blocked it")
        self.assertTrue(any("recheck" in (r["payload"] or "") for r in blocked),
                        "the re-check block was not recorded")

    def test_executor_gets_the_fresh_recheck_bind_ip(self):
        calls: list = []
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            executor=lambda h, a: calls.append(a))
        try:
            orch.guard = self.Guard([
                {"allowed": True, "reason": "first ok",
                 "detail": {"bind_ip": "10.0.0.5"}},
                {"allowed": True, "reason": "rechecked ok",
                 "detail": {"bind_ip": "10.0.0.9"}},
            ])
            hyp = {"id": "hyp_fresh", "kind": "hypothesis",
                   "engagement_id": self.eng, "state": "proposed",
                   "url": "https://app.example.com/x",
                   "actions": [{"tool": "nuclei", "cmd": "nuclei -u {url}"}]}
            orch.writer.upsert_entity(hyp)
            orch._act([hyp])
        finally:
            orch.close()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].get("bind_ip"), "10.0.0.9",
                         "the re-check's fresh bind_ip did not reach the executor")


class TestToolRunStamp(unittest.TestCase):
    """R5 M6: _act stamps the tool_run id onto the action it hands over."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-r5m6-"))
        self.eng = "eng-r5m6"
        db.init_engagement(self.root, self.eng, name="r5m6",
                           in_scope=["example.com"], out_of_scope=[])
        self.calls: list = []
        self.orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                                 executor=lambda h, a: self.calls.append(a),
                                 resolver=lambda h: ["10.0.0.5"])

    def tearDown(self):
        self.orch.close()

    def test_action_carries_the_started_tool_run_id(self):
        hyp = {"id": "hyp_tr", "kind": "hypothesis", "engagement_id": self.eng,
               "state": "proposed", "url": "https://app.example.com/x",
               "actions": [{"tool": "nuclei", "cmd": "nuclei -u {url}"}]}
        self.orch.writer.upsert_entity(hyp)
        self.orch._act([hyp])
        rows = self.orch.writer.conn.execute(
            "SELECT id, status FROM tool_run").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0].get("_tool_run_id"), rows[0]["id"],
                         "the started tool_run id did not travel with the action")


if __name__ == "__main__":
    unittest.main(verbosity=2)
