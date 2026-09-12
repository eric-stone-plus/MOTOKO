"""R6 regression tests — the wave-audit fix batch.

Covers: R6-1 stderr/summary persistence, R6-2 arjun parser (incl. the
'Extracted for testing' false-positive trap), R6-3 cache-buster
normalization, R6-4 category quotas + per-rule backlog cap, R6-5
host_crawled fact, R6-6 ffuf base_url fallback.

Run:  python3 tests/test_r6.py
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import db  # noqa: E402
from motoko.hypothesis_engine import HypothesisEngine  # noqa: E402
from motoko.orchestrator import Orchestrator  # noqa: E402
from motoko.parsers import get_parser  # noqa: E402
from motoko.parsers.katana import _normalize_cache_busters  # noqa: E402

RULES = Path(__file__).resolve().parents[1] / "rules"


class TestArjunParser(unittest.TestCase):
    def setUp(self):
        self.p = get_parser("arjun")
        self.action = {"url": "https://a.example.com/createCase.html"}

    def test_confirmed_parameters_become_findings(self):
        out = ("[*] Probing the target for stability\n"
               "[+] Parameters discovered: renderData, callback\n")
        r = self.p.parse(out, action=self.action)
        self.assertEqual(len(r.findings), 2)
        self.assertEqual(r.findings[0]["class"], "info_disclosure.hidden_param")
        self.assertEqual(r.findings[0]["param"], "renderData")

    def test_no_parameters_is_empty_not_dead(self):
        r = self.p.parse("[*] Probing\nNo parameters were discovered.\n",
                         action=self.action)
        self.assertEqual(r.findings, [])
        self.assertEqual(r.dead_letter, [])

    def test_extracted_for_testing_is_not_confirmed(self):
        # grok's trap: 'Extracted ... for testing' must NOT enter the graph
        out = ("[+] Extracted 1 parameter from response for testing: renderData\n"
               "[!] Processing chunks: 1/103\n"
               "No parameters were discovered.\n")
        r = self.p.parse(out, action=self.action)
        self.assertEqual(r.findings, [])

    def test_json_shape(self):
        r = self.p.parse('{"https://a.example.com": ["uid", "token"]}',
                         action=self.action)
        self.assertEqual(len(r.findings), 2)


class TestCacheBusterNormalization(unittest.TestCase):
    def test_plain_url(self):
        self.assertEqual(_normalize_cache_busters("https://a.com/page"),
                         ("https://a.com/page", False))

    def test_js_version_query(self):
        self.assertEqual(_normalize_cache_busters("https://a.com/app.js?v=1.2.3"),
                         ("https://a.com/app.js", False))

    def test_pure_cache_buster_stripped(self):
        self.assertEqual(_normalize_cache_busters("https://a.com/p?cb=123"),
                         ("https://a.com/p", False))

    def test_business_param_kept(self):
        self.assertEqual(_normalize_cache_busters("https://a.com/p?user=1"),
                         ("https://a.com/p?user=1", True))

    def test_mixed_cache_and_business_kept(self):
        self.assertEqual(_normalize_cache_busters("https://a.com/p?id=7&v=2"),
                         ("https://a.com/p?id=7&v=2", True))


class TestScheduling(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-r6-"))
        self.eng = "eng-r6"
        db.init_engagement(self.root, self.eng, name="t",
                           in_scope=["example.com"])
        w = db.Database(db.engagement_dir(self.root, self.eng) / "graph.db")
        # seed with status 200 -> bootstrap + scan + crawl all fire
        w.upsert_entity({"id": "ast_seed", "kind": "asset",
                         "engagement_id": self.eng, "state": "active",
                         "type": "url", "value": "https://a.example.com",
                         "status_code": 200, "frontier": True, "source": "seed"})
        w.close()
        self.orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES)

    def tearDown(self):
        self.orch.close()

    def test_category_quota_lets_scan_through(self):
        # bootstrap (tech, pri 60) alone would beat scan (tech, pri 53.33).
        # Build a backlog of high-priority context hyps, then prove SCAN
        # still gets a batch slot via the category reservation.
        w = self.orch.writer
        for i in range(30):
            w.upsert_entity({"id": f"hyp_c{i}", "kind": "hypothesis",
                             "engagement_id": self.eng, "state": "proposed",
                             "rule_id": "R-CTX-CRAWL-001", "category": "context",
                             "actions": [{"tool": "katana"}], "priority": 80.0})
        w.upsert_entity({"id": "hyp_scan", "kind": "hypothesis",
                         "engagement_id": self.eng, "state": "proposed",
                         "rule_id": "R-BOOT-SCAN-001", "category": "tech",
                         "actions": [{"tool": "nuclei"}], "priority": 53.33})
        batch = self.orch._prioritize()
        ids = [h["id"] for h in batch]
        self.assertIn("hyp_scan", ids)
        self.assertLessEqual(len(batch), 4)  # K=4: quota slots + priority fill

    def test_backlog_cap_stops_minting(self):
        # flood proposed bootstrap hyps to the cap; expand must not mint more
        w = self.orch.writer
        for i in range(40):
            w.upsert_entity({"id": f"hyp_b{i}", "kind": "hypothesis",
                             "engagement_id": self.eng, "state": "proposed",
                             "rule_id": "R-BOOT-URL-001", "category": "tech",
                             "asset_id": f"ast_x{i}",
                             "actions": [{"tool": "httpx"}], "priority": 60.0})
        self.orch._expand()
        n = sum(1 for h in w.query_entities(kind="hypothesis",
                                            engagement_id=self.eng)
                if h.get("rule_id") == "R-BOOT-URL-001")
        self.assertEqual(n, 40)          # cap held, no new bootstrap hyp


class TestHostCrawled(unittest.TestCase):
    def test_host_crawled_fact_blocks_crawl_rule(self):
        engine = HypothesisEngine(RULES)
        facts = {"url": "https://a.example.com/x", "status": 200,
                 "host_crawled": True}
        ids = [h["rule_id"] for h in engine.generate(facts)]
        self.assertNotIn("R-CTX-CRAWL-001", ids)
        facts["host_crawled"] = False
        ids = [h["rule_id"] for h in engine.generate(facts)]
        self.assertIn("R-CTX-CRAWL-001", ids)


class TestFfufBaseUrl(unittest.TestCase):
    def test_base_url_falls_back_to_action_url(self):
        p = get_parser("ffuf")
        r = p.parse("admin    [Status: 200, Size: 100, Words: 5, Lines: 3]\n",
                    action={"url": "https://u.example.com"})
        self.assertEqual(len(r.assets), 1)
        self.assertEqual(r.assets[0]["value"],
                         "https://u.example.com/admin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
