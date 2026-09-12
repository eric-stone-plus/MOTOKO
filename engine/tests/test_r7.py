"""R7 regression tests — the second wave-loop fix batch.

Covers: R7-1/R7-2 rule removals (test_strix_kali), R7-3 host consumption
chain, R7-5 nmap parser + services, R7-6 scan quota, R7-7 all-dupe empty
expansion, R7-8 container whitelist + error retry.

Run:  python3 tests/test_r7.py
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

RULES = Path(__file__).resolve().parents[1] / "rules"

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host><address addr="1.2.3.4" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="protocol 2.0"/></port>
<port protocol="tcp" portid="445"><state state="open"/>
  <service name="microsoft-ds" product="Samba" version="4.17"/></port>
<port protocol="tcp" portid="80"><state state="closed"/>
  <service name="http"/></port>
</ports></host>
</nmaprun>
"""


class TestNmapParser(unittest.TestCase):
    def test_services_and_stamp(self):
        p = get_parser("nmap")
        r = p.parse(NMAP_XML, action={"host": "a.example.com"})
        names = [s["service_name"] for s in r.services]
        self.assertEqual(names, ["ssh", "microsoft-ds"])   # closed skipped
        self.assertEqual(r.services[1]["product"], "Samba")
        self.assertEqual(r.assets[0]["nmap_host"], "a.example.com")

    def test_unparseable_is_dead(self):
        p = get_parser("nmap")
        r = p.parse("garbage output", action={"host": "x"})
        self.assertEqual(r.services, [])
        self.assertTrue(r.dead_letter)


class TestHostConsumptionChain(unittest.TestCase):
    def test_host_asset_fires_bootstrap(self):
        # R7-3: a bare host asset (subfinder output) must reach httpx.
        e = HypothesisEngine(RULES)
        ids = [h["rule_id"] for h in e.generate({"type": "host",
                                                 "url": "sub.example.com"})]
        self.assertIn("R-BOOT-URL-001", ids)


class TestAllDupRetires(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-r7-"))
        self.eng = "eng-r7"
        db.init_engagement(self.root, self.eng, name="t",
                           in_scope=["example.com"])
        w = db.Database(db.engagement_dir(self.root, self.eng) / "graph.db")
        w.upsert_entity({"id": "ast_seed", "kind": "asset",
                         "engagement_id": self.eng, "state": "active",
                         "type": "url", "value": "https://a.example.com",
                         "status_code": 405, "frontier": True, "source": "httpx"})
        w.close()
        self.orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES)

    def tearDown(self):
        self.orch.close()

    def test_all_dup_pass_retires_frontier(self):
        # R7-7: bootstrap fires (any url), then 405 flips in — the second
        # expansion is all-duplicate and must retire the frontier within the
        # empty-expansion budget instead of spinning 28 times.
        self.orch._expand()          # mints bootstrap + scan (405 in list)
        self.orch._expand()          # all dup now
        self.orch._expand()
        self.orch._expand()
        got = self.orch.writer.get_entity("ast_seed")
        self.assertFalse(got.get("frontier"),
                         "all-duplicate pass never retired the frontier")


class TestScanQuota(unittest.TestCase):
    def test_scan_slot_beats_context_flood(self):
        # R7-6: scan sits before context in the reserved order.
        orch_holder = Orchestrator.__new__(Orchestrator)
        # avoid full init: test the order via _prioritize on a tiny fake
        class W:
            def query_entities(self, kind, engagement_id, state=None):
                if kind != "hypothesis":
                    return []
                return [
                    {"id": "h_ctx", "kind": "hypothesis", "state": "proposed",
                     "category": "context", "actions": [{"tool": "katana"}],
                     "priority": 80.0},
                    {"id": "h_scan", "kind": "hypothesis", "state": "proposed",
                     "category": "scan", "actions": [{"tool": "nuclei"}],
                     "priority": 53.33},
                    {"id": "h_ctx2", "kind": "hypothesis", "state": "proposed",
                     "category": "context", "actions": [{"tool": "gau"}],
                     "priority": 79.0},
                ]
        orch_holder.writer = W()
        orch_holder.engagement_id = "eng-x"
        batch = orch_holder._prioritize()
        self.assertEqual(batch[0]["id"], "h_scan")
        self.assertLessEqual(len(batch), 4)


class TestContainerWhitelist(unittest.TestCase):
    def test_bad_container_name_refused(self):
        import shutil
        from motoko.executor import SubprocessExecutor
        ex = SubprocessExecutor.__new__(SubprocessExecutor)
        ex.tool_dirs = ()
        ex.tool_timeout = 10.0
        ex.kill_grace = 0.0
        calls = []

        class W:
            def record_observation(self, **kw):
                calls.append(kw)
                return "o"

            def finish_tool_run(self, action, **kw):
                calls.append(("finish", kw))

        ex.writer = W()
        ex.engagement_id = "e"
        ex.artifacts = Path(tempfile.mkdtemp(prefix="motoko-r7-c-"))
        ex({"url": "https://a.com"},
           {"tool": "nmap", "runtime": "container",
            "container": "--privileged",
            "argv": ["nmap", "1.2.3.4"]})
        self.assertTrue(calls)
        self.assertEqual(calls[0]["parsed_summary"][:8], "refusing")
        self.assertEqual(calls[0]["exit_code"], -2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
