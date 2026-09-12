"""Asset dedup tests — the production wave-1 bootstrap self-lock fix.

Run:  python3 tests/test_asset_dedup.py
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import db  # noqa: E402
from motoko.orchestrator import Orchestrator  # noqa: E402


def _asset(value: str, tech=None, status_code=200, source="httpx") -> dict:
    return {"kind": "asset", "state": "active", "type": "url", "value": value,
            "source": source, "status_code": status_code, "tech": tech or []}


class TestAssetDedup(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-dedup-"))
        self.eng = "eng-dedup"
        db.init_engagement(self.root, self.eng, name="t",
                           in_scope=["example.com"])
        w = db.Database(db.engagement_dir(self.root, self.eng) / "graph.db")
        w.upsert_entity({"id": "ast_seed", "kind": "asset",
                         "engagement_id": self.eng, "state": "active",
                         "type": "url", "value": "https://a.example.com",
                         "frontier": True, "source": "seed"})
        w.close()
        self.orch = Orchestrator(self.eng, root=self.root,
                                 rules_dir=Path(__file__).resolve().parents[1] / "rules")

    def tearDown(self):
        self.orch.close()

    def test_same_value_merges_not_multiplies(self):
        self.orch._merge_asset(_asset("https://a.example.com", tech=["Nginx"]))
        self.orch._merge_asset(_asset("https://a.example.com", tech=["Vue.js"]))
        assets = self.orch.writer.query_entities(kind="asset",
                                                 engagement_id=self.eng)
        self.assertEqual(len(assets), 1)   # seed row survived, no new rows

    def test_tech_union(self):
        self.orch._merge_asset(_asset("https://a.example.com", tech=["Nginx"]))
        self.orch._merge_asset(_asset("https://a.example.com", tech=["Vue.js"]))
        assets = self.orch.writer.query_entities(kind="asset",
                                                 engagement_id=self.eng)
        self.assertEqual(sorted(assets[0]["tech"]), ["Nginx", "Vue.js"])

    def test_different_value_creates_row(self):
        self.orch._merge_asset(_asset("https://b.example.com", tech=["Spring"]))
        assets = self.orch.writer.query_entities(kind="asset",
                                                 engagement_id=self.eng)
        self.assertEqual(len(assets), 2)

    def test_unchanged_rescan_does_not_reopen_frontier(self):
        # seed row already frontier=True; simulate a settled asset: set it
        # frontier=False, rescan with IDENTICAL facts -> must stay False
        self.orch._merge_asset(_asset("https://a.example.com", tech=["Nginx"]))
        w = self.orch.writer
        row = w.query_entities(kind="asset", engagement_id=self.eng)[0]
        row["frontier"] = False
        w.upsert_entity(row)
        self.orch._merge_asset(_asset("https://a.example.com", tech=["Nginx"]))
        row = w.query_entities(kind="asset", engagement_id=self.eng)[0]
        self.assertFalse(row.get("frontier"))

    def test_new_facts_reopen_frontier(self):
        self.orch._merge_asset(_asset("https://a.example.com", tech=["Nginx"]))
        w = self.orch.writer
        row = w.query_entities(kind="asset", engagement_id=self.eng)[0]
        row["frontier"] = False
        w.upsert_entity(row)
        self.orch._merge_asset(_asset("https://a.example.com",
                                      tech=["Nginx", "Spring"]))
        row = w.query_entities(kind="asset", engagement_id=self.eng)[0]
        self.assertTrue(row.get("frontier"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
