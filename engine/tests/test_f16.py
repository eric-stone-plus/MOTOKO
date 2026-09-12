"""F16 regression: one hypothesis per (rule, asset) — no duplicates.

Run:  python3 tests/test_f16.py
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import db  # noqa: E402
from motoko.orchestrator import Orchestrator  # noqa: E402


class TestHypothesisUniqueness(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-f16-"))
        self.eng = "eng-f16"
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

    def _hyp_count(self, rule_id: str) -> int:
        return sum(1 for h in self.orch.writer.query_entities(
            kind="hypothesis", engagement_id=self.eng)
            if h.get("rule_id") == rule_id)

    def test_reopen_frontier_does_not_duplicate(self):
        # expand once: bootstrap fires on the bare URL
        self.orch._expand()
        n1 = self._hyp_count("R-BOOT-URL-001")
        self.assertGreaterEqual(n1, 1)
        # simulate a fact merge re-opening the frontier (status arrives)
        self.orch._merge_asset({"kind": "asset", "state": "active",
                                "type": "url", "value": "https://a.example.com",
                                "source": "httpx", "status_code": 200,
                                "tech": ["Nginx"]})
        # expand again: same (rule, asset) pair must NOT mint a new hyp
        self.orch._expand()
        n2 = self._hyp_count("R-BOOT-URL-001")
        self.assertEqual(n1, n2)

    def test_new_rule_still_fires_after_reopen(self):
        self.orch._expand()                       # bootstrap
        self.orch._merge_asset({"kind": "asset", "state": "active",
                                "type": "url", "value": "https://a.example.com",
                                "source": "httpx", "status_code": 200,
                                "tech": ["Nginx"]})
        self.orch._expand()                       # scan rule fires (new pair)
        n = self._hyp_count("R-BOOT-SCAN-001")
        self.assertGreaterEqual(n, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
