"""P-028 regression: strix parser extracts structured VULN blocks.

Run:  python3 tests/test_strix_vuln.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko.parsers import get_parser  # noqa: E402

BLOCK = """
╭─ VULN-0003 ───────────────────────────────────────╮
│  Title: WAF Bypass via X-Real-IP Header           │
│  Severity: CRITICAL                               │
│  CVSS Score: 9.3                                  │
│  Target: https://support.example.com.cn               │
│  Endpoint: /iccp-isupport-gateway/            │
│  Method: GET                                      │
│  CVSS Vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N │
│  Description                                     │
│  The WAF can be bypassed with X-Real-IP header.   │
╭─ STRIX ───────────────────────────────────────────╮
"""


class TestStrixVulnBlocks(unittest.TestCase):
    def test_confirmed_finding_extracted(self):
        p = get_parser("strix")
        r = p.parse(BLOCK, action={"url": "https://support.example.com.cn"})
        conf = [f for f in r.findings if f["class"] == "vuln.strix_confirmed"]
        self.assertEqual(len(conf), 1)
        f = conf[0]
        self.assertEqual(f["severity"], "critical")
        # extra 浅合并进 finding 顶层（引擎行为，见 #39）
        self.assertEqual(f["cvss"], 9.3)
        self.assertIn("AV:N", f["vector"])
        self.assertEqual(f["method"], "GET")
        self.assertEqual(f["url"], "https://support.example.com.cn")

    def test_cve_layer_still_works(self):
        p = get_parser("strix")
        r = p.parse("found CVE-2021-44228 here", action={})
        cves = [f for f in r.findings if f["class"] == "vuln.cve_reported"]
        self.assertEqual(len(cves), 1)

    def test_block_boundary_stops_at_next_vuln(self):
        two = BLOCK.replace("╭─ STRIX ─", "╭─ VULN-0004 ─")
        p = get_parser("strix")
        r = p.parse(two)
        conf = [f for f in r.findings if f["class"] == "vuln.strix_confirmed"]
        self.assertEqual(len(conf), 1)  # second block has no fields

    def test_real_log_fixture(self):
        """P-028's real-run fixture: job-hr.log contains 2 MEDIUM vulns."""
        path = Path("/tmp/strix-burn2/job-hr.log")
        if not path.exists():
            self.skipTest("fixture log not present")
        p = get_parser("strix")
        r = p.parse(path.read_text(errors="ignore"), action={})
        conf = [f for f in r.findings if f["class"] == "vuln.strix_confirmed"]
        self.assertEqual(len(conf), 2)
        self.assertTrue(all(f["severity"] == "medium" for f in conf))


if __name__ == "__main__":
    unittest.main(verbosity=2)
