"""P-027 regression: line-list parsers feed _asset correctly.

Run:  python3 tests/test_lines_parser.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko.parsers import get_parser  # noqa: E402

SUB_OUTPUT = """docsub.example.com.cn
ipartner.example.com.cn
mail01.mkt.example.com.cn
https://gau.example.com/old/path?x=1
"""


class TestLineListParsers(unittest.TestCase):
    def test_subfinder_parses_hosts(self):
        p = get_parser("subfinder")
        r = p.parse(SUB_OUTPUT, action={"host": "example.com.cn"})
        values = [a["value"] for a in r.assets]
        self.assertIn("docsub.example.com.cn", values)
        self.assertIn("mail01.mkt.example.com.cn", values)

    def test_gau_parses_urls_and_hosts(self):
        p = get_parser("gau")
        r = p.parse(SUB_OUTPUT, action={"host": "example.com.cn"})
        values = [a["value"] for a in r.assets]
        self.assertIn("https://gau.example.com/old/path?x=1", values)

    def test_stamps_survive_into_extra(self):
        p = get_parser("subfinder")
        r = p.parse("docsub.example.com.cn\n", action={"host": "example.com.cn"})
        self.assertEqual(r.assets[0]["enumerated_host"], "docsub.example.com.cn")
        self.assertEqual(r.assets[0]["enumerated_domain"], "example.com.cn")

    def test_amass_and_naabu_and_dnsx_registered(self):
        for t in ("amass", "naabu", "dnsx"):
            self.assertIsNotNone(get_parser(t), t)


if __name__ == "__main__":
    unittest.main(verbosity=2)
