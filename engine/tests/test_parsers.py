"""Parser fixture tests — each parser must correctly consume real tool output.

Run:  python3 tests/test_parsers.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko.parsers import get_parser, parse_tool  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


def read(name: str) -> str:
    return (FIX / name).read_text()


class TestNuclei(unittest.TestCase):
    def test_jsonl(self):
        p = get_parser("nuclei")
        r = p.parse(read("nuclei.jsonl"))
        self.assertEqual(len(r.findings), 3)
        classes = [f["class"] for f in r.findings]
        self.assertIn("xss.reflected", classes)
        self.assertIn("exposure.actuator_env", classes)
        self.assertIn("cve", classes)
        self.assertEqual(r.dead_letter, [])
        # severity carried through
        crit = next(f for f in r.findings if f["class"] == "cve")
        self.assertEqual(crit["severity"], "critical")


class TestHttpx(unittest.TestCase):
    def test_json(self):
        r = get_parser("httpx").parse(read("httpx.json"))
        self.assertEqual(len(r.assets), 1)
        self.assertEqual(r.assets[0]["value"], "https://example.com")
        self.assertIn("nginx", r.assets[0]["tech"])

    def test_text(self):
        r = get_parser("httpx").parse(read("httpx.txt"))
        self.assertEqual(len(r.assets), 2)
        self.assertEqual(r.assets[0]["status_code"], 200)
        self.assertEqual(r.assets[1]["status_code"], 403)


class TestSqlmap(unittest.TestCase):
    def test_confirmed(self):
        r = get_parser("sqlmap").parse(read("sqlmap.txt"), action={"url": "https://example.com/search?q=1"})
        self.assertEqual(len(r.findings), 1)
        f = r.findings[0]
        self.assertEqual(f["class"], "sqli")
        self.assertEqual(f["param"], "q")
        self.assertIn("boolean-based", f["sink"])

    def test_negative_is_not_a_finding(self):
        # naive `"injectable" in stdout` would false-positive here: the word
        # "injectable" appears in the negative output, but there is no
        # confirmation marker.
        r = get_parser("sqlmap").parse(read("sqlmap_negative.txt"))
        self.assertEqual(r.findings, [])


class TestDalfox(unittest.TestCase):
    def test_poc(self):
        r = get_parser("dalfox").parse(read("dalfox.txt"))
        self.assertEqual(len(r.findings), 2)
        self.assertTrue(all(f["class"] == "xss.reflected" for f in r.findings))


class TestFfuf(unittest.TestCase):
    def test_text_single_line(self):
        # Real ffuf text output: `payload [Status: 200, Size: ...]` on ONE
        # line (the old fixture's `[Status: ...]` + `* FUZZ:` pair was wrong).
        r = get_parser("ffuf").parse(
            read("ffuf.txt"), action={"base_url": "https://example.com/FUZZ"})
        # 200 admin + 200 .env are hits; 404 nonexistent is dropped
        self.assertEqual(len(r.assets), 2)
        self.assertEqual(len(r.findings), 1)  # .env is sensitive
        self.assertEqual(r.findings[0]["class"], "info_disclosure.sensitive_file")
        self.assertEqual(r.assets[0]["value"], "https://example.com/admin")
        self.assertEqual(r.assets[0]["status_code"], 200)
        self.assertEqual(r.dead_letter, [], "banner lines must not become dead letters")

    def test_json_single_object(self):
        # Real `ffuf -of json`: ONE object with a results[] array, not JSONL.
        r = get_parser("ffuf").parse(read("ffuf.json"))
        self.assertEqual(len(r.assets), 2)          # admin + .env
        self.assertEqual(len(r.findings), 1)        # .env sensitive
        self.assertEqual(r.assets[0]["value"], "https://example.com/admin")
        self.assertEqual(r.assets[0]["status_code"], 200)
        self.assertEqual(r.dead_letter, [])

    def test_json_entry_without_url_falls_back_to_base_url(self):
        payload = ('{"commandline": "ffuf", "time": "t", "results": ['
                   '{"input": {"FUZZ": "admin"}, "status": 200, "length": 5}]}')
        r = get_parser("ffuf").parse(payload, action={"base_url": "https://example.com/FUZZ"})
        self.assertEqual(len(r.assets), 1)
        self.assertEqual(r.assets[0]["value"], "https://example.com/admin")

    def test_jsonl_is_not_silently_accepted(self):
        # the fake JSONL format now lands in dead_letter instead of parsing
        r = get_parser("ffuf").parse(
            '{"status":200,"url":"https://example.com/admin"}\n'
            '{"status":200,"url":"https://example.com/.env"}')
        self.assertEqual(r.assets, [])
        self.assertEqual(len(r.dead_letter), 1)

    def test_bad_json_goes_to_dead_letter(self):
        r = get_parser("ffuf").parse('{"results": [{"status": 200,')
        self.assertEqual(r.assets, [])
        self.assertEqual(len(r.dead_letter), 1)

    def test_json_without_results_goes_to_dead_letter(self):
        r = get_parser("ffuf").parse('{"commandline": "ffuf", "time": "t"}')
        self.assertEqual(r.assets, [])
        self.assertEqual(len(r.dead_letter), 1)

    def test_non_numeric_status_goes_to_dead_letter(self):
        # R3 H4: `int(status)` on garbage used to raise out of parse_tool and
        # kill the orchestrator main loop.
        payload = ('{"results": ['
                   '{"status": "not-a-number", "url": "https://example.com/bad1"}, '
                   '{"status": {"nested": true}, "url": "https://example.com/bad2"}, '
                   '{"status": 200, "url": "https://example.com/ok"}]}')
        r = get_parser("ffuf").parse(payload)
        self.assertEqual([a["value"] for a in r.assets], ["https://example.com/ok"])
        self.assertEqual(len(r.dead_letter), 2)

    def test_garbage_text_goes_to_dead_letter(self):
        r = get_parser("ffuf").parse("this is not ffuf output\nnor is this")
        self.assertEqual(r.assets, [])
        self.assertEqual(len(r.dead_letter), 2)


class TestRegistry(unittest.TestCase):
    def test_unregistered_tool(self):
        r = parse_tool("nonexistent_tool", "some output")
        self.assertIn("no parser registered", r.summary)
        self.assertEqual(r.dead_letter, ["some output"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
