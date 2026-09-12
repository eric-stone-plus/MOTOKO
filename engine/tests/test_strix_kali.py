"""strix/kali graph integration tests — runtime routing + parsers + rules.

Run:  python3 tests/test_strix_kali.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko.executor import SubprocessExecutor  # noqa: E402
from motoko.hypothesis_engine import HypothesisEngine  # noqa: E402
from motoko.parsers import get_parser  # noqa: E402

RULES = Path(__file__).resolve().parents[1] / "rules"


class TestContainerRouting(unittest.TestCase):
    def _mk(self):
        ex = SubprocessExecutor.__new__(SubprocessExecutor)
        ex.tool_dirs = ()
        return ex

    def test_container_action_skips_host_resolve(self):
        # runtime=container must build [podman, exec, kali-recon, <argv>]
        # WITHOUT resolving the tool binary on the host (netexec lives in the
        # container only).
        import shutil
        ex = self._mk()
        ex.tool_timeout = 1.0
        ex.kill_grace = 0.0
        ex.artifacts = Path("/tmp/never-created")  # replaced below
        # isolate: patch resolve via runtime branch by faking podman absence
        orig_which = shutil.which
        try:
            shutil.which = lambda *a, **k: None   # podman missing
            action = {"tool": "netexec", "runtime": "container",
                      "container": "kali-recon",
                      "argv": ["netexec", "smb", "1.2.3.4"]}
            # behavior under test: the podman-missing path must be reached
            # (exit 127 record) and never raise
            # full record path needs writer; use a minimal stub
            calls = []

            class W:
                def record_observation(self, **kw):
                    calls.append(kw)
                    return "o1"

                def finish_tool_run(self, action, **kw):
                    calls.append(("finish", kw))

            ex.writer = W()
            ex.engagement_id = "e"
            ex.artifacts = Path("/tmp")
            ex(hyp={}, action=action)
            self.assertTrue(calls, "executor recorded nothing")
            self.assertEqual(calls[0]["parsed_summary"],
                             "podman not found for container action")
        finally:
            shutil.which = orig_which


class TestStrixParser(unittest.TestCase):
    def test_extracts_urls_and_cves(self):
        p = get_parser("strix")
        out = ("Deep dive report\n"
               "Found https://a.example.com/api/v1/login\n"
               "CVE-2021-44228 confirmed on https://b.example.com\n"
               "also https://c.example.com/x?y=1\n")
        r = p.parse(out, action={"url": "https://a.example.com"})
        urls = [a["value"] for a in r.assets]
        self.assertIn("https://a.example.com/api/v1/login", urls)
        self.assertIn("https://b.example.com", urls)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0]["class"], "vuln.cve_reported")
        self.assertEqual(r.findings[0]["cve"], "CVE-2021-44228")

    def test_empty_session_is_empty_not_dead(self):
        p = get_parser("strix")
        r = p.parse("session ended, nothing found", action={})
        self.assertEqual(r.assets, [])
        self.assertEqual(r.findings, [])


class TestIntegrationRules(unittest.TestCase):
    def test_smb_rule_removed_auto_fire(self):
        # R7-2: SMB rules were demoted to registry-only (no parser yet) —
        # service=smb must NOT auto-fire any container tool this round.
        e = HypothesisEngine(RULES)
        ids = [h["rule_id"] for h in e.generate({"service": "smb"})]
        self.assertNotIn("R-ACCESS-SMB-001", ids)

    def test_strix_rule_removed_auto_fire(self):
        # R7-1: strix deep-dive is CLI-only; the auto-fire rule is gone.
        e = HypothesisEngine(RULES)
        ids = [h["rule_id"] for h in e.generate(
            {"url": "https://a.example.com", "status": 200,
             "tech": ["Vue.js"], "host_crawled": True})]
        self.assertNotIn("R-CTX-STRIX-001", ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
