"""Command rendering tests (F09) — argv arrays, never a shell string; target
values quoted for the summary; credentials only in the environment.

Run:  python3 tests/test_cmd.py
"""

from __future__ import annotations

import shlex
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import cmd  # noqa: E402


class TestRenderCommand(unittest.TestCase):
    def test_renders_an_argv_list(self):
        r = cmd.render_command("sqlmap -u {url} --batch --level=2",
                               {"url": "https://example.com/search?q=1"})
        self.assertEqual(r.argv, ["sqlmap", "-u", "https://example.com/search?q=1",
                                  "--batch", "--level=2"])
        self.assertEqual(r.env, {})
        self.assertIn("https://example.com/search?q=1", r.summary)

    def test_placeholders_inside_larger_tokens(self):
        r = cmd.render_command("curl -L {url}?redirect={oob} {url}/api/me",
                               {"url": "https://example.com", "oob": "c1.oob.test"})
        self.assertEqual(r.argv[2], "https://example.com?redirect=c1.oob.test")
        self.assertEqual(r.argv[3], "https://example.com/api/me")

    def test_unknown_placeholder_is_left_visible(self):
        r = cmd.render_command("tool {url} --out {out}",
                               {"url": "https://example.com"})
        self.assertEqual(r.argv, ["tool", "https://example.com", "--out", "{out}"])

    def test_dangerous_target_value_cannot_break_out(self):
        evil = "https://example.com/x; rm -rf ~; $(id) `whoami` | tee /tmp/x"
        r = cmd.render_command("curl {url}", {"url": evil})
        # argv carries the value verbatim as ONE token — nothing is interpreted
        self.assertEqual(r.argv, ["curl", evil])
        # the persisted summary is shell-safe: splitting it returns the token
        self.assertEqual(shlex.split(r.summary), ["curl", evil])
        self.assertIn("'", r.summary, "the summary did not shlex.quote the target value")
        self.assertNotIn("shell=True", Path(cmd.__file__).read_text())

    def test_credentials_never_reach_argv_or_summary(self):
        ctx = {"url": "https://cloud.example.com",
               "ak": "AKIAIOSFODNN7EXAMPLE",
               "sk": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
               "token": "FQoGZXIvYXdzEBYaDA1234567890"}
        r = cmd.render_command(
            "enumerate-iam --access-key {ak} --secret-key {sk} --session-token {token} {url}",
            ctx)
        blob = " ".join(r.argv) + " " + r.summary
        for secret in ctx.values():
            if secret == ctx["url"]:
                continue
            self.assertNotIn(secret, blob, f"credential {secret[:6]}... leaked into argv/summary")
        # they are in the environment instead
        self.assertEqual(r.env["MOTOKO_SECRET_AK"], ctx["ak"])
        self.assertEqual(r.env["MOTOKO_SECRET_SK"], ctx["sk"])
        self.assertEqual(r.env["MOTOKO_SECRET_TOKEN"], ctx["token"])
        # and the summary shows redaction, not the placeholder soup
        self.assertIn("***", r.summary)

    def test_secret_detection_is_case_insensitive_and_covers_aliases(self):
        r = cmd.render_command("tool --p {PASSWORD} --k {api_key}",
                               {"PASSWORD": "hunter2", "api_key": "k-123456"})
        self.assertEqual(r.env["MOTOKO_SECRET_PASSWORD"], "hunter2")
        self.assertEqual(r.env["MOTOKO_SECRET_API_KEY"], "k-123456")
        self.assertNotIn("hunter2", " ".join(r.argv) + r.summary)

    def test_non_secret_values_are_not_diverted(self):
        r = cmd.render_command("nuclei -u {url}", {"url": "https://example.com"})
        self.assertEqual(r.env, {})
        self.assertEqual(r.argv, ["nuclei", "-u", "https://example.com"])

    def test_empty_template(self):
        r = cmd.render_command("", {})
        self.assertEqual(r.argv, [])
        self.assertEqual(r.summary, "")
        self.assertEqual(r.env, {})

    def test_numbers_are_stringified(self):
        r = cmd.render_command("tool --port {port}", {"port": 8443})
        self.assertEqual(r.argv, ["tool", "--port", "8443"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
