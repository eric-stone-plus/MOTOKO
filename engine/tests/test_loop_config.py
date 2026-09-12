"""Loop-config consolidation — resolution order, ${VAR}/~ expansion.

The engine's config layering (ARCHITECTURE.md): $MOTOKO_CONFIG >
<motoko_root>/config/loop.yaml > legacy ~/.motoko/loop.yaml. Values
expand ${VAR} from the environment (unset = hard error) and a leading
"~"; api_key_env holds a variable NAME and is exempt.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import loop  # noqa: E402
from motoko.cli import validate_loop_config  # noqa: E402


class TestValueExpansion(unittest.TestCase):
    def test_env_var_expands(self):
        with mock.patch.dict(os.environ, {"TEST_BASE": "http://x.example/v1"}):
            self.assertEqual(loop._expand_value("${TEST_BASE}/chat"),
                             "http://x.example/v1/chat")

    def test_unset_var_is_a_hard_error(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as cm:
                loop._expand_value("http://${TEST_MISSING_VAR}/v1")
            self.assertIn("TEST_MISSING_VAR", str(cm.exception))

    def test_tilde_expands(self):
        self.assertEqual(loop._expand_value("~/.local/bin/tool"),
                         str(Path.home() / ".local" / "bin" / "tool"))

    def test_plain_value_untouched(self):
        self.assertEqual(loop._expand_value("qwen3.8-max"), "qwen3.8-max")


class TestParserExpansion(unittest.TestCase):
    def _parse(self, text: str) -> dict:
        return loop._parse_minimal_yaml(text)

    def test_command_tilde_entries_expand(self):
        cfg = self._parse(
            "adjudicator:\n"
            "  name: adj\n"
            "  protocol: cli\n"
            f"  command: [\"~/.local/bin/tool\", \"-p\"]\n")
        cmd = cfg["adjudicator"]["command"]
        self.assertEqual(cmd, [str(Path.home() / ".local/bin/tool"), "-p"])

    def test_command_env_var_entries_expand(self):
        with mock.patch.dict(os.environ, {"TEST_TOOL": "/opt/tool"}):
            cfg = self._parse(
                "adjudicator:\n"
                "  name: adj\n"
                "  protocol: cli\n"
                "  command: [\"${TEST_TOOL}\", \"-p\"]\n")
        self.assertEqual(cfg["adjudicator"]["command"], ["/opt/tool", "-p"])

    def test_api_key_env_is_not_interpolated(self):
        cfg = self._parse(
            "auditors:\n"
            "- name: a\n"
            "  protocol: anthropic\n"
            "  base_url: http://x.example\n"
            "  api_key_env: MY_KEY_ENV_NAME\n")
        self.assertEqual(cfg["auditors"][0]["api_key_env"], "MY_KEY_ENV_NAME")

    def test_base_url_env_var_expands(self):
        with mock.patch.dict(os.environ, {"TEST_BASE": "http://x.example"}):
            cfg = self._parse(
                "auditors:\n"
                "- name: a\n"
                "  protocol: anthropic\n"
                "  base_url: ${TEST_BASE}/v1\n"
                "  api_key_env: MY_KEY_ENV_NAME\n")
        self.assertEqual(cfg["auditors"][0]["base_url"], "http://x.example/v1")


class TestResolutionOrder(unittest.TestCase):
    def test_motoko_config_env_wins_even_if_missing(self):
        with mock.patch.dict(os.environ,
                             {"MOTOKO_CONFIG": "/tmp/does-not-matter.yaml"}):
            self.assertEqual(loop.default_config_path(),
                             Path("/tmp/does-not-matter.yaml"))

    def test_tree_config_beats_legacy_home(self):
        tree = Path(tempfile.mkdtemp(prefix="motoko-cfgtree-"))
        try:
            (tree / "config").mkdir()
            (tree / "config" / "loop.yaml").write_text("auditors:\n")
            fake_home = Path(tempfile.mkdtemp(prefix="motoko-cfghome-"))
            (fake_home / ".motoko").mkdir()
            (fake_home / ".motoko" / "loop.yaml").write_text("auditors:\n")
            env = {k: v for k, v in os.environ.items() if k != "MOTOKO_CONFIG"}
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(loop.util, "motoko_root",
                                       return_value=tree):
                    with mock.patch.object(loop.Path, "home",
                                           return_value=fake_home):
                        got = loop.default_config_path()
            self.assertEqual(got, tree / "config" / "loop.yaml")
        finally:
            import shutil
            shutil.rmtree(tree, ignore_errors=True)

    def test_legacy_home_is_final_fallback(self):
        tree = Path(tempfile.mkdtemp(prefix="motoko-cfgtree2-"))
        fake_home = Path(tempfile.mkdtemp(prefix="motoko-cfghome2-"))
        (fake_home / ".motoko").mkdir()
        legacy = fake_home / ".motoko" / "loop.yaml"
        legacy.write_text("auditors:\n")
        try:
            env = {k: v for k, v in os.environ.items() if k != "MOTOKO_CONFIG"}
            with mock.patch.dict(os.environ, env, clear=True):
                with mock.patch.object(loop.util, "motoko_root",
                                       return_value=tree):
                    # DEFAULT_CONFIG is bound at import time — patch the
                    # constant, not Path.home()
                    with mock.patch.object(loop, "DEFAULT_CONFIG", legacy):
                        got = loop.default_config_path()
            self.assertEqual(got, legacy)
        finally:
            import shutil
            shutil.rmtree(tree, ignore_errors=True)
            shutil.rmtree(fake_home, ignore_errors=True)


class TestInTreeLiveConfig(unittest.TestCase):
    """Integration: the operator-local motoko/config/loop.yaml must parse,
    expand and validate through the production path. Skipped on hosts that
    carry no live config (fresh clones) — the expansion mechanics are
    covered by TestParserExpansion."""

    def setUp(self):
        self.path = loop.util.motoko_root() / "config" / "loop.yaml"
        if not self.path.exists():
            self.skipTest("no live config/loop.yaml on this host")

    def test_tree_config_validates(self):
        cfg = loop.load_loop_config(self.path)
        self.assertEqual(validate_loop_config(cfg), [])
        names = [a["name"] for a in cfg["auditors"]]
        self.assertEqual(names, ["qwen", "kimi"])
        kimi_cmd = next(a for a in cfg["auditors"]
                        if a["name"] == "kimi")["command"]
        self.assertFalse(kimi_cmd[0].startswith("~"),
                         "cli command entries must be tilde-expanded")
        self.assertEqual(cfg["adjudicator"]["name"], "grok")

    def test_resolved_tree_config_has_no_home_path_literals(self):
        text = self.path.read_text()
        self.assertNotIn(str(Path.home()), text,
                         "live config FILE must be home-agnostic "
                         "(~ / ${VAR}); expansion happens at load time")
        cfg = loop.load_loop_config(self.path)
        blob = repr(cfg)
        self.assertNotIn('"~', blob,
                         "resolved config must have tilde-expanded commands")


if __name__ == "__main__":
    unittest.main()
