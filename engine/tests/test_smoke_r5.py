"""R5 smoke: init --seed -> run() must produce a REAL observation.

End-to-end integration over unit-testable seams: a temp rules dir carries
one bootstrap rule; a fake ``httpx`` executable on PATH emits one JSONL
record shaped like the real tool. The full chain under test is

    init (CLI) -> seed asset -> _expand -> rule -> scope guard -> cmd render
    -> SubprocessExecutor (real subprocess) -> obs/*.out -> _sync -> parser
    -> asset in the graph

Run:  python3 tests/test_smoke_r5.py
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import cli, db  # noqa: E402
from motoko.executor import SubprocessExecutor  # noqa: E402
from motoko.orchestrator import Orchestrator  # noqa: E402

SEED = "http://10.0.0.5/"

# One bootstrap rule; command renders to argv and the fake httpx echoes the
# URL as the last argument, exactly like the real -json output shape.
RULE = """{
  "id": "R-SMOKE-BOOT-001",
  "name": "smoke bootstrap",
  "category": "tech",
  "when": {"all": [{"fact": "url", "op": "matches", "value": "^https?://"}]},
  "then": {
    "hypothesis": "smoke httpx",
    "actions": [{"tool": "httpx",
                 "cmd": "httpx -silent -status-code -tech-detect -json -u {url}"}],
    "priority": {"impact": 0.6, "cost": 0.1}
  }
}
"""


def _write_fake_tool(bin_dir: Path) -> None:
    """A real executable that prints one httpx-shaped JSONL record."""
    script = bin_dir / "httpx"
    script.write_text(
        "#!/bin/sh\n"
        "# fake httpx: emit the last argument as the alive URL\n"
        'last=""; for a in "$@"; do last="$a"; done\n'
        "printf '{\"url\":\"%s\",\"status_code\":200,\"title\":\"smoke\","
        "\"tech\":[\"nginx\"],\"webserver\":\"nginx\"}\\n' \"$last\"\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class TestSmokeInitSeedRun(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-smoke-"))
        self.eng = "eng-smoke"
        self.rules = self.root / "rules"
        self.rules.mkdir()
        (self.rules / "boot.json").write_text(RULE)
        self.bin = self.root / "fakebin"
        self.bin.mkdir()
        _write_fake_tool(self.bin)

    def test_init_seed_run_produces_a_real_observation_and_asset(self):
        path_patch = {"PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", "")}
        with mock.patch.dict(os.environ, {"MOTOKO_HOME": str(self.root), **path_patch}):
            rc = cli.main(["init", self.eng, "--name", "smoke",
                           "--scope", "10.0.0.0/24", "--seed", SEED])
            self.assertEqual(rc, 0)

            edir = db.engagement_dir(self.root, self.eng)
            self.assertTrue((edir / "graph.db").exists())

            orch = Orchestrator(self.eng, root=self.root, rules_dir=self.rules,
                                resolver=lambda h: ["10.0.0.5"])
            orch.executor = SubprocessExecutor(
                orch.writer, self.eng, orch.artifacts,
                tool_timeout=10, tool_dirs=(self.bin,))
            try:
                summary = orch.run(max_cycles=3)

                obs = [dict(r) for r in orch.writer.conn.execute(
                    "SELECT tool, raw_path, url FROM observations")]
                self.assertTrue(obs, "no observation was recorded")
                executed = [o for o in obs if o["raw_path"]]
                self.assertTrue(
                    executed, "no observation has a raw_path — the tool was "
                              "never really executed (skeleton-only run?)")
                raw = Path(executed[0]["raw_path"])
                self.assertTrue(raw.exists() and raw.stat().st_size > 0,
                                "the recorded stdout file is empty")
                body = raw.read_text()
                self.assertIn("status_code", body,
                              "the raw output is not the fake httpx JSONL")
                self.assertEqual(executed[0]["tool"], "httpx")

                assets = orch.writer.query_entities(kind="asset",
                                                    engagement_id=self.eng)
                parsed = [a for a in assets if a.get("source") == "httpx"]
                self.assertTrue(parsed, "the httpx observation produced no asset")
                self.assertEqual(parsed[0]["value"], SEED)

                # R5 M6: every tool_run row was closed by the executor
                runs = [dict(r) for r in orch.writer.conn.execute(
                    "SELECT status, exit_code, stdout_ref FROM tool_run")]
                self.assertTrue(runs, "no tool_run row was opened for the action")
                self.assertNotIn("running", [r["status"] for r in runs],
                                 "a tool_run row was left hanging in 'running'")
                self.assertEqual(runs[0]["status"], "done")
                self.assertTrue(runs[0]["stdout_ref"])
            finally:
                orch.close()
        self.assertGreaterEqual(summary["cycle"], 2)

    def test_parse_of_the_smoke_jsonl_yields_one_asset(self):
        from motoko.parsers import parse_tool
        out = ('{"url":"http://10.0.0.5/","status_code":200,'
               '"title":"smoke","tech":["nginx"]}\n')
        parsed = parse_tool("httpx", out, "", {})
        self.assertEqual(len(parsed.assets), 1)
        self.assertEqual(parsed.assets[0]["value"], SEED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
