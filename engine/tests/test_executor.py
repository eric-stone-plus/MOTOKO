"""SubprocessExecutor tests — real child processes, no shell, capture + timeout.

Run:  python3 tests/test_executor.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko.executor import SubprocessExecutor, resolve_tool  # noqa: E402


class FakeWriter:
    def __init__(self):
        self.obs: list[dict] = []

    def record_observation(self, **kw):
        self.obs.append(kw)


class TestResolveTool(unittest.TestCase):
    def test_echo_on_path(self):
        self.assertTrue(resolve_tool("echo"))

    def test_unknown_tool_none(self):
        self.assertIsNone(resolve_tool("definitely-not-a-tool-xyz"))


class TestResolveToolPrecedence(unittest.TestCase):
    """R5 M4: known dirs outrank PATH; path-looking names are refused."""

    def _fake_tool(self, name: str) -> Path:
        d = Path(tempfile.mkdtemp(prefix="motoko-bin-"))
        p = d / name
        p.write_text("#!/bin/sh\necho fake\n")
        p.chmod(p.stat().st_mode | 0o111)
        return p

    def test_known_dirs_win_over_path(self):
        fake = self._fake_tool("echo")
        got = resolve_tool("echo", extra_dirs=(fake.parent,))
        self.assertEqual(got, str(fake),
                         "a PATH copy shadowed the known tool directory")

    def test_tool_name_with_separators_is_refused(self):
        for bad in ("/bin/sh", "../bin/sh", "bin/sh", "a\\b", "..", "x/../y"):
            self.assertIsNone(resolve_tool(bad), f"refused name resolved: {bad!r}")

    def test_bare_name_is_not_affected_by_the_separator_rule(self):
        self.assertTrue(resolve_tool("echo"))


class TestExecutor(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="motoko-exec-"))
        self.writer = FakeWriter()
        self.ex = SubprocessExecutor(self.writer, "eng", self.tmp / "obs",
                                     tool_timeout=10)

    def _action(self, argv, **kw):
        return {"tool": argv[0], "argv": argv,
                "url": "https://example.com", **kw}

    def test_runs_and_records(self):
        argv = ["echo", "hello-motoko"]
        self.ex({}, self._action(argv))
        self.assertEqual(len(self.writer.obs), 1)
        o = self.writer.obs[0]
        self.assertEqual(o["tool"], "echo")
        self.assertEqual(o["exit_code"], 0)
        self.assertIsNotNone(o["raw_path"])
        out = Path(o["raw_path"]).read_text()
        self.assertIn("hello-motoko", out)

    def test_missing_binary_records_127(self):
        self.ex({}, self._action(["definitely-not-a-tool-xyz", "x"]))
        self.assertEqual(self.writer.obs[0]["exit_code"], 127)
        self.assertIn("not found", self.writer.obs[0]["parsed_summary"])

    def test_nonzero_exit_recorded(self):
        self.ex({}, self._action(["false"]))
        self.assertEqual(self.writer.obs[0]["exit_code"], 1)

    def test_no_argv_recorded(self):
        self.ex({}, {"tool": "echo", "argv": None})
        self.assertEqual(self.writer.obs[0]["exit_code"], -1)

    def test_timeout_kills(self):
        argv = ["sleep", "30"]
        ex = SubprocessExecutor(self.writer, "eng", self.tmp / "obs2",
                                tool_timeout=1, kill_grace=1)
        ex({}, self._action(argv))
        o = self.writer.obs[0]
        self.assertNotEqual(o["exit_code"], 0)
        self.assertIn("timeout", o["parsed_summary"])

    def test_argv_is_not_shell_parsed(self):
        # a literal "$HOME|curl" token must survive as ONE argv element
        argv = ["printf", "%s", "$HOME|curl"]
        self.ex({}, self._action(argv))
        out = Path(self.writer.obs[0]["raw_path"]).read_text()
        self.assertIn("$HOME|curl", out)

    def test_unwritable_artifact_path_does_not_raise(self):
        # R5 H2: the error path's write_text used to re-throw OSError and
        # kill the main loop. Sabotage the obs dir (replace it with a file)
        # so both the stdout open and the stderr fallback fail.
        obs = self.tmp / "obs_sabotaged"
        ex = SubprocessExecutor(self.writer, "eng", obs, tool_timeout=5)
        obs.rmdir()
        obs.write_text("now a file, not a directory")
        ex({}, self._action(["echo", "hi"]))     # must not raise
        self.assertEqual(len(self.writer.obs), 1)
        self.assertEqual(self.writer.obs[0]["exit_code"], 126)

    def test_record_observation_failure_does_not_raise(self):
        # R5 H2: a DB error while recording must not escape __call__.
        import sqlite3

        class DownWriter:
            def record_observation(self, **kw):
                raise sqlite3.OperationalError("database is locked")

        ex = SubprocessExecutor(DownWriter(), "eng", self.tmp / "obs_down",
                                tool_timeout=5)
        ex({}, self._action(["echo", "hi"]))     # must not raise

    def test_observation_records_target_url_and_host(self):
        # R5 H3: url/host were computed but dropped — the next SYNC beat
        # then had no target context for the parser (F13 regression).
        action = {"tool": "echo", "argv": ["echo", "hi"],
                  "url": "https://app.example.com/x"}
        self.ex({"host": "app.example.com"}, action)
        o = self.writer.obs[0]
        self.assertEqual(o["url"], "https://app.example.com/x")
        self.assertEqual(o["host"], "app.example.com")

    def test_missing_binary_observation_keeps_target_context(self):
        self.ex({"url": "https://app.example.com/x", "host": "app.example.com"},
                {"tool": "definitely-not-a-tool-xyz",
                 "argv": ["definitely-not-a-tool-xyz", "x"]})
        o = self.writer.obs[0]
        self.assertEqual(o["exit_code"], 127)
        self.assertEqual(o["url"], "https://app.example.com/x")
        self.assertEqual(o["host"], "app.example.com")

    def test_no_argv_observation_keeps_target_context(self):
        self.ex({"url": "https://app.example.com/x", "host": "app.example.com"},
                {"tool": "echo", "argv": None})
        o = self.writer.obs[0]
        self.assertEqual(o["exit_code"], -1)
        self.assertEqual(o["url"], "https://app.example.com/x")
        self.assertEqual(o["host"], "app.example.com")

    def test_summary_carries_the_guard_checked_bind_ip(self):
        # R5 H4: a subprocess tool re-resolves DNS itself, so the executor
        # cannot pin it — but the observation must record which address the
        # guard actually cleared for this run.
        action = self._action(["echo", "hi"], bind_ip="10.0.0.5")
        self.ex({}, action)
        self.assertIn("bind_ip=10.0.0.5", self.writer.obs[0]["parsed_summary"])

    def test_env_must_be_a_mapping(self):
        # R5 M3: a non-mapping env is a malformed action — record, never exec.
        self.ex({}, {"tool": "echo", "argv": ["echo", "hi"],
                     "env": ["MOTOKO_SECRET_A"]})
        o = self.writer.obs[0]
        self.assertIsNone(o["raw_path"], "the tool executed with a malformed env")
        self.assertEqual(o["exit_code"], -2)
        self.assertIn("env", o["parsed_summary"])

    def test_non_secret_env_keys_are_dropped_and_recorded(self):
        # R5 M3: only MOTOKO_SECRET_* may reach the child environment.
        self.ex({}, {"tool": "env", "argv": ["env"],
                     "env": {"NOTOKEN_K": "sekret-value",
                             "MOTOKO_SECRET_OK": "fine"}})
        o = self.writer.obs[0]
        out = Path(o["raw_path"]).read_text()
        self.assertIn("MOTOKO_SECRET_OK=fine", out)
        self.assertNotIn("NOTOKEN_K=sekret-value", out,
                         "a non-prefixed key reached the child environment")
        self.assertIn("NOTOKEN_K", o["parsed_summary"],
                      "the dropped key was not recorded")

    def test_argv0_fallback_when_the_tool_name_is_stale(self):
        # R5 M4: tool name misses (legacy rule naming) fall back to the
        # basename of argv[0] — here "kr" while the action says "kiterunner".
        d = Path(tempfile.mkdtemp(prefix="motoko-fb-"))
        fake = d / "kr"
        fake.write_text("#!/bin/sh\necho kr-ran\n")
        fake.chmod(fake.stat().st_mode | 0o111)
        with mock.patch.dict(os.environ,
                             {"PATH": str(d) + os.pathsep + os.environ.get("PATH", "")}):
            self.ex({}, {"tool": "kiterunner", "argv": ["kr", "scan", "http://x"]})
        o = self.writer.obs[0]
        self.assertEqual(o["exit_code"], 0, "the argv[0] fallback did not run")
        self.assertIn("kr-ran", Path(o["raw_path"]).read_text())


class LifecycleWriter(FakeWriter):
    """FakeWriter + finish_tool_run capture (R5 M6)."""

    def __init__(self):
        super().__init__()
        self.finished: list[tuple] = []

    def finish_tool_run(self, run_id, *, status, exit_code=None,
                        stdout_ref=None, stderr_ref=None):
        self.finished.append((run_id, status, exit_code, stdout_ref, stderr_ref))


class TestToolRunLifecycle(unittest.TestCase):
    """R5 M6: every executed action closes its tool_run row."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="motoko-tr-"))
        self.writer = LifecycleWriter()
        self.ex = SubprocessExecutor(self.writer, "eng", self.tmp / "obs",
                                     tool_timeout=5)

    def test_done_closes_the_row(self):
        self.ex({}, {"tool": "echo", "argv": ["echo", "hi"],
                     "_tool_run_id": "tr_done"})
        self.assertEqual(len(self.writer.finished), 1)
        rid, status, code, out_ref, _err = self.writer.finished[0]
        self.assertEqual((rid, status, code), ("tr_done", "done", 0))
        self.assertTrue(out_ref and Path(out_ref).exists())

    def test_error_closes_the_row(self):
        self.ex({}, {"tool": "false", "argv": ["false"],
                     "_tool_run_id": "tr_err"})
        rid, status, code, _o, _e = self.writer.finished[-1]
        self.assertEqual((rid, status, code), ("tr_err", "error", 1))

    def test_timeout_closes_the_row(self):
        ex = SubprocessExecutor(self.writer, "eng", self.tmp / "obs_t",
                                tool_timeout=1, kill_grace=1)
        ex({}, {"tool": "sleep", "argv": ["sleep", "30"],
                "_tool_run_id": "tr_to"})
        rid, status, _c, _o, _e = self.writer.finished[-1]
        self.assertEqual((rid, status), ("tr_to", "timeout"))

    def test_missing_binary_closes_the_row_as_error(self):
        self.ex({}, {"tool": "definitely-not-a-tool-xyz",
                     "argv": ["definitely-not-a-tool-xyz", "x"],
                     "_tool_run_id": "tr_127"})
        rid, status, code, _o, _e = self.writer.finished[-1]
        self.assertEqual((rid, status, code), ("tr_127", "error", 127))

    def test_argv_elements_must_be_strings(self):
        # R5 M9: non-string argv elements are refused before Popen.
        self.ex({}, {"tool": "echo", "argv": ["echo", 123, None]})
        o = self.writer.obs[0]
        self.assertIsNone(o["raw_path"], "executed with non-string argv")
        self.assertEqual(o["exit_code"], -2)
        self.assertIn("argv", o["parsed_summary"])

    def test_popen_type_error_is_contained(self):
        # R5 M9: the spawn except clause covers TypeError/ValueError too.
        with mock.patch("motoko.executor.subprocess.Popen",
                        side_effect=TypeError("bad args")):
            self.ex({}, {"tool": "echo", "argv": ["echo", "hi"],
                         "url": "https://example.com"})
        o = self.writer.obs[0]
        self.assertEqual(o["exit_code"], 126, "spawn type error escaped the guard")
        self.assertIn("error", o["parsed_summary"])

    def test_no_run_id_is_a_noop(self):
        self.ex({}, {"tool": "echo", "argv": ["echo", "hi"]})
        self.assertEqual(self.writer.finished, [])

    def test_finish_failure_does_not_raise(self):
        class BrokenFinish(LifecycleWriter):
            def finish_tool_run(self, run_id, **kw):
                raise RuntimeError("db is gone")

        ex = SubprocessExecutor(BrokenFinish(), "eng", self.tmp / "obs_b",
                                tool_timeout=5)
        ex({}, {"tool": "echo", "argv": ["echo", "hi"], "_tool_run_id": "tr_b"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
