"""R5 M1/M2: CLI pre-flight guards.

M1 — every --seed passes the scope guard BEFORE any engagement is created;
an out-of-scope seed is rejected (stderr + non-zero exit), no --force.
M2 — `run` on a missing engagement reports cleanly and returns 2 instead
of silently creating an empty graph.db.

Run:  python3 tests/test_cli.py
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import cli, db  # noqa: E402


class CliCase(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-cli-"))
        self._env = mock.patch.dict(os.environ, {"MOTOKO_HOME": str(self.root)})
        self._env.start()
        self.addCleanup(self._env.stop)

    def _engage(self, eng: str) -> Path:
        return db.engagement_dir(self.root, eng)


class TestInitSeedGuard(CliCase):
    def test_out_of_scope_seed_is_rejected(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["init", "eng-rej", "--scope", "10.0.0.0/24",
                           "--seed", "http://10.0.1.99/"])
        self.assertNotEqual(rc, 0, "an out-of-scope seed was accepted")
        self.assertIn("10.0.1.99", err.getvalue(),
                      "the rejection reason did not reach stderr")
        self.assertFalse((self._engage("eng-rej") / "graph.db").exists(),
                         "a rejected init still created an engagement")

    def test_seed_matching_out_of_scope_wins(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["init", "eng-ooo", "--scope", "10.0.0.0/24",
                           "--out-of-scope", "10.0.0.99",
                           "--seed", "http://10.0.0.99/"])
        self.assertNotEqual(rc, 0)
        self.assertFalse((self._engage("eng-ooo") / "graph.db").exists())

    def test_in_scope_seed_is_accepted_and_seeded(self):
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["init", "eng-ok", "--scope", "10.0.0.0/24",
                           "--seed", "http://10.0.0.5/"])
        self.assertEqual(rc, 0)
        d = db.Database(self._engage("eng-ok") / "graph.db")
        try:
            assets = d.query_entities(kind="asset", engagement_id="eng-ok")
        finally:
            d.close()
        self.assertEqual([a["value"] for a in assets], ["http://10.0.0.5/"])

    def test_all_seeds_checked_before_anything_is_created(self):
        with contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["init", "eng-mixed", "--scope", "10.0.0.0/24",
                           "--seed", "http://10.0.0.5/",
                           "--seed", "http://10.0.1.99/"])
        self.assertNotEqual(rc, 0, "one bad seed in a batch was not rejected")
        self.assertFalse((self._engage("eng-mixed") / "graph.db").exists(),
                         "a rejected batch still created the engagement")


class TestRunMissingEngagement(CliCase):
    def test_run_on_missing_engagement_returns_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["run", "no-such-eng", "--max-cycles", "1"])
        self.assertEqual(rc, 2)
        self.assertIn("no-such-eng", err.getvalue(),
                      "no friendly message on stderr")
        self.assertFalse((self._engage("no-such-eng") / "graph.db").exists(),
                         "run silently created a graph.db for a missing engagement")

    def test_run_on_existing_engagement_proceeds(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["init", "eng-run", "--scope", "10.0.0.0/24"]), 0)
        rules = self.root / "empty-rules"
        rules.mkdir()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["run", "eng-run", "--max-cycles", "1",
                           "--rules-dir", str(rules)])
        self.assertEqual(rc, 0, f"run failed on an existing engagement: {out.getvalue()!r}")
        self.assertIn("cycle", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
