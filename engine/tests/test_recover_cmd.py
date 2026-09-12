"""cmd_recover — the one-shot re-drive entry (CLI wrapper contract).

recycle_stuck_hypotheses itself is covered in test_failure.py; these pin
the CLI surface: JSON output, exit codes, and the sealed-reopened note.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import cli, db, seal  # noqa: E402

ENG = "eng-recover"


def _hyp(w, hid: str, state: str = "testing", priority: float = 60.0) -> None:
    w.upsert_entity({
        "id": hid, "kind": "hypothesis", "engagement_id": ENG,
        "state": state, "priority": priority,
        "type": "probe", "target": "https://target.example",
        "source": "test",
    })


def _failed_run(w, hid: str) -> None:
    run_id = w.start_tool_run(tool="printenv", command="printenv",
                              hypothesis_id=hid)
    w.finish_tool_run(run_id, status="error", exit_code=1)


class TestRecoverCmd(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-recover-"))
        self.old_root = db.default_root
        db.default_root = lambda: self.root  # CLI resolves root lazily
        db.init_engagement(self.root, ENG, name="rec",
                           in_scope=["example.com"])
        w = db.Database(self.root / ENG / "graph.db")
        _hyp(w, "hyp_strand")
        _failed_run(w, "hyp_strand")
        _hyp(w, "hyp_live")
        w.start_tool_run(tool="strix", command="strix -m deep",
                         hypothesis_id="hyp_live")
        w.commit()
        w.close()
        self.env_root = self.root

    def tearDown(self):
        db.default_root = self.old_root
        shutil.rmtree(self.root, ignore_errors=True)

    def _run_cli(self, *argv: str):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(list(argv))
        return rc, buf.getvalue()

    def test_recycle_via_cli(self):
        rc, out = self._run_cli("recover", ENG)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["recycled"], 1)
        self.assertEqual(payload["abandoned"], 0)
        self.assertEqual(payload["testing_remaining"], 1)  # the live one
        self.assertFalse(payload["sealed_reopened"])
        w = db.Database(self.root / ENG / "graph.db", read_only=True)
        try:
            self.assertEqual(w.get_entity("hyp_strand")["state"], "proposed")
            self.assertEqual(w.get_entity("hyp_live")["state"], "testing")
        finally:
            w.close()

    def test_missing_engagement_exits_two(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cli.main(["recover", "ghost"])
        self.assertEqual(rc, 2)
        self.assertIn("not found", err.getvalue())

    def test_sealed_reopen_reports_re_seal(self):
        seal.seal_engagement(ENG, root=self.root)
        rc, out = self._run_cli("recover", ENG)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertTrue(payload["sealed_reopened"])
        self.assertTrue(payload["re_seal"])
        # the artifact drifted from its manifest — verify must say so
        ok, detail = seal.verify_seal(ENG, root=self.root)
        self.assertFalse(ok)
        self.assertIn("MISMATCH", detail)


if __name__ == "__main__":
    unittest.main()
