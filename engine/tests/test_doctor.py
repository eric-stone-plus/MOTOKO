"""motoko doctor — self-check contract tests.

doctor is the fresh-host gate: it must fail loudly on a broken runtime
surface, warn (never fail) on optional pieces, and NEVER print a secret
value.
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

from motoko import doctor  # noqa: E402

VALID_CFG = (
    "auditors:\n"
    "- name: leg-a\n"
    "  protocol: anthropic\n"
    "  base_url: http://endpoint.example/v1\n"
    "  api_key_env: DOCTOR_TEST_KEY\n"
    "adjudicator:\n"
    "  name: judge\n"
    "  protocol: cli\n"
    '  command: ["/bin/true", "-p"]\n'
)


class DoctorTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="motoko-doctor-"))
        (self.tmp / "root").mkdir()
        self.env = {
            "MOTOKO_HOME": str(self.tmp / "root"),
            "MOTOKO_CONFIG": str(self.tmp / "loop.yaml"),
            "PATH": os.environ.get("PATH", "/usr/bin"),
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_doctor(self, extra_env: dict | None = None):
        env = dict(self.env)
        env.update(extra_env or {})
        with mock.patch.dict(os.environ, env, clear=True):
            return doctor.doctor()


class TestDoctorHappyPath(DoctorTestBase):
    def test_valid_config_reports_ok_and_exit_zero(self):
        (self.tmp / "loop.yaml").write_text(VALID_CFG)
        rc, lines = self.run_doctor({"DOCTOR_TEST_KEY": "x"})
        self.assertEqual(rc, 0)
        by_msg = " | ".join(m for _, m in lines)
        self.assertIn("loop config", by_msg)
        self.assertIn("valid (auditors: leg-a; adjudicator: judge)", by_msg)
        self.assertIn("key env DOCTOR_TEST_KEY: set", by_msg)
        self.assertNotIn("FAIL", [level for level, _ in lines])

    def test_missing_config_is_warn_not_fail(self):
        rc, lines = self.run_doctor()
        self.assertEqual(rc, 0)
        self.assertTrue(any("no loop config" in m for _, m in lines))

    def test_missing_engagement_root_warns(self):
        rc, lines = self.run_doctor({"MOTOKO_HOME": str(self.tmp / "nope")})
        self.assertEqual(rc, 0)
        self.assertTrue(any("root missing" in m for _, m in lines))


class TestDoctorFailures(DoctorTestBase):
    def test_invalid_config_fails(self):
        (self.tmp / "loop.yaml").write_text("auditors:\n")  # no adjudicator
        rc, lines = self.run_doctor()
        self.assertEqual(rc, 1)
        self.assertTrue(any(level == doctor.FAIL for level, _ in lines))

    def test_unset_env_var_in_config_fails(self):
        (self.tmp / "loop.yaml").write_text(
            VALID_CFG.replace("http://endpoint.example/v1", "${DOCTOR_UNSET_X}"))
        rc, _ = self.run_doctor()
        self.assertEqual(rc, 1)

    def test_unwritable_root_fails(self):
        ro = self.tmp / "ro"
        ro.mkdir()
        ro.chmod(0o555)
        try:
            rc, lines = self.run_doctor({"MOTOKO_HOME": str(ro)})
            self.assertEqual(rc, 1)
            self.assertTrue(any("not writable" in m for _, m in lines))
        finally:
            ro.chmod(0o755)


class TestDoctorNeverLeaks(DoctorTestBase):
    def test_key_values_never_appear_in_output(self):
        (self.tmp / "loop.yaml").write_text(VALID_CFG)
        secret = "SUPERSECRETVALUE-9x8y7z"
        rc, lines = self.run_doctor({"DOCTOR_TEST_KEY": secret})
        blob = repr(lines)
        self.assertNotIn(secret, blob)
        buf = io.StringIO()
        with mock.patch.dict(os.environ,
                             dict(self.env, DOCTOR_TEST_KEY=secret),
                             clear=True):
            with contextlib.redirect_stdout(buf):
                from motoko import cli
                cli.main(["doctor"])
        self.assertNotIn(secret, buf.getvalue())
        self.assertIn("set", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
