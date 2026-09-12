"""P-030-R2 micro-patch lock tests (grok round-2 adjudication).

Two lock tests the round-1 LAND list demanded but never received:

* T-ARGV — the container argv contract: a non-proxy tool's podman exec
  argv carries the 8x ``--env`` blanking pairs (6 proxy vars + no_proxy /
  NO_PROXY) strictly BEFORE the container name, so podman parses them as
  exec options and not as the container's command. gau (a _PROXY_TOOLS
  member) gets none of them. The production order is legal; this test
  pins it so nobody "fixes" it into -e-after-container (rejected).
* T-ASSET — the asset-side seen-set inside the PRODUCTION ingest-strix
  path: re-ingesting the same strix report must not grow the asset table
  (first pass left 87 rows / 43 distinct values in a production graph).

Run:  python3 tests/test_p030_micro.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import db as motoko_db  # noqa: E402
from motoko.executor import SubprocessExecutor  # noqa: E402

_PROXY_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
               "all_proxy", "ALL_PROXY")


class _NullWriter:
    """Records observation/finish calls; no database behind it."""

    def __init__(self):
        self.obs: list[dict] = []
        self.finished: list[dict] = []

    def record_observation(self, **kw):
        self.obs.append(kw)
        return "obs-1"

    def finish_tool_run(self, run_id, **kw):
        self.finished.append({"run_id": run_id, **kw})


class _FakeProc:
    returncode = 0

    def communicate(self, timeout=None):
        return (b"", b"")

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        pass

    def kill(self):
        pass

    pid = -1


class TestContainerArgvOrder(unittest.TestCase):
    """T-ARGV: 8x --env blanking strictly before the container name for
    non-proxy tools; gau gets none. No real container is touched — a fake
    podman path plus a mocked Popen captures the argv."""

    def _capture(self, tool, runtime="container"):
        argvs: list[list[str]] = []
        ex = SubprocessExecutor.__new__(SubprocessExecutor)
        ex.writer = _NullWriter()
        ex.engagement_id = "t-eng"
        ex.artifacts = Path(tempfile.mkdtemp(prefix="motoko-argv-"))
        ex.tool_timeout = 5
        ex.kill_grace = 0
        ex.tool_dirs = ()
        action = {"tool": tool, "runtime": runtime,
                  "container": "kali-recon",
                  "url": "https://job.example.com.cn/",
                  "argv": [tool, "-u", "https://job.example.com.cn/"]}
        with mock.patch("motoko.executor.resolve_tool",
                        return_value="/fake/bin/podman"), \
                mock.patch("motoko.executor.subprocess.Popen",
                           side_effect=lambda argv, **kw: (argvs.append(list(argv)),
                                                           _FakeProc())[1]):
            ex({}, action)
        return argvs[0]

    def test_non_proxy_tool_has_eight_envs_before_container(self):
        argv = self._capture("netexec")
        self.assertEqual(argv[0], "/fake/bin/podman")
        self.assertEqual(argv[1], "exec")
        cpos = argv.index("kali-recon")
        self.assertGreater(cpos, 1, "container name before 'exec' options")
        head = argv[:cpos]
        # exactly 8 --env pairs in the pre-container region: 6 proxy blanks
        # + no_proxy=* + NO_PROXY=*
        self.assertEqual(head.count("--env"), 8,
                         f"expected 8 --env pairs before the container, "
                         f"got {head.count('--env')}: {head}")
        cleared = {head[i + 1].split("=", 1)[0]
                   for i in range(len(head)) if head[i] == "--env"}
        self.assertEqual(cleared, set(_PROXY_VARS) | {"no_proxy", "NO_PROXY"})
        # every pair is a blanking assignment (var=) or the wildcard passthrough
        for i in range(len(head)):
            if head[i] == "--env":
                self.assertTrue(head[i + 1].endswith("=") or
                                head[i + 1] in ("no_proxy=*", "NO_PROXY=*"),
                                f"non-blanking --env value: {head[i + 1]!r}")
        # the tool argv still rides AFTER the container name
        self.assertIn("netexec", argv[cpos + 1:])

    def test_gau_gets_no_env_clears(self):
        argv = self._capture("gau")
        cpos = argv.index("kali-recon")
        self.assertEqual(argv[:cpos].count("--env"), 0,
                         "gau is a proxy tool — it must keep the proxy env, "
                         "no blanking pairs may precede the container name")


class TestIngestAssetSeenSet(unittest.TestCase):
    """T-ASSET: the PRODUCTION ingest-strix seen-set. The same strix
    report ingested twice must not grow the asset table — the first pass
    left 87 rows / 43 distinct values (evil.example.com.cn x4) in a production graph.
    Drives cli.main(["ingest-strix", ...]) end to end; no hand-written
    loop duplicating the gate."""

    REPORT = (
        "Deep dive session report\n"
        "found https://job.example.com.cn/campus\n"
        "crawled https://job.example.com.cn/campus/list\n"
        "also https://www.example.com.cn/about\n"
    )

    def setUp(self):
        import tempfile as _tf
        self.tmp = Path(_tf.mkdtemp(prefix="motoko-tasset-"))
        self._env = mock.patch.dict(os.environ,
                                    {"MOTOKO_HOME": str(self.tmp)})
        self._env.start()
        self.addCleanup(self._env.stop)
        from motoko import cli, db
        self.cli = cli
        self.db = db
        db.init_engagement(self.tmp, "eng-t", name="t",
                           in_scope=["example.com.cn"], out_of_scope=[])
        self.report = self.tmp / "strix-report.md"
        self.report.write_text(self.REPORT, encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ingest_twice(self):
        import contextlib
        import io
        for _ in range(2):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = self.cli.main(["ingest-strix", "eng-t",
                                    str(self.report)])
            self.assertEqual(rc, 0, out.getvalue())
        w = self.db.Database(self.tmp / "eng-t" / "graph.db")
        try:
            rows = w.query_entities(kind="asset", engagement_id="eng-t")
        finally:
            w.close()
        return rows

    def test_same_assets_twice_does_not_grow_rows(self):
        rows = self._ingest_twice()
        distinct = {(r.get("type"), r.get("value")) for r in rows}
        self.assertEqual(len(rows), len(distinct),
                         "asset rows grew on re-ingest: "
                         f"{len(rows)} rows / {len(distinct)} distinct")
        self.assertEqual(len(rows), 3,
                         f"expected the 3 report URLs, got {len(rows)}")
        values = {r["value"] for r in rows}
        self.assertEqual(values, {"https://job.example.com.cn/campus",
                                  "https://job.example.com.cn/campus/list",
                                  "https://www.example.com.cn/about"})


if __name__ == "__main__":
    unittest.main()

