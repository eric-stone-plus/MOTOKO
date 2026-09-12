"""Validator wiring tests (F11 + F26 + F27).

The three deterministic validators must actually run from the main loop, be
fed by injectable IO, and never treat infrastructure failure or a missing URL
as falsification.

Run:  python3 tests/test_validation.py
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
RULES = Path(__file__).resolve().parents[1] / "rules"

from motoko import db  # noqa: E402
from motoko import orchestrator as orchestrator_mod  # noqa: E402
from motoko.orchestrator import Orchestrator  # noqa: E402
from motoko.verification import dom, oob, replay  # noqa: E402
from motoko.verification.dom import DomResult  # noqa: E402
from motoko.verification.replay import Response  # noqa: E402


class StubCanary:
    """Injected OOB IO: issue/trigger/poll over a callback script."""

    def __init__(self, callback: bool = True):
        self.callback = callback
        self.issued: list[str] = []
        self.triggered: list[tuple[str, str]] = []

    def issue(self) -> str:
        token = f"canary{len(self.issued) + 1}.oob.test"
        self.issued.append(token)
        return token

    def trigger(self, finding, canary) -> None:
        self.triggered.append((finding.get("id", "?"), canary))

    def poll(self, canary) -> bool:
        return self.callback


class ValidationCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="motoko-val-"))
        self.eng = "eng-val"
        db.init_engagement(self.tmp, self.eng, name="val",
                           in_scope=["example.com"], out_of_scope=[])

    def _orch(self, **kwargs):
        return Orchestrator(self.eng, root=self.tmp, rules_dir=RULES,
                            resolver=lambda h: [], **kwargs)

    def _finding(self, orch, fid, *, klass="sqli", url="https://api.example.com/?q=1",
                 detector="sqlmap"):
        orch.writer.upsert_entity({
            "id": fid, "kind": "finding", "engagement_id": self.eng,
            "state": "candidate", "class": klass, "url": url,
            "detector": detector, "signals": [], "confidence": 0.75,
        })
        ok, reason = orch.writer.advance_and_persist(fid, "dedup_pass")
        self.assertTrue(ok, reason)

    def _state(self, orch, fid):
        return orch.writer.get_entity(fid)["state"]


class TestValidatorDispatch(ValidationCase):
    def test_replay_validator_runs_from_the_loop(self):
        seen: list[str] = []

        def fetcher(url):
            seen.append(url)
            return Response(200, "<html>ok</html>")

        orch = self._orch(fetcher=fetcher)
        try:
            self._finding(orch, "fnd_rep")
            orch._validate()
            state = self._state(orch, "fnd_rep")
        finally:
            orch.close()
        self.assertEqual(seen, ["https://api.example.com/?q=1"],
                         "the replay validator never fetched the finding url")
        self.assertEqual(state, "reproduced")

    def test_oob_validator_runs_from_the_loop(self):
        canary = StubCanary(callback=True)
        orch = self._orch(canary=canary)
        try:
            self._finding(orch, "fnd_oob", klass="ssrf.basic", detector="nuclei")
            orch._validate()
            state = self._state(orch, "fnd_oob")
            signals = orch.writer.get_entity("fnd_oob")["signals"]
        finally:
            orch.close()
        self.assertEqual(state, "verified", "ssrf with a live callback must verify")
        self.assertIn("oob_callback", signals)
        self.assertTrue(canary.triggered, "the canary was never triggered")

    def test_dom_validator_runs_from_the_loop(self):
        orch = self._orch(browser=lambda url: DomResult(True, ["alert(1)"]))
        try:
            self._finding(orch, "fnd_dom", klass="xss.reflected", detector="dalfox")
            orch._validate()
            state = self._state(orch, "fnd_dom")
        finally:
            orch.close()
        self.assertEqual(state, "verified")

    def test_reproduced_findings_are_revalidated(self):
        fetched: list[str] = []

        def fetcher(url):
            fetched.append(url)
            return Response(200, "ok")

        orch = self._orch(fetcher=fetcher)
        try:
            self._finding(orch, "fnd_recheck")            # -> triaged
            ok, reason = orch.writer.advance_and_persist("fnd_recheck", "replay_ok")
            self.assertTrue(ok, reason)                   # -> reproduced
            orch._validate()
            state = self._state(orch, "fnd_recheck")
        finally:
            orch.close()
        self.assertEqual(fetched, ["https://api.example.com/?q=1"],
                         "a reproduced finding was not re-validated")
        self.assertEqual(state, "reproduced")


class TestNoFalseFalsification(ValidationCase):
    def test_io_exception_is_inconclusive(self):
        def fetcher(url):
            raise RuntimeError("connection reset by peer")

        orch = self._orch(fetcher=fetcher)
        try:
            self._finding(orch, "fnd_io")
            orch._validate()
            state = self._state(orch, "fnd_io")
            signals = orch.writer.get_entity("fnd_io")["signals"]
        finally:
            orch.close()
        self.assertEqual(state, "triaged", "an IO failure falsified the finding")
        self.assertNotIn("replay_fail", signals)

    def test_fetch_returning_nothing_is_inconclusive(self):
        orch = self._orch(fetcher=lambda url: None)
        try:
            self._finding(orch, "fnd_none")
            orch._validate()
            state = self._state(orch, "fnd_none")
        finally:
            orch.close()
        self.assertEqual(state, "triaged")

    def test_missing_url_is_inconclusive(self):
        orch = self._orch(fetcher=lambda url: Response(200))
        try:
            self._finding(orch, "fnd_nourl", url="")
            orch._validate()
            state = self._state(orch, "fnd_nourl")
            verdict = orch._run_validator("replay", {"id": "fnd_nourl", "class": "sqli",
                                                     "url": ""})
        finally:
            orch.close()
        self.assertEqual(state, "triaged", "a finding without a url was falsified")
        self.assertEqual(verdict.event, "inconclusive")

    def test_dom_without_a_browser_backend_is_inconclusive(self):
        orch = self._orch()   # no browser wired
        try:
            self._finding(orch, "fnd_nodom", klass="xss.reflected", detector="dalfox")
            orch._validate()
            state = self._state(orch, "fnd_nodom")
        finally:
            orch.close()
        self.assertEqual(state, "triaged")

    def test_canary_backend_missing_is_inconclusive(self):
        orch = self._orch()   # no canary wired
        try:
            self._finding(orch, "fnd_nocanary", klass="ssrf.basic", detector="nuclei")
            orch._validate()
            state = self._state(orch, "fnd_nocanary")
        finally:
            orch.close()
        self.assertEqual(state, "triaged")

    def test_out_of_scope_url_never_reaches_the_fetcher(self):
        fetched: list[str] = []
        orch = self._orch(fetcher=lambda url: fetched.append(url) or Response(200))
        try:
            self._finding(orch, "fnd_offscope", url="https://evil.com/?q=1")
            orch._validate()
            state = self._state(orch, "fnd_offscope")
            blocked = orch.writer.conn.execute(
                "SELECT COUNT(*) c FROM events WHERE kind='scope_blocked'").fetchone()["c"]
        finally:
            orch.close()
        self.assertEqual(fetched, [], "the validator issued a request to an out-of-scope host")
        self.assertEqual(state, "triaged")
        self.assertGreaterEqual(blocked, 1)


class TestFullLadder(ValidationCase):
    """triaged -> reproduced -> verified with real validators + stub IO."""

    def test_triaged_reproduced_verified(self):
        canary = StubCanary(callback=True)
        orch = self._orch(fetcher=lambda url: Response(200, "<html>ok</html>"),
                          canary=canary)
        try:
            self._finding(orch, "fnd_full", klass="sqli")
            # stage 1: replay puts it in reproduced
            v1 = replay.replay_verdict({"url": "https://api.example.com/?q=1"},
                                       orch.fetcher)
            ok, reason = orch.writer.advance_and_persist("fnd_full", v1.event,
                                                         verdict=v1)
            self.assertTrue(ok, reason)
            self.assertEqual(self._state(orch, "fnd_full"), "reproduced")
            # stage 2: OOB hard evidence promotes to verified
            finding = orch.writer.get_entity("fnd_full")
            v2 = oob.oob_verdict(finding, canary.issue, canary.trigger, canary.poll)
            self.assertEqual(v2.event, "oob_callback")
            ok, reason = orch.writer.advance_and_persist("fnd_full", v2.event,
                                                         verdict=v2)
            self.assertTrue(ok, reason)
            entity = orch.writer.get_entity("fnd_full")
        finally:
            orch.close()
        self.assertEqual(entity["state"], "verified")
        self.assertIn("oob_callback", entity["signals"])
        self.assertIn("replay_ok", entity["signals"])


class TestBindIpPinning(ValidationCase):
    """R3 H3: the address the guard cleared must be the address connected to.

    Re-resolving at request time reopens the DNS-rebinding window (guard sees
    an in-scope A record, the connection lands on an out-of-scope one)."""

    def _orch_pinned(self, resolver, **kwargs):
        return Orchestrator(self.eng, root=self.tmp, rules_dir=RULES,
                            resolver=resolver, **kwargs)

    def test_validator_hands_the_bind_ip_to_the_fetcher(self):
        seen = []

        def fetcher(url, bind_ip=None):
            seen.append((url, bind_ip))
            return Response(200, "<html>ok</html>")

        orch = self._orch_pinned(lambda h: ["93.184.216.34"], fetcher=fetcher)
        try:
            self._finding(orch, "fnd_bind", url="https://api.example.com/?q=1")
            orch._validate()
            state = self._state(orch, "fnd_bind")
        finally:
            orch.close()
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], "https://api.example.com/?q=1")
        self.assertEqual(seen[0][1], "93.184.216.34",
                         "the fetcher was not pinned to the guard's address")
        self.assertEqual(state, "reproduced")

    def test_dns_flip_still_connects_to_the_cleared_address(self):
        asked = []

        def flipping_resolver(host):
            asked.append(host)
            # first resolution (in the guard): in-scope; if anything resolved
            # again at connect time it would get the out-of-scope address
            return ["10.0.0.5"] if len(asked) == 1 else ["8.8.8.8"]

        seen = []

        def fetcher(url, bind_ip=None):
            seen.append(bind_ip)
            return Response(200, "ok")

        orch = self._orch_pinned(flipping_resolver, fetcher=fetcher)
        try:
            self._finding(orch, "fnd_flip", url="https://app.example.com/?q=1")
            orch._validate()
        finally:
            orch.close()
        self.assertEqual(seen, ["10.0.0.5"],
                         "the request was re-resolved instead of pinned")

    def test_no_bind_ip_means_no_request(self):
        calls = []

        def fetcher(url, bind_ip=None):
            calls.append((url, bind_ip))
            return Response(200)

        # A literal in-scope IP: the guard cleared the target by IP check and
        # never produced a bind_ip — there is nothing to pin, so nothing may
        # be sent.
        eng = "eng-h3-literal"
        db.init_engagement(self.tmp, eng, name="h3", in_scope=["example.com", "10.0.0.0/24"])
        orch = Orchestrator(eng, root=self.tmp, rules_dir=RULES,
                            resolver=lambda h: [], fetcher=fetcher)
        try:
            orch.writer.upsert_entity({
                "id": "fnd_noip", "kind": "finding", "engagement_id": eng,
                "state": "candidate", "class": "sqli", "url": "https://10.0.0.5/?q=1",
                "detector": "sqlmap", "signals": [], "confidence": 0.75,
            })
            ok, reason = orch.writer.advance_and_persist("fnd_noip", "dedup_pass")
            self.assertTrue(ok, reason)
            verdict = orch._run_validator(
                "replay", {"id": "fnd_noip", "class": "sqli",
                           "url": "https://10.0.0.5/?q=1"})
            orch._validate()
            state = orch.writer.get_entity("fnd_noip")["state"]
        finally:
            orch.close()
        self.assertEqual(calls, [], "the validator connected without a bind_ip")
        self.assertEqual(verdict.event, "inconclusive")
        self.assertEqual(state, "triaged")


class TestDefaultFetcherPinning(unittest.TestCase):
    """R3 H3: the real fetcher must TCP-connect to the bind_ip while keeping
    the original hostname in the Host header / TLS SNI."""

    def test_default_fetcher_connects_to_the_bind_ip(self):
        attempts = []

        def fake_connect(*args, **kwargs):
            attempts.append(args[0] if args else kwargs.get("address"))
            raise OSError("connection refused")

        with mock.patch.object(orchestrator_mod.socket, "create_connection",
                               fake_connect):
            got = orchestrator_mod.default_fetcher("https://api.example.com/x?q=1",
                                                   bind_ip="93.184.216.34")
        self.assertIsNone(got)
        self.assertEqual(attempts, [("93.184.216.34", 443)],
                         "the fetcher did not connect to the guard's address")

    def test_default_fetcher_refuses_without_a_bind_ip(self):
        attempts = []

        def fake_connect(*args, **kwargs):
            attempts.append(args[0] if args else kwargs.get("address"))
            raise OSError("connection refused")

        with mock.patch.object(orchestrator_mod.socket, "create_connection",
                               fake_connect):
            got = orchestrator_mod.default_fetcher("https://api.example.com/x")
        self.assertIsNone(got)
        self.assertEqual(attempts, [], "connected without a bind_ip")

    def test_default_fetcher_sends_the_original_host_header(self):
        # real loopback round trip: connect to 127.0.0.1 (the "bind_ip"),
        # present the URL's hostname in the Host header
        import socket as socketmod
        import threading

        srv = socketmod.socket(socketmod.AF_INET, socketmod.SOCK_STREAM)
        srv.setsockopt(socketmod.SOL_SOCKET, socketmod.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        host, port = srv.getsockname()
        seen = {}

        def serve():
            try:
                conn, _ = srv.accept()
                try:
                    conn.settimeout(5)
                    seen["request"] = conn.recv(4096).decode("utf-8", "replace")
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                 b"Connection: close\r\n\r\nhi")
                finally:
                    conn.close()
            finally:
                srv.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            resp = orchestrator_mod.default_fetcher(
                f"http://example.com:{port}/path?q=1", bind_ip=host)
        finally:
            t.join(timeout=5)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, "hi")
        self.assertIn("GET /path?q=1 HTTP/1.1", seen["request"])
        self.assertIn(f"Host: example.com:{port}", seen["request"])


class TestValidatorUnits(unittest.TestCase):
    def test_replay_network_error_is_inconclusive(self):
        v = replay.replay_verdict({"url": "https://x"}, lambda u: None)
        self.assertEqual(v.event, "inconclusive")

    def test_replay_no_url_is_inconclusive(self):
        v = replay.replay_verdict({}, lambda u: Response(200))
        self.assertEqual(v.event, "inconclusive")

    def test_replay_real_failure_still_falsifies(self):
        v = replay.replay_verdict({"url": "https://x"}, lambda u: Response(500))
        self.assertEqual(v.event, "replay_fail")

    def test_dom_io_error_is_inconclusive(self):
        def broken(url):
            raise RuntimeError("browser crashed")

        v = dom.dom_verdict({"url": "https://x"}, broken)
        self.assertEqual(v.event, "inconclusive")

    def test_dom_no_url_is_inconclusive(self):
        v = dom.dom_verdict({}, lambda u: DomResult(False))
        self.assertEqual(v.event, "inconclusive")

    def test_oob_trigger_failure_is_inconclusive(self):
        def broken_trigger(finding, canary):
            raise RuntimeError("payload delivery failed")

        v = oob.oob_verdict({"url": "https://x"}, lambda: "c1", broken_trigger,
                            lambda c: False)
        self.assertEqual(v.event, "inconclusive")

    def test_oob_poll_failure_is_inconclusive(self):
        def broken_poll(canary):
            raise RuntimeError("canary service unreachable")

        v = oob.oob_verdict({"url": "https://x"}, lambda: "c1",
                            lambda f, c: None, broken_poll)
        self.assertEqual(v.event, "inconclusive")


if __name__ == "__main__":
    unittest.main(verbosity=2)
