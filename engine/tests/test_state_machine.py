"""State machine + validator tests.

Run:  python3 tests/test_state_machine.py
"""

from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import confidence  # noqa: E402
from motoko import state_machine as sm  # noqa: E402
from motoko.state_machine import ForbiddenActor, InvalidTransition  # noqa: E402
from motoko.verification import dom, oob, replay  # noqa: E402
from motoko.verification.dom import DomResult  # noqa: E402
from motoko.verification.replay import Response  # noqa: E402


def finding(**kw) -> dict:
    f = {
        "id": "fnd_test", "kind": "finding", "state": "candidate",
        "class": "sqli", "url": "https://example.com/?q=1",
        "detector": "sqlmap", "signals": [], "confidence": 0.75,
    }
    f.update(kw)
    return f


class TestStateMachine(unittest.TestCase):
    def test_candidate_to_triaged(self):
        f = finding()
        sm.advance(f, "dedup_pass")
        self.assertEqual(f["state"], "triaged")

    def test_dedup_hit(self):
        f = finding()
        sm.advance(f, "dedup_hit")
        self.assertEqual(f["state"], "duplicate")

    def test_triaged_replay_ok(self):
        f = finding(state="triaged")
        sm.advance(f, "replay_ok")
        self.assertEqual(f["state"], "reproduced")
        self.assertIn("replay_ok", f["signals"])

    def test_triaged_oob_direct_verified(self):
        f = finding(state="triaged")
        f["class"] = "ssrf.basic"
        sm.advance(f, "oob_callback")
        self.assertEqual(f["state"], "verified")

    def test_verified_guard_no_hard_evidence(self):
        # A signal that was never written by a validator event cannot promote:
        # the old `extra_signals=["oob_callback"]` shortcut is gone (F05).
        f = finding(state="reproduced", signals=["oob_callback"])
        sm.advance(f, "replay_ok")
        self.assertEqual(f["state"], "reproduced")
        self.assertNotIn("verified", [f["state"]])

    def test_verified_guard_with_evidence(self):
        # Hard evidence arrives as a validator EVENT (F10 row): reproduced ->
        # verified via oob_callback.
        f = finding(state="reproduced")
        sm.advance(f, "oob_callback")
        self.assertEqual(f["state"], "verified")

    def test_verified_guard_low_confidence_caps_at_reproduced(self):
        # Hard evidence + confidence below VERIFIED_MIN_CONF stays reproduced.
        f = finding(state="triaged", detector="llm")
        sm.advance(f, "oob_callback")
        self.assertLess(confidence.score("llm", ["oob_callback"]),
                        confidence.VERIFIED_MIN_CONF)
        self.assertEqual(f["state"], "reproduced")

    def test_llm_forbidden(self):
        f = finding()
        with self.assertRaises(ForbiddenActor):
            sm.advance(f, "replay_ok", actor="llm")

    def test_invalid_transition(self):
        with self.assertRaises(InvalidTransition):
            sm.transition("candidate", "poc_success")

    def test_full_chain(self):
        # Verdict-driven end to end: no extra_signals anywhere.
        f = finding(state="triaged")
        v1 = replay.replay_verdict({"url": f["url"]}, lambda u: Response(200, "<html>"))
        sm.advance(f, v1.event, verdict=v1)                  # -> reproduced
        self.assertEqual(f["state"], "reproduced")
        v2 = oob.oob_verdict(f, lambda: "c1", lambda fd, c: None, lambda c: True)
        sm.advance(f, v2.event, verdict=v2)                  # -> verified
        self.assertEqual(f["state"], "verified")
        self.assertTrue(confidence.has_hard_evidence(f["signals"]))
        sm.advance(f, "poc_success")                         # -> exploitable
        self.assertEqual(f["state"], "exploitable")
        sm.advance(f, "impact_confirmed")                    # -> confirmed_impact
        self.assertEqual(f["state"], "confirmed_impact")

    def test_refute_universal(self):
        f = finding(state="triaged")
        sm.advance(f, "refute")
        self.assertEqual(f["state"], "false_positive")


class TestTransitionTable(unittest.TestCase):
    """F10: the union of both reviewers' missing rows, and the removal of the
    fake `verified_evidence` signal."""

    def test_new_evidence_rows(self):
        expected = {
            ("reproduced", "oob_callback"): "verified",
            ("reproduced", "dom_confirmed"): "verified",
            ("reproduced", "credential_usable"): "verified",
            ("triaged", "credential_usable"): "verified",
            # demotions once infra/replay evidence contradicts an earlier pass
            ("verified", "oob_negative"): "reproduced",
            ("verified", "replay_fail"): "reproduced",
            ("exploitable", "oob_negative"): "verified",
            ("exploitable", "replay_fail"): "verified",
        }
        for (state, event), want in expected.items():
            self.assertEqual(sm.transition(state, event), want,
                             f"({state}, {event}) table row wrong")

    def test_fake_verified_evidence_event_is_gone(self):
        with self.assertRaises(InvalidTransition):
            sm.transition("reproduced", "verified_evidence")

    def test_inconclusive_is_a_no_op_self_loop(self):
        # F26/F27: an IO failure / missing url must NOT change the state.
        self.assertEqual(sm.transition("triaged", "inconclusive"), "triaged")
        self.assertEqual(sm.transition("reproduced", "inconclusive"), "reproduced")
        f = finding(state="triaged", signals=["replay_ok"])
        sm.advance(f, "inconclusive")
        self.assertEqual(f["state"], "triaged")
        self.assertEqual(f["signals"], ["replay_ok"], "inconclusive must not log a signal")


class TestExploitableGate(unittest.TestCase):
    """F23: poc_success -> exploitable only at conf >= EXPLOITABLE_MIN_CONF."""

    def test_below_threshold_falls_back(self):
        f = finding(state="verified", detector="unknown", signals=["oob_callback"])
        lo = confidence.score("unknown", ["oob_callback"])
        self.assertLess(lo, confidence.EXPLOITABLE_MIN_CONF)
        self.assertGreaterEqual(lo, confidence.VERIFIED_MIN_CONF)
        sm.advance(f, "poc_success")
        self.assertEqual(f["state"], "verified")   # still meets verified

    def test_below_threshold_without_hard_evidence_falls_to_reproduced(self):
        f = finding(state="verified", detector="sqlmap", signals=["replay_ok"])
        self.assertLess(confidence.score("sqlmap", ["replay_ok"]),
                        confidence.EXPLOITABLE_MIN_CONF)
        sm.advance(f, "poc_success")
        self.assertEqual(f["state"], "reproduced")

    def test_at_or_above_threshold_promotes(self):
        f = finding(state="verified", detector="trufflehog", signals=["oob_callback"])
        self.assertGreaterEqual(confidence.score("trufflehog", ["oob_callback"]),
                                confidence.EXPLOITABLE_MIN_CONF)
        sm.advance(f, "poc_success")
        self.assertEqual(f["state"], "exploitable")


class TestSignalRevocation(unittest.TestCase):
    """F24: falsification events remove the positive signals they contradict."""

    def test_oob_negative_revokes_oob_callback(self):
        f = finding(state="verified", signals=["oob_callback", "replay_ok"])
        sm.advance(f, "oob_negative")
        self.assertEqual(f["state"], "reproduced")
        self.assertNotIn("oob_callback", f["signals"])
        self.assertIn("oob_negative", f["signals"])
        self.assertFalse(confidence.has_hard_evidence(f["signals"]),
                         "revoked oob_callback still counts as hard evidence")

    def test_replay_fail_revokes_replay_ok(self):
        f = finding(state="reproduced", signals=["replay_ok"])
        sm.advance(f, "replay_fail")
        self.assertEqual(f["state"], "false_positive")
        self.assertNotIn("replay_ok", f["signals"])
        self.assertIn("replay_fail", f["signals"])

    def test_revocation_is_not_append_only(self):
        # signals must shrink when a positive signal is contradicted
        f = finding(state="verified", signals=["oob_callback"])
        before = len(f["signals"])
        sm.advance(f, "oob_negative")
        self.assertLess(len(f["signals"]), before + 1)


class TestSignalDedup(unittest.TestCase):
    """R3 H2: the same evidence re-observed must not stack. ``replay_ok``
    self-loops while the orchestrator keeps re-validating reproduced rows; a
    list that grows by one logit per beat drifts the confidence score through
    the EXPLOITABLE_MIN_CONF gate ("wait a few beats")."""

    def test_second_replay_ok_changes_nothing(self):
        once = finding(state="triaged")
        sm.advance(once, "replay_ok")
        twice = finding(state="triaged")
        sm.advance(twice, "replay_ok")
        sm.advance(twice, "replay_ok")          # reproduced -> reproduced
        self.assertEqual(twice["signals"], once["signals"],
                         "a repeated replay_ok stacked in the signal log")
        self.assertEqual(twice["confidence"], once["confidence"],
                         "a repeated replay_ok stacked in the confidence score")
        self.assertEqual(twice["signals"], ["replay_ok"])

    def test_repeated_replay_ok_never_crosses_the_exploitable_gate(self):
        # kimi H2 kill chain: sqlmap prior 0.75 + n x replay_ok -> >= 0.9.
        f = finding(state="triaged")
        for _ in range(5):
            sm.advance(f, "replay_ok")
        self.assertEqual(f["signals"], ["replay_ok"])
        self.assertLess(f["confidence"], confidence.EXPLOITABLE_MIN_CONF,
                        "5 replay_ok beats drifted the score through the gate")

    def test_distinct_signals_still_accumulate(self):
        f = finding(state="triaged")
        sm.advance(f, "replay_ok")
        conf_one = f["confidence"]
        sm.advance(f, "dom_confirmed")
        self.assertEqual(len(f["signals"]), 2, "distinct signals were deduped together")
        self.assertIn("replay_ok", f["signals"])
        self.assertIn("dom_confirmed", f["signals"])
        self.assertGreater(f["confidence"], conf_one,
                           "distinct evidence no longer adds weight")

    def test_score_counts_a_signal_once(self):
        once = confidence.score("sqlmap", ["replay_ok"])
        five = confidence.score("sqlmap", ["replay_ok"] * 5)
        self.assertEqual(once, five)
        # and the order of distinct signals does not matter
        self.assertEqual(confidence.score("sqlmap", ["replay_ok", "waf_blocked"]),
                         confidence.score("sqlmap", ["waf_blocked", "replay_ok"]))


class TestNoForgedEvidence(unittest.TestCase):
    """F05: hard evidence only from validator verdicts / real events."""

    def test_advance_has_no_extra_signals_parameter(self):
        params = inspect.signature(sm.advance).parameters
        self.assertNotIn("extra_signals", params)

    def test_extra_signals_kwarg_is_rejected(self):
        f = finding(state="triaged")
        with self.assertRaises(TypeError):
            sm.advance(f, "replay_ok", extra_signals=["oob_callback"])
        self.assertEqual(f["state"], "triaged")

    def test_verdict_event_mismatch_is_rejected(self):
        f = finding(state="triaged")
        v = oob.oob_verdict(f, lambda: "c1", lambda fd, c: None, lambda c: True)
        with self.assertRaises(ValueError):
            sm.advance(f, "replay_ok", verdict=v)      # verdict says oob_callback

    def test_verdict_signals_must_be_backed_by_the_event(self):
        from motoko.verification import Verdict
        f = finding(state="triaged")
        forged = Verdict("replay_ok", "ok", signals=["replay_ok", "oob_callback"])
        with self.assertRaises(ValueError):
            sm.advance(f, "replay_ok", verdict=forged)


class TestInvalidTransitionContainment(unittest.TestCase):
    """F30: a bad event must not blow up the main loop."""

    def test_advance_safe_reports_instead_of_raising(self):
        f = finding(state="candidate")
        ok, reason = sm.advance_safe(f, "poc_success")
        self.assertFalse(ok)
        self.assertIn("no transition", reason)
        self.assertEqual(f["state"], "candidate", "failed transition mutated the finding")

    def test_advance_safe_passes_valid_events_through(self):
        f = finding(state="triaged")
        ok, reason = sm.advance_safe(f, "replay_ok")
        self.assertTrue(ok)
        self.assertEqual(reason, "")
        self.assertEqual(f["state"], "reproduced")

    def test_advance_still_raises_for_direct_callers(self):
        f = finding(state="candidate")
        with self.assertRaises(InvalidTransition):
            sm.advance(f, "poc_success")


class TestReplayValidator(unittest.TestCase):
    def test_ok(self):
        v = replay.replay_verdict({"url": "https://x"}, lambda u: Response(200, "<html>"))
        self.assertEqual(v.event, "replay_ok")

    def test_server_error(self):
        v = replay.replay_verdict({"url": "https://x"}, lambda u: Response(500))
        self.assertEqual(v.event, "replay_fail")

    def test_verify_mismatch(self):
        f = {"url": "https://x", "verify": {"body_contains": "SECRET"}}
        v = replay.replay_verdict(f, lambda u: Response(200, "nothing"))
        self.assertEqual(v.event, "replay_fail")

    def test_network_error(self):
        # F26: an IO failure is NOT falsification — it is inconclusive.
        v = replay.replay_verdict({"url": "https://x"}, lambda u: None)
        self.assertEqual(v.event, "inconclusive")


class TestOobValidator(unittest.TestCase):
    def test_callback_first(self):
        v = oob.oob_verdict({}, lambda: "c1", lambda f, c: None, lambda c: c == "c1")
        self.assertEqual(v.event, "oob_callback")

    def test_negative_two_canaries(self):
        issued = iter(["c1", "c2"])
        v = oob.oob_verdict({}, lambda: next(issued), lambda f, c: None, lambda c: False)
        self.assertEqual(v.event, "oob_negative")
        self.assertIn("c1", v.detail)
        self.assertIn("c2", v.detail)

    def test_second_callback(self):
        issued = iter(["c1", "c2"])
        v = oob.oob_verdict({}, lambda: next(issued), lambda f, c: None, lambda c: c == "c2")
        self.assertEqual(v.event, "oob_callback")


class TestDomValidator(unittest.TestCase):
    def test_confirmed(self):
        v = dom.dom_verdict({"url": "https://x"}, lambda u: DomResult(True, ["alert(1)"]))
        self.assertEqual(v.event, "dom_confirmed")

    def test_no_injection(self):
        v = dom.dom_verdict({"url": "https://x"}, lambda u: DomResult(False))
        self.assertEqual(v.event, "replay_fail")


if __name__ == "__main__":
    unittest.main(verbosity=2)
