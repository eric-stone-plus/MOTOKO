"""Tests for the audit-loop evaluator.

Run:  python3 test_evaluate.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko.loop_evaluate import evaluate, reward  # noqa: E402


def m(**kw) -> dict:
    base = {
        "test_pass_rate": 1.0, "new_red_tests": 0, "static_warnings": 0,
        "static_errors": 0, "arch_violations": 0, "coverage": 0.9,
        "open_confirmed": 0, "churn": 0,
    }
    base.update(kw)
    return base


class TestReward(unittest.TestCase):
    def test_fix_worth_25(self):
        r = reward(m(), m(), [{"severity": "HIGH", "status": "fix_confirmed"}])
        self.assertGreaterEqual(r, 25.0)

    def test_regression_lowers_reward(self):
        # G = -25 per regression (regression's real disposal is D2 zero-tolerance
        # rollback; the reward term is a supplemental signal, not the trigger).
        r_clean = reward(m(), m(), [])
        r_reg = reward(m(), m(new_red_tests=1), [])
        self.assertAlmostEqual(r_clean - r_reg, 25.0, places=1)


class TestConvergence(unittest.TestCase):
    def test_r1_never_converges(self):
        v = evaluate(1, None, m(), [], [], None)
        self.assertFalse(v.converged)

    def test_high_finding_blocks_convergence(self):
        findings = [{"id": "f1", "severity": "HIGH", "status": "verified_true"}]
        v = evaluate(2, m(), m(), findings, [{"round": 1, "reward": 50, "checkpoint": "c"}],
                     {"confirmed_findings": 6, "churn": 500})
        self.assertFalse(v.converged)

    def test_converges_when_clean_and_decayed(self):
        # no high/medium confirmed findings + churn decayed -> converge
        findings = [{"id": "f1", "severity": "NIT", "status": "reported"}]
        history = [{"round": 1, "reward": 50, "checkpoint": "c"}]
        v = evaluate(3, m(), m(churn=5), findings, history,
                     {"confirmed_findings": 6, "churn": 500})
        self.assertTrue(v.converged)


class TestRollback(unittest.TestCase):
    def test_new_red_test_rolls_back(self):
        history = [{"round": 1, "reward": 50, "checkpoint": "c1"}]
        v = evaluate(2, m(), m(new_red_tests=1), [], history)
        self.assertTrue(v.rollback)
        self.assertEqual(v.action, "ROLLBACK")
        self.assertEqual(v.best_checkpoint, "c1")

    def test_repeated_regression_stops(self):
        history = [{"round": 1, "reward": 50, "checkpoint": "c1"}]
        curr = m(new_red_tests=1, _regression_strikes=1)
        v = evaluate(2, m(), curr, [], history)
        self.assertEqual(v.action, "STOP")
        self.assertEqual(v.reason, "REPEATED_REGRESSION")


class TestHardCap(unittest.TestCase):
    def test_hard_cap(self):
        # a persistent HIGH finding blocks convergence, forcing the round-5 fuse
        findings = [{"id": "f1", "severity": "HIGH", "status": "verified_true"}]
        history = [{"round": i, "reward": 50, "checkpoint": f"c{i}"} for i in range(1, 5)]
        v = evaluate(5, m(), m(), findings, history, {"confirmed_findings": 6, "churn": 500})
        self.assertEqual(v.action, "STOP")
        self.assertEqual(v.reason, "BUDGET_EXHAUSTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
