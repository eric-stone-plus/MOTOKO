#!/usr/bin/env python3
"""Deterministic round evaluator for the audit-loop.

Implements MECHANISM.md: reward score, convergence predicate, degradation
detection, rollback decision. Pure functions over JSON input — no model
self-assessment, no side effects.

Usage:
    python3 evaluate.py --round 2 --audit audit-r2.json \
        --metrics metrics-r2.json --history state/history.json

Input schema (see MECHANISM.md §7). Output is a JSON Verdict.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --- constants (MECHANISM.md) ----------------------------------------
HARD_MAX_ROUNDS = 5
SOFT_CONVERGE = 3
DELTA_R = 10.0
EPSILON_FLOOR = 5.0
EPSILON_FRAC = 0.03
MAX_ROLLBACKS = 2
NIT_RATIO = 0.8
CHURN_FLOOR = 30
CHURN_FRAC = 0.2
VERIFY_BUDGET = 20

WEIGHTS = {
    "test_pass_rate": 30.0,
    "fix_confirmed": 25.0,
    "regression": -25.0,
    "static_delta": -10.0,
    "arch_violation": -15.0,
    "coverage_delta": 10.0,
    "open_confirmed": -5.0,
}


@dataclass
class Verdict:
    round: int
    reward: float
    converged: bool
    rollback: bool
    action: str                      # CONTINUE | ROLLBACK | STOP
    reason: str
    best_checkpoint: str | None = None
    residual_risks: list = field(default_factory=list)


# --- metric extraction ------------------------------------------------
def reward(prev: dict | None, curr: dict, findings: list[dict]) -> float:
    """Compute R_t per MECHANISM.md §3."""
    tp = curr.get("test_pass_rate", 0.0)
    fixed = _count(findings, "fix_confirmed")
    regress = curr.get("new_red_tests", 0)
    dstatic = curr.get("static_warnings", 0) - (prev or {}).get("static_warnings", 0)
    arch = curr.get("arch_violations", 0)
    dcoverage = curr.get("coverage", 0.0) - (prev or {}).get("coverage", 0.0)
    dcoverage = max(-0.05, min(0.05, dcoverage))
    open_conf = curr.get("open_confirmed", 0)

    r = (WEIGHTS["test_pass_rate"] * tp
         + WEIGHTS["fix_confirmed"] * fixed
         + WEIGHTS["regression"] * regress
         + WEIGHTS["static_delta"] * max(0.0, dstatic)
         + WEIGHTS["arch_violation"] * arch
         + WEIGHTS["coverage_delta"] * dcoverage * 100.0
         + WEIGHTS["open_confirmed"] * open_conf)
    return round(r, 2)


# --- convergence predicates ------------------------------------------
def _confirmed_new(findings: list[dict], min_sev: str = "HIGH") -> int:
    """Count verified_true findings at/above min severity, not seen before."""
    order = {"NIT": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold = order[min_sev]
    return sum(
        1 for f in findings
        if f.get("status") == "verified_true"
        and order.get(f.get("severity", "NIT"), 0) >= threshold
    )


def _nit_ratio(findings: list[dict]) -> float:
    if not findings:
        return 1.0
    nits = sum(1 for f in findings if f.get("severity") == "NIT")
    return nits / len(findings)


def _pipes_unchanged(prev: dict | None, curr: dict) -> bool:
    if prev is None:
        return False
    return (
        prev.get("test_pass_rate") == curr.get("test_pass_rate")
        and prev.get("static_warnings") == curr.get("static_warnings")
        and prev.get("static_errors") == curr.get("static_errors")
        and prev.get("coverage") == curr.get("coverage")
    )


def evaluate(round_num: int, prev: dict | None, curr: dict,
             findings: list[dict], history: list[dict],
             r1_baseline: dict | None = None) -> Verdict:
    """Produce the round Verdict (MECHANISM.md §2, §5, §6)."""
    r_cur = reward(prev, curr, findings)
    prev_reward = history[-1]["reward"] if history else 0.0
    best = max(history, key=lambda s: s["reward"], default=None)

    # --- degradation (hard first) ---
    hard_degrade = (
        curr.get("new_red_tests", 0) > 0
        or curr.get("arch_violations", 0) > (prev or {}).get("arch_violations", 0)
        or curr.get("static_errors", 0) > (prev or {}).get("static_errors", 0)
    )
    if hard_degrade:
        strikes = curr.get("_regression_strikes", 0) + 1
        if strikes >= MAX_ROLLBACKS:
            return Verdict(round_num, r_cur, False, True, "STOP",
                           "REPEATED_REGRESSION",
                           best["checkpoint"] if best else None,
                           residual_risks=_residual(findings))
        return Verdict(round_num, r_cur, False, True, "ROLLBACK",
                       "HARD_REGRESSION",
                       best["checkpoint"] if best else None)

    # --- convergence (before soft-degrade: converge wins over warn) ---
    c1 = _confirmed_new(findings, "HIGH") == 0
    if round_num >= 2 and c1:
        baseline = r1_baseline or {"confirmed_findings": 1, "churn": 1}
        c2 = _confirmed_new(findings, "MEDIUM") <= max(1, 0.25 * baseline.get("confirmed_findings", 1))
        c3 = _stagnated(history, r_cur, k=2)
        c4 = (curr.get("churn", 0) < CHURN_FLOOR
              and curr.get("churn", 0) < CHURN_FRAC * baseline.get("churn", 1))
        c5 = _nit_ratio(findings) >= NIT_RATIO
        c6 = _pipes_unchanged(prev, curr)

        if c1 and (c2 or c3 or c4) or (c1 and c5 and c6):
            return Verdict(round_num, r_cur, True, False, "STOP", "CONVERGED")

    # --- hard cap / budget ---
    if round_num >= HARD_MAX_ROUNDS:
        return Verdict(round_num, r_cur, False, False, "STOP", "BUDGET_EXHAUSTED",
                       best["checkpoint"] if best else None,
                       residual_risks=_residual(findings))

    # --- soft degrade: warn only, rollback next round if it fails to recover ---
    if prev is not None and r_cur < prev_reward - DELTA_R:
        return Verdict(round_num, r_cur, False, False, "CONTINUE", "SOFT_REGRESSION_WARN")

    return Verdict(round_num, r_cur, False, False, "CONTINUE", "PROGRESS")


def _stagnated(history: list[dict], r_cur: float, k: int) -> bool:
    if len(history) < k:
        return False
    eps = EPSILON_FLOOR
    if history:
        eps = max(EPSILON_FLOOR, EPSILON_FRAC * history[0]["reward"])
    recent = [s["reward"] for s in history[-k:]]
    return all(abs(r_cur - r) < eps for r in recent)


def _residual(findings: list[dict]) -> list[dict]:
    return [
        {"id": f["id"], "severity": f["severity"], "title": f.get("title", "")}
        for f in findings if f.get("status") == "verified_true"
    ]


def _count(findings: list[dict], status: str) -> int:
    return sum(1 for f in findings if f.get("status") == status)


# --- CLI --------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="evaluate.py", description="audit-loop round evaluator")
    p.add_argument("--round", type=int, required=True)
    p.add_argument("--audit", required=True, help="JSON list of findings (this round)")
    p.add_argument("--metrics", required=True, help="JSON metrics for this round")
    p.add_argument("--history", required=True, help="JSON list of prior round states")
    p.add_argument("--r1-baseline", help="JSON {confirmed_findings, churn} from round 1")
    args = p.parse_args(argv)

    findings = json.loads(Path(args.audit).read_text())
    curr = json.loads(Path(args.metrics).read_text())
    history = json.loads(Path(args.history).read_text())
    baseline = json.loads(Path(args.r1_baseline).read_text()) if args.r1_baseline else None
    prev = history[-1]["metrics"] if history else None

    v = evaluate(args.round, prev, curr, findings, history, baseline)
    print(json.dumps(v.__dict__, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
