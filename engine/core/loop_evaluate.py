#!/usr/bin/env python3
'Deterministic round evaluator for the audit-loop.'

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

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

# Finding statuses that count as CONFIRMED for convergence (c1/c2) and for
# the residual-risk list. Two different strengths of evidence live here and
# must not be conflated:
#   verified_true       — independently VERIFIED (the VERIFY beat's output;
#                         that beat is unbuilt, so nothing stamps this today)
#   consensus_confirmed — what the loop can actually produce: two or more
#                         audit LENSES agreeing. On one substrate the lenses'
#                         blind spots are correlated, so this is weaker
#                         evidence than cross-vendor agreement.
# Weaker evidence, same blocking force: if consensus stopped counting toward
# c1, renaming the status would silently make "no new confirmed HIGH" true by
# default and convergence easier — the opposite of what the rename is for.
CONFIRMED_STATUSES = frozenset({"verified_true", "consensus_confirmed"})

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
    # how many audit legs actually reported this round, so a verdict names
    # the size of the evidence base it rests on
    legs_ok: int = 0
    legs_total: int = 0


# --- metric extraction ------------------------------------------------
def reward(prev: dict | None, curr: dict, findings: list[dict]) -> float:
    ''
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
    """Count CONFIRMED findings at/above min severity, not seen before.

    Confirmed means ``CONFIRMED_STATUSES`` — independently verified OR
    cross-lens consensus. Both block convergence equally (see the constant).
    """
    order = {"NIT": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold = order[min_sev]
    return sum(
        1 for f in findings
        if f.get("status") in CONFIRMED_STATUSES
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
    ''
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
            quorum, legs_ok, legs_total = _leg_quorum(curr)
            if not quorum:
                # PARK, never converge: the lens set that "found nothing
                # new" was smaller than the one configured, so the empty
                # finding set measured the legs that failed to report, not
                # the code. Convergence-by-emptiness was reachable at
                # round>=2 with every leg dead (c1 and c2 both hold on
                # findings==[]), which is exactly the "we could not verify"
                # / "we found nothing" confusion the verdict reason exists
                # to keep apart.
                return Verdict(round_num, r_cur, False, False, "CONTINUE",
                               "LEG_QUORUM_UNMET",
                               legs_ok=legs_ok, legs_total=legs_total)
            return Verdict(round_num, r_cur, True, False, "STOP", "CONVERGED",
                           legs_ok=legs_ok, legs_total=legs_total)

    # --- hard cap / budget ---
    if round_num >= HARD_MAX_ROUNDS:
        return Verdict(round_num, r_cur, False, False, "STOP", "BUDGET_EXHAUSTED",
                       best["checkpoint"] if best else None,
                       residual_risks=_residual(findings))

    # --- soft degrade: warn only, rollback next round if it fails to recover ---
    if prev is not None and r_cur < prev_reward - DELTA_R:
        return Verdict(round_num, r_cur, False, False, "CONTINUE", "SOFT_REGRESSION_WARN")

    return Verdict(round_num, r_cur, False, False, "CONTINUE", "PROGRESS")


def _leg_quorum(curr: dict) -> tuple[bool, int, int]:
    """Whether enough audit legs reported to support a convergence claim.

    Returns ``(met, legs_ok, legs_total)``. The quorum is a strict majority
    of the configured legs: convergence asserts that the lens set found
    nothing new, and a set missing half its lenses measured the legs that
    failed to report, not the code.

    Absent telemetry is a PASS, not a failure — a caller that measured no
    legs (a history row written before this field existed, or a direct
    ``evaluate()`` call) cannot answer the gate, and inventing a zero-leg
    round would turn every such evaluation into a permanent
    LEG_QUORUM_UNMET.
    """
    total = curr.get("legs_total")
    if not isinstance(total, int) or total <= 0:
        return True, 0, 0
    ok = curr.get("legs_ok")
    ok = ok if isinstance(ok, int) and ok >= 0 else 0
    return ok >= (total // 2 + 1), ok, total


def _stagnated(history: list[dict], r_cur: float, k: int) -> bool:
    if len(history) < k:
        return False
    eps = EPSILON_FLOOR
    if history:
        eps = max(EPSILON_FLOOR, EPSILON_FRAC * history[0]["reward"])
    recent = [s["reward"] for s in history[-k:]]
    return all(abs(r_cur - r) < eps for r in recent)


def _residual(findings: list[dict]) -> list[dict]:
    # a consensus-confirmed finding belongs here at least as much as a
    # verified one: at STOP it is still an unresolved claim the loop is
    # handing back, and dropping it because no VERIFY beat ran would make
    # the residual list report less risk than the round actually carries.
    return [
        {"id": f["id"], "severity": f["severity"], "title": f.get("title", "")}
        for f in findings if f.get("status") in CONFIRMED_STATUSES
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
