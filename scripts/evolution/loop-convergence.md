# Loop Convergence Mechanism

MOTOKO's feedback loop is a bounded process, not an open-ended
"audit → fix → re-audit" token burn. This document defines the convergence
rules the operator shell enforces on every loop run.

## State machine

```
AUDIT ──► ADJUDGE ──► LAND ──► EVALUATE ──┬─► CONVERGE (stop)
   ▲                                      ├─► ROLLBACK (re-anchor at argmax R)
   └──────────── next round ◄─────────────┴─► CONTINUE
```

| Role | Who | Duty | Boundary |
|---|---|---|---|
| AUDIT | N independent models in parallel | read the same bundle, report defects | report only — no truth authority |
| ADJUDGE | one model | dedupe, merge, schedule | **no truth authority — editor only** |
| LAND | the executing agent | apply the adjudicated fix list + tests | fixes must be independently verified |
| EVALUATE | deterministic code | reward score, convergence predicate, rollback | **the only authority on "enough"** |

## Core disciplines

Violating any of these voids the loop:

1. **Unverified findings do not count.** Every finding must land in one of:
   a red→green regression test, a static-tool warning, or a minimal PoC
   run. Model self-reports are not evidence.
2. **Truth and convergence belong to machine evidence, never to a model.**
   The adjudicator deduplicates and schedules; it does not decide what is
   true or when to stop.
3. **Rollback anchors at the historical best (argmax R), not the previous
   round.** Worst case is clamped at "best so far + a residual-risk list".
4. **Budget exhaustion is not convergence.** Running out of budget stops
   the loop with an explicit NOT_CONVERGED verdict and a residual list —
   never a silent "looks clean".

## Round bounds

- **Soft convergence: round 3.** Most effective iteration is done by the
  end of round 3 (defect-discovery follows geometric decay; correlated
  auditors make marginal returns fall faster).
- **Hard ceiling: round 5.** Never exceed 5 rounds; on exhaustion, roll
  back to the best checkpoint and emit NOT_CONVERGED.
- The stop predicate is **verified finding throughput**, not the round
  number: stop when independently-confirmed new findings of severity
  ≥MEDIUM are zero AND the metric delta is below ε for that round. Round
  count is only a backstop.

## Reward signal

`R_t` is a weighted sum of tool-produced metrics only: test pass-rate
delta, confirmed bugs fixed, regressions introduced (negative weight),
static-analysis warning delta, and architecture-violation count delta.
No model self-assessment enters the reward.

## Degradation and rollback

A hard degradation (new red tests, or an architecture-violation count
increase) triggers ROLLBACK to the checkpoint with the highest historical
reward. Two consecutive degradations trigger STOP. Checkpoints are the
LAND commits of each round.

## Provenance

Abstracted from a production multi-model audit loop (two independent
auditor models in parallel, one adjudicator, one executor) that ran
multiple full convergence cycles against a real orchestration engine,
including a round where a fix was itself rejected by the next audit round
and re-landed under an adjudicated micro-patch. The evaluator is pure
functions over JSON metrics; no vendor or model names are load-bearing.
