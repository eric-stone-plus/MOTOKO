"""Log-odds confidence model (kimi review: additive, auditable, per-signal).

Unlike qwen's linear weighting (which used status to compute confidence and
confidence to change status — a cycle), this is a source prior + additive
log-odds signal model. Every transition is a numeric, explainable delta.
"""

from __future__ import annotations

import math

# Source priors: probability a raw finding from this tool is a true positive.
# Seeded values; calibrate from engagement history (see rules/learned_noise).
SOURCE_PRIOR: dict[str, float] = {
    "nuclei": 0.45,        # has matchers but still reports "suspected"
    "dalfox": 0.60,        # ships a PoC it already triggered
    "sqlmap": 0.75,        # real echo when confirmed
    "tplmap": 0.60,
    "trufflehog": 0.85,
    "strix": 0.30,         # LLM judgement, uncalibrated hallucination rate
    "ffuf": 0.35,          # directory hit != vuln
    "httpx": 0.20,         # alive/fingerprint, not a vuln
    "whatweb": 0.90,       # fingerprint accuracy
    "nmap": 0.90,
    "kerbrute": 0.85,
    "hydra": 0.90,
    "llm": 0.20,
    "unknown": 0.40,
}

# Signal weights in log-odds space (logit deltas). Deterministic constants.
SIGNAL_WEIGHTS: dict[str, float] = {
    "replay_ok": +0.5,              # same signal re-observed on replay
    "second_tool_hit": +0.4,        # independent tool hit same dedup key
    "dom_confirmed": +1.0,          # Playwright confirmed injection
    "oob_callback": +2.0,           # interactsh received the callback
    "credential_usable": +1.8,      # leaked cred actually logs in
    "replay_fail": -0.6,
    "oob_negative": -1.5,           # two distinct canaries, no callback
    "waf_blocked": -0.4,
    "version_mismatch": -1.0,
}

# State thresholds (kimi review: score alone cannot jump the validation gate).
VERIFIED_MIN_CONF = 0.7
EXPLOITABLE_MIN_CONF = 0.9

# Hard-evidence signal names that qualify a finding for `verified`. A high
# score WITHOUT one of these caps out at `reproduced`.
HARD_EVIDENCE_SIGNALS = frozenset({
    "oob_callback",
    "dom_confirmed",
    "credential_usable",
})


def logit(p: float) -> float:
    return math.log(p / (1.0 - p))


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def clamp(p: float, lo: float = 0.01, hi: float = 0.99) -> float:
    return max(lo, min(hi, p))


def prior_for(source: str) -> float:
    return SOURCE_PRIOR.get(source, SOURCE_PRIOR["unknown"])


def score(source: str, signals: list[str] | None = None) -> float:
    """Return confidence in [0.01, 0.99] from a source prior + signal list.

    R3 H2: each distinct signal counts exactly once (first occurrence). A
    re-observed ``replay_ok`` is the same evidence, not a fresh logit.
    """
    logit_val = logit(prior_for(source))
    seen: set[str] = set()
    for s in signals or []:
        if s in seen:
            continue
        seen.add(s)
        logit_val += SIGNAL_WEIGHTS.get(s, 0.0)
    return clamp(sigmoid(logit_val))


def has_hard_evidence(signals: list[str] | None) -> bool:
    return bool(HARD_EVIDENCE_SIGNALS & set(signals or []))
