"""Deterministic validators — the only code allowed to promote a finding.

Validators are pure judgement logic over an injected IO function (fetcher,
browser, canary manager), so they are unit-testable without live targets.
The orchestrator supplies the real IO; an LLM supplies nothing here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Reason codes. Only IO_ERROR describes the target's behaviour; every other
# code describes the harness, and a harness limitation must never be allowed
# to consume a strike or terminate a finding.
DECIDED = "decided"                    # a real verdict, not inconclusive
NO_TARGET = "no_target"
MISSING_BACKEND = "missing_backend"    # no browser / canary / validator wired
EGRESS_POLICY = "egress_policy"        # replay refused: no asserted anonymous egress
UNPINNED = "unpinned"                  # guard cleared without a bind_ip (rebinding)
SCOPE_BLOCKED = "scope_blocked"
NO_VALIDATOR = "no_validator"          # class routed to an unimplemented validator
IO_ERROR = "io_error"                  # transport failure on a real attempt
IO_EXHAUSTED = "io_exhausted"          # IO_ERROR repeated past the retry budget

STRIKE_REASONS = frozenset({IO_ERROR})

# Codes a report can act on: each names a backend or a config assertion whose
# absence is why findings are unverified.
BLOCKING_REASONS = frozenset({
    MISSING_BACKEND, EGRESS_POLICY, UNPINNED, NO_VALIDATOR, IO_EXHAUSTED,
})


@dataclass
class Verdict:
    "A validator's deterministic conclusion, mapped onto state-machine events."

    event: str                      # replay_ok / oob_callback / dom_confirmed / ...
    detail: str
    signals: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    reason: str = DECIDED


# Which validator a finding class routes to (class prefix -> validator name).
_CLASS_VALIDATOR: list[tuple[str, str]] = [
    ("ssrf", "oob"),
    ("ssti", "oob"),
    ("rce", "oob"),
    ("xxe", "oob"),
    ("lfi", "oob"),
    ("deserialization", "oob"),
    ("xss", "dom"),
    ("open_redirect", "replay"),
    ("idor", "replay"),
    ("auth", "replay"),
    ("info_disclosure", "replay"),
    ("sqli", "replay"),
]


def pick_validator(finding: dict) -> str:
    """Route a finding to a validator name based on its class."""
    c = finding.get("class", "")
    for prefix, name in _CLASS_VALIDATOR:
        if c.startswith(prefix):
            return name
    return "replay"
