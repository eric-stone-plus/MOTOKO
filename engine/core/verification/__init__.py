"""Deterministic validators — the only code allowed to promote a finding.

Validators are pure judgement logic over an injected IO function (fetcher,
browser, canary manager), so they are unit-testable without live targets.
The orchestrator supplies the real IO; an LLM supplies nothing here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Verdict:
    """A validator's deterministic conclusion, mapped onto state-machine events."""

    event: str                      # replay_ok / oob_callback / dom_confirmed / ...
    detail: str
    signals: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


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
