"OOB validator — interactsh-style callback confirmation.\n\nInjected IO:\n* ``issue_canary() -> str``        unique canary token/URL\n* ``trigger(finding, canary)``     send the payload pointing at the canary\n* ``poll_callback(canary) -> bool`` did the canary receive a callback?\n\nNote: this validator does not itself require a URL — a callback can arrive\nfor payloads delivered by another component. The orchestrator's guard is the\ngate; see ``Orchestrator._run_validator``.\n"

from __future__ import annotations

from . import IO_ERROR, Verdict


def _inconclusive(detail: str, reason: str = IO_ERROR) -> Verdict:
    return Verdict("inconclusive", detail, reason=reason)


def oob_verdict(finding: dict, issue_canary, trigger, poll_callback) -> Verdict:
    # first canary
    try:
        c1 = issue_canary()
    except Exception as e:
        return _inconclusive(f"canary manager unavailable: {e}")
    try:
        trigger(finding, c1)
    except Exception as e:
        return _inconclusive(f"trigger failed: {e}")
    try:
        got_callback = poll_callback(c1)
    except Exception as e:
        return _inconclusive(f"canary poll failed: {e}")
    if got_callback:
        return Verdict(
            "oob_callback",
            f"canary {c1} received callback",
            signals=["oob_callback"],
            evidence={"canary": c1, "protocols": ["unknown"]},
        )

    # second, distinct canary
    try:
        c2 = issue_canary()
    except Exception as e:
        return _inconclusive(f"canary manager unavailable: {e}")
    if c2 == c1:
        # An infra anomaly cannot be read as a negative.
        return _inconclusive("canary manager returned a duplicate token")
    try:
        trigger(finding, c2)
    except Exception as e:
        return _inconclusive(f"trigger failed: {e}")
    try:
        got_callback = poll_callback(c2)
    except Exception as e:
        return _inconclusive(f"canary poll failed: {e}")
    if got_callback:
        return Verdict(
            "oob_callback",
            f"canary {c2} received callback",
            signals=["oob_callback"],
            evidence={"canary": c2},
        )

    return Verdict(
        "oob_negative",
        f"two distinct canaries ({c1}, {c2}) received no callback",
        signals=["oob_negative"],
        evidence={"canaries": [c1, c2]},
    )
