"OOB validator — interactsh-style callback confirmation.\n\nInjected IO:\n* ``issue_canary() -> str``        unique canary token/URL\n* ``trigger(finding, canary)``     send the payload pointing at the canary\n* ``poll_callback(canary) -> bool`` did the canary receive a callback?\n* ``interactions(canary) -> [dict]`` OPTIONAL. The rows behind a positive poll,\n  used only to record WHICH protocol answered — see ``_protocols``.\n\nNote: this validator does not itself require a URL — a callback can arrive\nfor payloads delivered by another component. The orchestrator's guard is the\ngate; see ``Orchestrator._run_validator``.\n"

from __future__ import annotations

import time

from . import IO_ERROR, Verdict

# Seconds to wait for a callback when nothing else says. A canary manager
# carries its own window (``poll_window_s``); this is the fallback for a
# caller that passes a bare callable — a lambda or ``functools.partial`` has no
# ``__self__``, so reading the window off the callback silently degraded such a
# caller to ONE immediate poll (a real negative reported before the canary
# could answer). The window is now explicit; this constant only fills the gap.
DEFAULT_POLL_WINDOW_S = 6.0


def _inconclusive(detail: str, reason: str = IO_ERROR) -> Verdict:
    return Verdict("inconclusive", detail, reason=reason)


def _protocols(interactions, canary: str) -> list[str]:
    """The protocols that answered a canary, or ``["unknown"]``.

    A DNS interaction is weaker evidence than an HTTP one: any resolver on the
    path can produce a DNS hit, while an HTTP fetch means the target's own
    egress reached the canary server. Collapsing both into the boolean
    ``poll_callback`` returns throws that difference away, so the rows are read
    here when the manager offers them.

    Optional and defensive on purpose — a manager that only offers the boolean
    still verifies, and enriching evidence must never be able to change or fail
    a verdict.
    """
    if interactions is None:
        return ["unknown"]
    try:
        rows = interactions(canary) or []
    except Exception:      # noqa: BLE001 - enrichment is never fatal
        return ["unknown"]
    protos = sorted({str(r.get("protocol") or "unknown")
                     for r in rows if isinstance(r, dict)})
    return protos or ["unknown"]


def _poll_window(poll_callback, poll_window: float | None) -> float:
    """Seconds to wait for a callback. Explicit wins; then the MANAGER's own
    window (a bound method's ``__self__.poll_window_s``); then the module
    default — so a lambda/partial no longer degrades to a single immediate
    poll while a manager that carries its own window keeps it."""
    if poll_window is not None:
        try:
            return max(0.0, float(poll_window))
        except (TypeError, ValueError):
            return DEFAULT_POLL_WINDOW_S
    owner = getattr(poll_callback, "__self__", None)
    own = getattr(owner, "poll_window_s", None)
    if own is not None:
        try:
            return max(0.0, float(own))
        except (TypeError, ValueError):
            return DEFAULT_POLL_WINDOW_S
    return DEFAULT_POLL_WINDOW_S


def _poll(poll_callback, canary: str, window: float) -> bool:
    deadline = time.monotonic() + max(0.0, window)
    while True:
        if poll_callback(canary):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(min(0.25, deadline - time.monotonic()))


def oob_verdict(finding: dict, issue_canary, trigger, poll_callback,
                interactions=None, poll_window: float | None = None) -> Verdict:
    window = _poll_window(poll_callback, poll_window)
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
        got_callback = _poll(poll_callback, c1, window)
    except Exception as e:
        return _inconclusive(f"canary poll failed: {e}")
    if got_callback:
        return Verdict(
            "oob_callback",
            f"canary {c1} received callback",
            signals=["oob_callback"],
            evidence={"canary": c1,
                      "protocols": _protocols(interactions, c1)},
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
        got_callback = _poll(poll_callback, c2, window)
    except Exception as e:
        return _inconclusive(f"canary poll failed: {e}")
    if got_callback:
        return Verdict(
            "oob_callback",
            f"canary {c2} received callback",
            signals=["oob_callback"],
            evidence={"canary": c2,
                      "protocols": _protocols(interactions, c2)},
        )

    return Verdict(
        "oob_negative",
        f"two distinct canaries ({c1}, {c2}) received no callback",
        signals=["oob_negative"],
        evidence={"canaries": [c1, c2]},
    )
