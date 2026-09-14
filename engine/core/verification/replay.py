"""Replay validator — re-issue the finding's request, judge reproducibility.

The IO is injected as ``fetcher(url, bind_ip=None) -> Response | None``.
Reproducibility is judged against optional ``finding["verify"]`` expectations
(status / body marker); absent those, a reachable server (status < 500) is a
weak replay confirmation — enough for triaged -> reproduced, never for
verified.

R3 H3: when the caller passes the scope guard's ``bind_ip``, the fetcher MUST
connect to that address (the one the guard actually checked) instead of
re-resolving the hostname. Re-resolution is the DNS rebinding window; a
fetcher that cannot pin must refuse (return None) rather than connect.

F26/F27: an IO failure (network error, timeout, nothing returned) or a
finding without a URL yields ``inconclusive`` — a no-op on the state machine.
Only a real response that fails the expectation falsifies the finding.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import Verdict


@dataclass
class Response:
    status: int
    body: str = ""
    headers: dict | None = None


def replay_verdict(finding: dict, fetcher, *, bind_ip: str | None = None) -> Verdict:
    url = finding.get("url")
    if not url:
        # F27: no url is not evidence of absence.
        return Verdict("inconclusive", "no url to replay")

    try:
        if bind_ip is None:
            resp = fetcher(url)
        else:
            # pinned path: connect to the address the guard cleared.
            resp = fetcher(url, bind_ip=bind_ip)
    except Exception as e:  # network error / timeout / wire failure
        # F26: infrastructure failure must never be read as falsification.
        return Verdict("inconclusive", f"fetch failed: {e}")

    if resp is None:
        return Verdict("inconclusive", "fetch returned nothing")

    verify = finding.get("verify") or {}
    exp_status = verify.get("status")
    exp_contains = verify.get("body_contains")

    if exp_status is not None and resp.status != exp_status:
        return Verdict(
            "replay_fail",
            f"status {resp.status} != expected {exp_status}",
            signals=["replay_fail"],
        )
    if exp_contains and exp_contains not in resp.body:
        return Verdict(
            "replay_fail",
            "response body missing expected marker",
            signals=["replay_fail"],
        )
    if resp.status >= 500:
        return Verdict("replay_fail", f"server error {resp.status}", signals=["replay_fail"])

    return Verdict(
        "replay_ok",
        f"replayed {url}, status {resp.status}",
        signals=["replay_ok"],
        evidence={"status": resp.status, "body_len": len(resp.body)},
    )
