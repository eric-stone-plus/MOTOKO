'Replay validator — re-issue the finding\'s request, judge reproducibility.\n\nThe IO is injected as ``fetcher(url, bind_ip=None) -> Response | None``.\nReproducibility is judged against optional ``finding["verify"]`` expectations\n(status / body marker); absent those, a reachable server (status < 500) is a\nweak replay confirmation — enough for triaged -> reproduced, never for\nverified.'

from __future__ import annotations

from dataclasses import dataclass

from . import IO_ERROR, NO_TARGET, Verdict


@dataclass
class Response:
    status: int
    body: str = ""
    headers: dict | None = None


def replay_verdict(finding: dict, fetcher, *, bind_ip: str | None = None) -> Verdict:
    url = finding.get("url")
    if not url:
        return Verdict("inconclusive", "no url to replay", reason=NO_TARGET)

    try:
        if bind_ip is None:
            resp = fetcher(url)
        else:
            # pinned path: connect to the address the guard cleared.
            resp = fetcher(url, bind_ip=bind_ip)
    except Exception as e:  # network error / timeout / wire failure
        return Verdict("inconclusive", f"fetch failed: {e}", reason=IO_ERROR)

    if resp is None:
        # "nothing returned" is the built-in fetcher's fail-closed refusal as
        # well as a transport death; the orchestrator relabels this to
        # EGRESS_POLICY when it knows the deployment has not asserted an
        # anonymous egress, so the two never share a strike budget.
        return Verdict("inconclusive", "fetch returned nothing",
                       reason=IO_ERROR)

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
