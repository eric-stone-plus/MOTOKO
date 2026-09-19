'DOM validator — headless-browser confirmation of client-side injection.\n\nInjected IO: ``browser(url) -> DomResult``. The orchestrator backs this with\nPlaywright + chromium; the unit test backs it with a stub. A positive DOM\nconfirmation is hard evidence (promotes directly to ``verified``).'

from __future__ import annotations

from dataclasses import dataclass, field

from . import IO_ERROR, NO_TARGET, Verdict


@dataclass
class DomResult:
    injected: bool
    alerts: list[str] = field(default_factory=list)
    detail: str = ""


def dom_verdict(finding: dict, browser) -> Verdict:
    url = finding.get("url")
    if not url:
        return Verdict("inconclusive", "no url to load", reason=NO_TARGET)

    try:
        result = browser(url)
    except Exception as e:
        return Verdict("inconclusive", f"browser error: {e}",
                       reason=IO_ERROR)

    if result is None:
        return Verdict("inconclusive", "browser returned nothing",
                       reason=IO_ERROR)

    if result.injected:
        return Verdict(
            "dom_confirmed",
            f"injection observed: {result.detail or result.alerts}",
            signals=["dom_confirmed"],
            evidence={"alerts": result.alerts, "detail": result.detail},
        )

    return Verdict(
        "replay_fail",
        "no injection observed in DOM",
        signals=["replay_fail"],
        evidence={"detail": result.detail},
    )
