'DOM validator — headless-browser confirmation of client-side injection.'

from __future__ import annotations

from dataclasses import dataclass, field

from . import IO_ERROR, NO_TARGET, Verdict


@dataclass
class DomResult:
    injected: bool
    alerts: list[str] = field(default_factory=list)
    detail: str = ""
    #: True only when the document reached ``readyState === 'complete'``.
    #: A backend that cannot know (a stub, a future CDP-free implementation)
    #: leaves it False — an unknown is never evidence of a clean page, so
    #: ``injected=False, loaded=False`` is inconclusive, not a refutation.
    loaded: bool = False


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

    if not result.loaded:
        # The page never finished loading, so "no injection" is not an
        # observation — it is the ABSENCE of one. Inconclusive (no strike
        # beyond the IO retry budget), never the terminal replay_fail.
        return Verdict(
            "inconclusive",
            "page did not finish loading; no injection observed is not evidence",
            reason=IO_ERROR,
            evidence={"detail": result.detail},
        )

    return Verdict(
        "replay_fail",
        "no injection observed in DOM",
        signals=["replay_fail"],
        evidence={"detail": result.detail},
    )
