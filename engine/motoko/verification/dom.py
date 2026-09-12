"""DOM validator — headless-browser confirmation of client-side injection.

Injected IO: ``browser(url) -> DomResult``. The orchestrator backs this with
Playwright + chromium; the unit test backs it with a stub. A positive DOM
confirmation is hard evidence (promotes directly to ``verified``).

F26/F27: a browser crash / missing backend / missing URL is ``inconclusive``
(no-op) — only a page that loaded and showed no injection falsifies.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import Verdict


@dataclass
class DomResult:
    injected: bool
    alerts: list[str] = field(default_factory=list)
    detail: str = ""


def dom_verdict(finding: dict, browser) -> Verdict:
    url = finding.get("url")
    if not url:
        # F27
        return Verdict("inconclusive", "no url to load")

    try:
        result = browser(url)
    except Exception as e:
        # F26: browser crash is infrastructure, not evidence.
        return Verdict("inconclusive", f"browser error: {e}")

    if result is None:
        return Verdict("inconclusive", "browser returned nothing")

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

