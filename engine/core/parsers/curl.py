"""curl output parser — robots.txt mode + generic passthrough.

curl has no structured output, so this parser dispatches on the action's
URL (F13 context): a fetch of ``<base>/robots.txt`` is parsed as robots
(opsec.parse_robots) and stamps the base asset with the OPSEC facts the
burst rules gate on (``robots_host`` / ``canary_paths`` / ``crawl_delay``).
Any other curl invocation has no stable shape — the body goes to the
dead letter intact (audit trail, never silently dropped).
"""

from __future__ import annotations

from urllib.parse import urlparse

from .. import opsec
from . import Parser, register


@register
class CurlParser(Parser):
    tool = "curl"

    def parse(self, stdout, stderr="", action=None):
        url = str((action or {}).get("url") or "")
        if url.rstrip("/").lower().endswith("/robots.txt"):
            return self._robots_result(stdout, url)
        lines = stdout.splitlines() if stdout else []
        return self._result(
            summary=(f"curl: {len(lines)} lines (no structured parser for "
                     f"this target shape)"),
            dead_letter=[stdout[:2000]] if stdout else [],
        )

    def _robots_result(self, body: str, url: str):
        paths, delay = opsec.parse_robots(body)
        parts = urlparse(url)
        base = f"{parts.scheme}://{parts.netloc}"
        host = (parts.hostname or "").lower()
        canary_shaped = [p for p in paths if opsec.canary_hit(p)]
        # round-6 audit: an HTML body is NOT a robots answer — it is a 404
        # page or a WAF block page, and treating it as "probed, no traps"
        # would open the burst gate on an UNKNOWN surface. Only non-HTML
        # bodies stamp the robots facts; HTML keeps the gate closed (the
        # ffuf host_no_2xx alternative covers walled hosts).
        if body.lstrip().lower().startswith("<"):
            return self._result(
                summary=("curl robots.txt: HTML body (404/block page) — "
                         "robots state UNKNOWN, burst gate stays closed"),
                assets=[])
        asset = self._asset(type_="url", value=base, extra={
            "robots_host": host,
            "canary_paths": paths[:64],
            "crawl_delay": delay,
        })
        return self._result(
            summary=(f"curl robots.txt: {len(paths)} disallow, "
                     f"{len(canary_shaped)} canary-shaped, "
                     f"crawl-delay={delay}"),
            assets=[asset],
        )
