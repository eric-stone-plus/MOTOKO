'curl output parser — robots.txt mode + generic passthrough.'

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
