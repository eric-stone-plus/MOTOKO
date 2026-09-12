"""katana output parser — crawled endpoints.

``katana -u <url> -silent`` prints one URL per line. URLs carrying a query
string are emitted as assets with ``has_param`` set, which feeds the
parameter-mining and injection chains (R-TECH-PARAM-001 / R-VULN-*).
"""

from __future__ import annotations

from . import Parser, register


_STATIC_SUFFIXES = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip", ".mp4", ".webp",
    ".avif", ".webm", ".mp3", ".xml", ".txt",
)

# R6-3: resource suffixes whose query strings are version noise, never
# business parameters. arjun wasted 17/30 ACT slots on *.js?v= URLs in
# A deep-dive production wave.
_RESOURCE_SUFFIXES = (".js", ".css")

# R6-3: pure cache-buster query keys — an URL whose query contains ONLY
# these keys carries no business parameter surface, and the query can be
# stripped to converge asset values (app.js?v=1 vs app.js?v=2 = one asset).
_CACHE_BUSTER_KEYS = {
    "v", "ver", "version", "_", "t", "ts", "cb", "hash", "rev", "timestamp",
}


def _is_static_asset(url: str) -> bool:
    path = url.split("?", 1)[0].lower()
    return path.endswith(_STATIC_SUFFIXES)


def _is_resource(url: str) -> bool:
    path = url.split("?", 1)[0].lower()
    return path.endswith(_RESOURCE_SUFFIXES)


def _normalize_cache_busters(url: str) -> tuple[str, bool]:
    """Return (canonical_url, has_business_param).

    A query made only of cache-buster keys is stripped (asset convergence);
    any other key keeps the URL untouched and marks a real parameter surface.
    Resource suffixes (.js/.css) force has_business_param=False.
    """
    if "?" not in url:
        return url, False
    base, query = url.split("?", 1)
    keys = []
    for pair in query.split("&"):
        keys.append(pair.split("=", 1)[0] if pair else "")
    if _is_resource(url):
        return base, False          # version noise on resources
    if keys and all(k in _CACHE_BUSTER_KEYS for k in keys):
        return base, False          # pure cache-buster -> converge to base
    return url, True


@register
class KatanaParser(Parser):
    tool = "katana"

    def parse(self, stdout, stderr="", action=None):
        assets: list[dict] = []
        dead: list[str] = []
        for raw in (stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            if not line.startswith(("http://", "https://")):
                dead.append(line[:500])
                continue
            # Static resources are crawl noise: they are recorded as dead
            # letter context instead of minting a frontier asset + a
            # bootstrap hypothesis each (one wave exploded to 1884 hyps).
            if _is_static_asset(line):
                dead.append(line[:500])
                continue
            value, has_param = _normalize_cache_busters(line)
            # R6-5: mark the host as crawled so R-CTX-CRAWL-001 fires at most
            # once per host (crawl recursion guard, grok R6-5).
            host = value.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] if "://" in value else ""
            assets.append(self._asset(
                type_="url", value=value,
                extra={"has_param": has_param, "crawled_host": host}))
        return self._result(
            summary=f"katana: {len(assets)} endpoints, {len(dead)} dead",
            assets=assets, dead_letter=dead)
