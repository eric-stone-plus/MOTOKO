"""Kiterunner JSONL route observations, including redirect response chains.

The parent record owns the target, path and HTTP method; its ``responses``
array owns status codes and optional redirected URIs. Discovery proves a
route was observed, never that a vulnerability or API specification exists.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlsplit

from . import Parser, register


def _http_url(value):
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
        return False
    try:
        url = urlsplit(value)
        return url.scheme in {"http", "https"} and bool(url.hostname) and url.port != 0
    except ValueError:
        return False


def _origin(url: str):
    """(scheme, host, port) of an http(s) URL, or None — port normalized to
    the scheme default so https://h and https://h:443 compare equal."""
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return (parts.scheme, parts.hostname.lower(), port)
    except ValueError:
        return None


@register
class KiterunnerParser(Parser):
    tool = "kr"

    def parse(self, stdout, stderr="", action=None):
        assets, dead, seen = [], [], set()
        for number, line in enumerate((stdout or "").splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                dead.append(f"line {number}: invalid JSON")
                continue
            if not isinstance(record, dict):
                dead.append(f"line {number}: expected route object")
                continue
            target, path = record.get("target"), record.get("path")
            method, responses = record.get("method"), record.get("responses")
            if (not _http_url(target) or not isinstance(path, str)
                    or not path.startswith("/") or not isinstance(method, str)
                    or not method.isalpha() or not isinstance(responses, list) or not responses):
                dead.append(f"line {number}: invalid route fields")
                continue
            # Kiterunner appends the route to its target (which may already
            # carry a base path), then follows response URIs with URL rules.
            value = target.rstrip("/") + "/" + path.lstrip("/")
            for response in responses:
                if not isinstance(response, dict):
                    dead.append(f"line {number}: invalid response object")
                    continue
                status, uri = response.get("sc"), response.get("uri", "")
                if (isinstance(status, bool) or not isinstance(status, int)
                        or not 100 <= status <= 599 or not isinstance(uri, str)):
                    dead.append(f"line {number}: invalid response fields")
                    continue
                # A redirect Location is target-controlled: following an
                # absolute or scheme-relative URI cross-origin would mint an
                # out-of-scope asset into the inventory frontier.
                if uri:
                    joined = urljoin(value, uri)
                    if _origin(joined) != _origin(value):
                        dead.append(f"line {number}: cross-origin redirect "
                                    f"refused ({uri[:120]})")
                        continue
                    value = joined
                if not _http_url(value):
                    dead.append(f"line {number}: invalid response URL")
                    continue
                key = (value, method, status)
                if key in seen:
                    continue
                seen.add(key)
                assets.append(self._asset(type_="url", value=value,
                    extra={"status_code": status, "method": method, "route": path}))
        return self._result(f"kr: {len(assets)} routes, {len(dead)} unparseable",
                            assets=assets, dead_letter=dead)
