"""jsluice output parser — URLs extracted from JavaScript.

``jsluice urls`` emits JSONL records; ``-j`` selects raw JavaScript input,
not JSON output. Relative paths resolve against the scanned script URL.
Legacy URL lists remain readable; dynamic expressions remain dead letters.
"""

from __future__ import annotations

import json
from urllib.parse import urljoin, urlsplit

from . import Parser, register


@register
class JsluiceParser(Parser):
    tool = "jsluice"

    def parse(self, stdout, stderr="", action=None):
        assets: list[dict] = []
        dead: list[str] = []
        text = stdout.strip()
        base = str((action or {}).get("url") or "")
        seen: set[str] = set()
        records: list = []
        if text.startswith("["):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, list):
                records = data
            else:
                dead.append(text[:2000])
        else:
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    records.append(line.strip())
        for item in records:
            value = item.get("url") if isinstance(item, dict) else item
            if not isinstance(value, str) or "EXPR" in value or any(c.isspace() for c in value):
                dead.append(str(item)[:500])
                continue
            if not value.startswith(("http://", "https://", "/", "./", "../")):
                dead.append(str(item)[:500])
                continue
            url = urljoin(base, value)
            try:
                parsed = urlsplit(url)
                valid = parsed.scheme in ("http", "https") and bool(parsed.hostname)
            except ValueError:
                valid = False
            if not valid:
                dead.append(str(item)[:500])
            elif url not in seen:
                seen.add(url)
                assets.append(self._asset(type_="url", value=url))
        return self._result(
            summary=f"jsluice: {len(assets)} urls, {len(dead)} dead",
            assets=assets, dead_letter=dead)
