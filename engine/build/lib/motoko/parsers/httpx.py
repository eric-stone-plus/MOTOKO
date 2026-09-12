"""httpx output parser — produces ASSETS (alive URLs), not findings.

Supports ``httpx -json`` (object per line, or a JSON array) and the default
text format ``URL [status] [title] [tech1,tech2]``.
"""

from __future__ import annotations

import json

from . import Parser, register


@register
class HttpxParser(Parser):
    tool = "httpx"

    def parse(self, stdout, stderr="", action=None):
        assets: list[dict] = []
        dead: list[str] = []
        text = stdout.strip()

        if text.startswith("["):
            # JSON array form
            try:
                records = json.loads(text)
            except json.JSONDecodeError:
                records = None
            if records is not None:
                for d in records:
                    a = self._asset_from_json(d)
                    if a:
                        assets.append(a)
                return self._result(summary=f"httpx: {len(assets)} alive (json)", assets=assets)

        # JSONL form (one object per line) or text form
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    a = self._asset_from_json(json.loads(line))
                except json.JSONDecodeError:
                    dead.append(line[:500])
                    continue
                if a:
                    assets.append(a)
            else:
                a = self._asset_from_text(line)
                if a:
                    assets.append(a)
                else:
                    dead.append(line[:500])
        return self._result(
            summary=f"httpx: {len(assets)} alive, {len(dead)} unparseable",
            assets=assets,
            dead_letter=dead,
        )

    def _asset_from_json(self, d: dict) -> dict | None:
        url = d.get("url") or d.get("host") or d.get("input")
        if not url:
            return None
        return self._asset(
            type_="url",
            value=url,
            extra={
                "status_code": d.get("status_code"),
                "title": d.get("title"),
                "tech": d.get("tech") or d.get("tech_stack") or [],
                "webserver": d.get("webserver"),
            },
        )

    def _asset_from_text(self, line: str) -> dict | None:
        # https://shop.invalid [200] [Page Title] [nginx,react]
        parts = line.split()
        if not parts or "://" not in parts[0]:
            return None
        url = parts[0]
        status = None
        title = None
        tech: list[str] = []
        for tok in parts[1:]:
            if tok.startswith("[") and tok.endswith("]"):
                inner = tok[1:-1]
                if inner.isdigit():
                    status = int(inner)
                elif "," in inner:
                    tech = [t.strip() for t in inner.split(",") if t.strip()]
                else:
                    title = inner
        return self._asset(
            type_="url", value=url,
            extra={"status_code": status, "title": title, "tech": tech},
        )
