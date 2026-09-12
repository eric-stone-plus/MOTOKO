"""jsluice output parser — URLs extracted from JavaScript.

``jsluice urls <target>`` prints one URL per line; ``-j`` prints a JSON
array. Both shapes land in assets (type=url); anything else goes to
dead_letter.
"""

from __future__ import annotations

import json

from . import Parser, register


@register
class JsluiceParser(Parser):
    tool = "jsluice"

    def parse(self, stdout, stderr="", action=None):
        assets: list[dict] = []
        dead: list[str] = []
        text = stdout.strip()

        if text.startswith("["):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str) and item.startswith(("http://", "https://")):
                        assets.append(self._asset(type_="url", value=item))
                    else:
                        dead.append(str(item)[:500])
                return self._result(
                    summary=f"jsluice: {len(assets)} urls",
                    assets=assets, dead_letter=dead)
            dead.append(stdout[:2000])
            return self._result(summary="jsluice: unparseable output",
                                dead_letter=dead)

        for raw in stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith(("http://", "https://")):
                assets.append(self._asset(type_="url", value=line))
            else:
                dead.append(line[:500])
        return self._result(
            summary=f"jsluice: {len(assets)} urls, {len(dead)} dead",
            assets=assets, dead_letter=dead)
