"""arjun output parser — hidden parameter discovery (R6-2).

arjun text output shapes (v2.2.7, real captures from a deep-dive wave obs/):

* confirmed discovery — must enter the graph::

      [+] Parameters discovered: renderData, callback

* NO discovery — a legitimate empty result, NOT a dead letter::

      No parameters were discovered.

* ``[+] Extracted 1 parameter from response for testing: renderData`` — this
  is arjun *preparing* to brute the parameter, NOT a confirmed discovery.
  Treating it as confirmed was the R6-2 false-positive trap grok flagged.

* ``-oJ`` writes ``{"<url>": ["param", ...]}``.

Confirmed params land as findings ``class=info_disclosure.hidden_param``
(one per param, dedup on url+param) so the R7 bridge rule can feed them to
sqlmap/dalfox.
"""

from __future__ import annotations

import json
import re

from . import Parser, register

_CONFIRMED = re.compile(
    r"Parameters discovered:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_NO_PARAMS = re.compile(r"No parameters were discovered", re.IGNORECASE)


@register
class ArjunParser(Parser):
    tool = "arjun"

    def parse(self, stdout, stderr="", action=None):
        findings: list[dict] = []
        dead: list[str] = []
        url = (action or {}).get("url") or ""
        text = (stdout or "").strip()

        if text.startswith("{"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict):
                found_any = False
                for key, params in data.items():
                    if isinstance(key, str) and key.startswith("http"):
                        url = key
                    if isinstance(params, list):
                        for p in params:
                            if isinstance(p, str) and p.strip():
                                found_any = True
                                findings.append(self._hidden_param(url, p.strip()))
                if found_any:
                    return self._result(
                        summary=f"arjun: {len(findings)} hidden params",
                        findings=findings)
                return self._result(summary="arjun: no parameters discovered")

        if _NO_PARAMS.search(text) and not _CONFIRMED.search(text):
            return self._result(summary="arjun: no parameters discovered")

        m = _CONFIRMED.search(text)
        if m:
            for p in re.split(r"[,\s]+", m.group(1).strip()):
                if p:
                    findings.append(self._hidden_param(url, p))
            return self._result(
                summary=f"arjun: {len(findings)} hidden params",
                findings=findings)

        dead.append(text[:2000])
        return self._result(summary="arjun: unparseable output",
                            dead_letter=dead)

    def _hidden_param(self, url: str, param: str) -> dict:
        return self._finding(
            class_="info_disclosure.hidden_param",
            title=f"Hidden parameter discovered: {param}",
            url=url,
            param=param,
            severity="info",
        )
