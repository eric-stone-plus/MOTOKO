"""dalfox output parser — XSS PoC lines.

dalfox prints confirmed payloads as ``[POC][<flags>][<method>] <url>``. Only
``[POC]`` lines are findings (dalfox ships a PoC it already triggered, hence
the elevated prior handled by confidence.SOURCE_PRIOR).
"""

from __future__ import annotations

import re

from . import Parser, register

_POC = re.compile(r"\[POC\](?:\[[^\]]*\])*\s+(\S+)")


@register
class DalfoxParser(Parser):
    tool = "dalfox"

    def parse(self, stdout, stderr="", action=None):
        findings: list[dict] = []
        seen: set[str] = set()
        for line in stdout.splitlines():
            m = _POC.search(line)
            if not m:
                continue
            url = m.group(1)
            if url in seen:
                continue
            seen.add(url)
            findings.append(self._finding(
                class_="xss.reflected",
                title=f"Reflected XSS via dalfox",
                url=url,
                severity="medium",
            ))
        return self._result(
            summary=f"dalfox: {len(findings)} PoC(s)",
            findings=findings,
        )
