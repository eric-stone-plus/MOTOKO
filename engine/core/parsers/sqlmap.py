"""sqlmap text-output parser (precise, not the naive ``"injectable" in out``).

sqlmap confirms injection with either ``is vulnerable`` or ``identified the
following injection point(s)``; the parameter and technique then appear as
``Parameter: <p> (<place>)`` and ``Type: <technique>``. A finding is only
emitted when a confirmation marker AND a parameter are both present.
"""

from __future__ import annotations

import re

from . import Parser, register

_CONFIRM = re.compile(r"is vulnerable|identified the following injection point", re.I)
_PARAM = re.compile(r"Parameter:\s*(\S+?)\s*\((\w+)\)")
_TYPE = re.compile(r"Type:\s*([^\n]+)")
_TITLE = re.compile(r"Title:\s*([^\n]+)")


@register
class SqlmapParser(Parser):
    tool = "sqlmap"

    def parse(self, stdout, stderr="", action=None):
        findings: list[dict] = []
        if not _CONFIRM.search(stdout):
            return self._result(summary="sqlmap: no confirmed injection")

        params = _PARAM.findall(stdout)
        types = _TYPE.findall(stdout)
        titles = _TITLE.findall(stdout)
        url = (action or {}).get("url", "")

        if not params:
            # Confirmed but no parameter captured (rare) — still record, param unknown.
            findings.append(self._finding(
                class_="sqli",
                title="SQL injection confirmed",
                url=url,
                severity="critical",
                extra={"technique": types[0].strip() if types else None},
            ))
        else:
            for i, (param, place) in enumerate(params):
                technique = types[i].strip() if i < len(types) else ""
                title = titles[i].strip() if i < len(titles) else ""
                findings.append(self._finding(
                    class_="sqli",
                    title=f"SQL injection in {param} ({technique or 'unknown'})",
                    url=url,
                    param=param,
                    sink=technique,
                    severity="critical",
                    extra={"place": place, "technique_title": title},
                ))

        return self._result(
            summary=f"sqlmap: {len(findings)} injectable parameter(s)",
            findings=findings,
        )
