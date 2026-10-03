"""sqlmap text-output parser (precise, not the naive ``"injectable" in out``).

sqlmap confirms injection with ``is vulnerable`` or with either injection-point
header — ``identified the following injection point(s)`` on a fresh run,
``resumed the following injection point(s) from stored session`` on a re-run.
The parameter and technique then appear as ``Parameter: <p> (#N*)? (<place>)``
and ``Type: <technique>``. A confirmation marker is required; when no parameter
block matches, each technique is still recorded with the parameter unknown.
"""

from __future__ import annotations

import re

from . import Parser, register

_CONFIRM = re.compile(r"is vulnerable|the following injection point", re.I)
# Line-anchored (^…$, re.M): sqlmap url-decodes a payload before echoing it, so
# a target-shaped "Parameter: evil (POST)" inside a Payload: line must not mint
# a finding. Tolerates the real forms sqlmap renders — an injection-point index
# ("#1*") and a nested place ("((custom) HEADER)") — and the bare no-place form.
_PARAM = re.compile(r"^Parameter:\s*(.+?)\s*(?:#\d+\*)?\s*(?:\((.+)\))?\s*$",
                    re.M)
_TYPE = re.compile(r"^\s*Type:\s*(.+)$", re.M)
_TITLE = re.compile(r"^\s*Title:\s*(.+)$", re.M)


@register
class SqlmapParser(Parser):
    tool = "sqlmap"

    def parse(self, stdout, stderr="", action=None):
        findings: list[dict] = []
        if not _CONFIRM.search(stdout):
            return self._result(summary="sqlmap: no confirmed injection")

        matches = list(_PARAM.finditer(stdout))
        url = (action or {}).get("url", "")

        if not matches:
            # Confirmed but no Parameter: block matched (rare) — record one
            # finding per technique with the technique in sink, so the dedup
            # key keeps them distinct. Keeping only types[0] in extra dropped
            # every technique past the first and left sink empty.
            types = [t.strip() for t in _TYPE.findall(stdout)]
            for technique in (types or [""]):
                findings.append(self._finding(
                    class_="sqli",
                    title=f"SQL injection confirmed ({technique or 'unknown'})",
                    url=url,
                    severity="critical",
                    sink=technique or None,
                    extra={"technique": technique or None},
                ))
        else:
            for i, m in enumerate(matches):
                param, place = m.group(1), m.group(2)
                # Type:/Title: lines nest under their own Parameter: block —
                # pairing them by global findall index misattributes a
                # technique when one parameter carries several.
                end = matches[i + 1].start() if i + 1 < len(matches) else len(stdout)
                block = stdout[m.end():end]
                types = [t.strip() for t in _TYPE.findall(block)]
                titles = [t.strip() for t in _TITLE.findall(block)]
                # One finding per technique: a parameter confirmed with two
                # techniques used to lose every one past the first. The sink
                # rides the dedup key, so both survive ingestion.
                for j, technique in enumerate(types or [""]):
                    title = titles[j] if j < len(titles) else ""
                    findings.append(self._finding(
                        class_="sqli",
                        title=f"SQL injection in {param} ({technique or 'unknown'})",
                        url=url,
                        param=param,
                        sink=technique,
                        severity="critical",
                        extra={"place": place, "technique_title": title},
                    ))

        params = {f.get("param") for f in findings if f.get("param")}
        if params:
            summary = (f"sqlmap: {len(params)} injectable parameter(s), "
                       f"{len(findings)} technique(s)")
        else:
            # The no-Parameter branch mints with param=None; counting that
            # as "1 injectable parameter" asserted a parameter that was
            # never identified.
            summary = (f"sqlmap: {len(findings)} confirmed injection(s), "
                       "no parameter identified")
        return self._result(summary=summary, findings=findings)
