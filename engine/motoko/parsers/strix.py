"""strix output parser — autonomous deep-dive report → graph facts.

strix -n prints an agent session report. Two durable fact layers:
1. URLs (assets) and CVE identifiers (candidate findings) — legacy layer.
2. Structured VULN-XXXX report blocks (TUI 1.6.x format):

   ╭─ VULN-0001 ─╮
   │  Title: ...                                        │
   │  Severity: CRITICAL                                │
   │  CVSS Score: 9.3                                   │
   │  Target: https://host                              │
   │  Endpoint: /path                                   │
   │  Method: GET                                       │
   │  CVSS Vector: AV:N/...                             │
   │  Description / Impact / Technical Analysis ...     │

Each block becomes a finding with class vuln.strix_confirmed and
CVSS/vector/endpoint/method in extra. Everything else stays dead-letter
context (R6-1 persists it for human review).

Pitfall history: P-028 — before this upgrade, confirmed VULN blocks were
dropped entirely; only URLs and CVE strings survived. Real-run evidence:
support.target.example CRITICAL 9.3 WAF bypass was never represented in the
graph.
"""

from __future__ import annotations

import re

from . import Parser, register

_URL = re.compile(r"https?://[^\s\)\]\"'`]+")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

# TUI report fields are padded inside │ ... │ columns; strip both.
_FIELD = re.compile(
    r"^\s*│\s*([A-Za-z ]{3,30}?):\s+(.*?)\s*│\s*$")


@register
class StrixParser(Parser):
    tool = "strix"

    def parse(self, stdout, stderr="", action=None):
        assets: list[dict] = []
        findings: list[dict] = []
        dead: list[str] = []
        target = (action or {}).get("url") or ""
        seen_urls: set[str] = set()

        # Pass 1: legacy URL + CVE layer.
        for line in (stdout or "").splitlines():
            for m in _URL.finditer(line):
                url = m.group(0).rstrip(".,;")
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                if url.startswith(("http://", "https://")):
                    assets.append(self._asset(type_="url", value=url))
            for m in _CVE.finditer(line):
                findings.append(self._finding(
                    class_="vuln.cve_reported",
                    title=f"strix reported {m.group(0)}",
                    url=target,
                    severity="medium",
                    extra={"cve": m.group(0)},
                ))

        # Pass 2: structured VULN-XXXX blocks (P-028).
        lines = (stdout or "").splitlines()
        i, n = 0, len(lines)
        while i < n:
            m = re.match(r".*VULN-(\d+)\s+─+.*", lines[i])
            if not m:
                i += 1
                continue
            block: dict[str, str] = {}
            desc_lines: list[str] = []
            section = None
            i += 1
            while i < n:
                if "─ STRIX ─" in lines[i]:
                    break
                if re.match(r".*VULN-\d+\s+─+.*", lines[i]):
                    break
                fm = _FIELD.match(lines[i])
                if fm:
                    key, val = fm.group(1).strip(), fm.group(2).strip()
                    if key in ("Description", "Impact", "Technical Analysis"):
                        section = key
                    elif key in ("Title", "Severity", "CVSS Score", "Target",
                                 "Endpoint", "Method", "CVSS Vector"):
                        block[key] = val
                    elif section:
                        desc_lines.append(val)
                i += 1
            if block.get("Severity"):
                sev = _SEV.get(block["Severity"].upper(), "medium")
                url = block.get("Target") or target
                try:
                    cvss = float(block.get("CVSS Score", ""))
                except ValueError:
                    cvss = None
                findings.append(self._finding(
                    class_="vuln.strix_confirmed",
                    title=block.get("Title", "strix confirmed finding"),
                    url=url,
                    severity=sev,
                    extra={
                        "cvss": cvss,
                        "vector": block.get("CVSS Vector", ""),
                        "endpoint": block.get("Endpoint", ""),
                        "method": block.get("Method", ""),
                        "source": "strix",
                    },
                ))

        summary = (f"strix: {len(assets)} urls, {len(findings)} findings "
                   f"({sum(1 for f in findings if f['class'] == 'vuln.strix_confirmed')} confirmed)")
        return self._result(
            summary=summary, assets=assets, findings=findings,
            dead_letter=dead)
