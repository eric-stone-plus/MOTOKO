'strix output parser — autonomous deep-dive report → graph facts.\n\nstrix -n prints an agent session report. Two durable fact layers:\n1. URLs (assets) and CVE identifiers (candidate findings) — legacy layer.\n2. Structured VULN-XXXX report blocks (TUI 1.6.x format):\n\n   ╭─ VULN-0001 ─╮\n   │  Title: ...                                        │\n   │  Severity: CRITICAL                                │\n   │  CVSS Score: 9.3                                   │\n   │  Target: https://host                              │\n   │  Endpoint: /path                                   │\n   │  Method: GET                                       │\n   │  CVSS Vector: AV:N/...                             │\n   │  Description / Impact / Technical Analysis ...     │'

from __future__ import annotations

import re

from . import Parser, register

_URL = re.compile(r"https?://[^\s\)\]\"'`]+")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

# TUI report fields are padded inside │ ... │ columns; strip both.
_FIELD = re.compile(
    r"^\s*│\s*([A-Za-z ]{3,30}?):\s+(.*?)\s*│\s*$")



def _map_strix_class(title: str, cwe: str) -> str:
    ''
    t = f"{title} {cwe}".lower()
    cwe = (cwe or "").upper()
    if "open redirect" in t or cwe == "CWE-601":
        return "open_redirect.basic"
    if "postmessage" in t:
        return "xss.postmessage"
    if "xss" in t or "cross-site scripting" in t or cwe == "CWE-79":
        return "xss.reflected"
    if "hardcod" in t or cwe in ("CWE-321", "CWE-798"):
        return "info_disclosure.key"
    if "schema" in t or "disclos" in t or cwe == "CWE-200":
        return "info_disclosure.schema"
    if "sqli" in t or "sql injection" in t or cwe == "CWE-89":
        return "sqli"
    if "ssrf" in t or cwe == "CWE-918":
        return "ssrf.basic"
    if "idor" in t or "bola" in t or "insecure direct object" in t \
            or "object level authorization" in t or cwe == "CWE-639":
        return "idor.confirmed"
    if "path traversal" in t or "directory traversal" in t \
            or cwe == "CWE-22":
        return "path_traversal"
    # Two distinct findings, never collapsed: shipped credentials vs a logic
    # bypass. Both route to replay via the router's `auth` prefix.
    if "default cred" in t or cwe in ("CWE-1188", "CWE-1392"):
        return "auth.default_creds"
    if "authentication bypass" in t or "auth bypass" in t or cwe == "CWE-287":
        return "auth.bypass"
    if "cors" in t or cwe == "CWE-942":
        return "misconfig.cors"
    return "vuln.strix_confirmed"

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
                                 "Endpoint", "Method", "CVSS Vector", "CWE"):
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
                    class_=_map_strix_class(block.get("Title", ""),
                                            block.get("CWE", "")),
                    title=block.get("Title", "strix confirmed finding"),
                    url=url,
                    severity=sev,
                    extra={
                        "cwe": block.get("CWE", ""),
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
