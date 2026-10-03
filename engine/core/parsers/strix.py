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

# The box bottom border (╰─…─╯, U+2570). A block whose capture ended on this
# line — or on nothing at all — must stop here; scanning to EOF instead pulls
# the trailing context into the block and swallows it.
_CLOSE = re.compile(r"\s*╰")

# A block that has left the │-box for this many consecutive lines has hit a
# bare tail (a truncated/killed capture): stop and let the tail fall through
# to the legacy pass and the dead-letter sweep.
_MAX_TAIL = 2



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
        confirmed = 0

        lines = (stdout or "").splitlines()
        consumed = [False] * len(lines)

        i, n = 0, len(lines)
        while i < n:
            # Anchored to the ╭─ decoration: an unanchored ".*VULN-…" let a
            # mid-prose mention ("skipped VULN-0099 ─── section") open a
            # phantom block that consumed — and dropped — the lines after it.
            m = re.match(r"\s*╭\s*─+\s*VULN-(\d+)\s+─+", lines[i])
            if not m:
                i += 1
                continue
            header = i
            block: dict[str, str] = {}
            desc_lines: list[str] = []
            section = None
            i += 1
            # content_end is the exclusive end of the box itself: the header
            # plus every │-wrapped line. A block that runs into a bare tail —
            # no ╰ close, no banner — must not consume that tail, or a trailing
            # CVE/URL dies with neither finding nor dead letter (the contract
            # at core/parsers/__init__.py).
            content_end = i
            tail = 0
            structural = False
            while i < n:
                line = lines[i]
                if "─ STRIX ─" in line or _CLOSE.match(line) \
                        or re.match(r"\s*╭\s*─+\s*VULN-\d+\s+─+", line):
                    # Box decoration or the next block header: structure, not
                    # data — consume it and stop.
                    structural = True
                    break
                fm = _FIELD.match(line)
                if fm:
                    key, val = fm.group(1).strip(), fm.group(2).strip()
                    if key in ("Description", "Impact", "Technical Analysis"):
                        section = key
                    elif key in ("Title", "Severity", "CVSS Score", "Target",
                                 "Endpoint", "Method", "CVSS Vector", "CWE"):
                        block[key] = val
                    elif section:
                        desc_lines.append(val)
                if fm or line.lstrip().startswith("│"):
                    # Still inside the box (a │-wrapped line, field or prose).
                    content_end = i + 1
                    tail = 0
                else:
                    tail += 1
                    if tail >= _MAX_TAIL:
                        break
                i += 1
            end = i + 1 if structural else content_end
            for j in range(header, min(end, n)):
                consumed[j] = True
            if not (block or desc_lines):
                # Bare-prose interior (no │-field line): nothing was minted,
                # so the interior must not stay consumed — unmarked, the
                # legacy pass reports an interior CVE and the dead-letter
                # sweep sees the prose. Only the header line is consumed.
                for j in range(header + 1, min(i, n)):
                    consumed[j] = False
            if block or desc_lines:
                # Gating the mint on a Severity line let a Severity-less
                # block swallow its own CVE with neither finding nor dead
                # letter. A missing or unrecognized severity label maps to
                # info: inflating it overstated what strix claimed.
                sev = _SEV.get((block.get("Severity") or "").upper(), "info")
                url = block.get("Target") or target
                try:
                    cvss = float(block.get("CVSS Score", ""))
                except ValueError:
                    cvss = None
                extra = {
                    "cwe": block.get("CWE", ""),
                    "cvss": cvss,
                    "vector": block.get("CVSS Vector", ""),
                    "endpoint": block.get("Endpoint", ""),
                    "method": block.get("Method", ""),
                    "source": "strix",
                }
                if desc_lines:
                    # Bounded: the prose is context, not a dump channel.
                    extra["description"] = " ".join(desc_lines)[:1000]
                findings.append(self._finding(
                    class_=_map_strix_class(block.get("Title", ""),
                                            block.get("CWE", "")),
                    title=block.get("Title", "strix confirmed finding"),
                    url=url,
                    severity=sev,
                    extra=extra,
                ))
                confirmed += 1

        # Pass 2: legacy URL + CVE layer. BOTH are gated on `consumed`: a line
        # a VULN block already covered is represented by that block's finding
        # (its url is the finding's url, its CVE the finding's evidence), so
        # re-minting here would double-count. Gating only the CVE let a
        # swallowed tail keep its asset while its evidence vanished.
        for idx, line in enumerate(lines):
            if consumed[idx]:
                continue
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
            if _URL.search(line) or _CVE.search(line):
                consumed[idx] = True

        dead.extend(line.strip()[:500] for idx, line in enumerate(lines)
                    if line.strip() and not consumed[idx])

        summary = (f"strix: {len(assets)} urls, {len(findings)} findings "
                   f"({confirmed} confirmed)")
        return self._result(
            summary=summary, assets=assets, findings=findings,
            dead_letter=dead)
