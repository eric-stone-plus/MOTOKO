"""nuclei JSONL output parser.

Expects ``nuclei -jsonl -o out.jsonl`` (one JSON object per line). Text
format is NOT parsed — the engine's tool wrapper always passes ``-jsonl``.
Unparseable lines go to dead_letter, never silently dropped.
"""

from __future__ import annotations

import json

from .. import opsec
from . import Parser, register

# template-id keyword -> finding class. Order matters (first match wins).
_CLASS_MAP: list[tuple[str, str]] = [
    ("xss", "xss.reflected"),
    ("sqli", "sqli"),
    ("sql-injection", "sqli"),
    ("ssrf", "ssrf.basic"),
    ("ssti", "ssti.suspected"),
    ("template-injection", "ssti.suspected"),
    ("lfi", "lfi.basic"),
    ("path-traversal", "path_traversal"),
    ("file-inclusion", "lfi.basic"),
    ("deserialization", "deserialization"),
    ("rce", "rce"),
    ("command-injection", "rce"),
    ("cve-", "cve"),
    ("actuator", "exposure.actuator_env"),
    ("springboot", "exposure.actuator_env"),
    ("swagger", "exposure.swagger"),
    ("git-", "exposure.git"),
    ("backup", "exposure.backup"),
    ("debug", "exposure.debug"),
    ("default-login", "auth.default_creds"),
    ("cors", "misconfig.cors"),
    ("missing-security", "misconfig.security_header"),
    ("tech-detect", "fingerprint"),
    ("tls-version", "misconfig.tls"),
]


def map_class(template_id: str) -> str:
    t = template_id.lower()
    for kw, cls in _CLASS_MAP:
        if kw in t:
            return cls
    return "other"


@register
class NucleiParser(Parser):
    tool = "nuclei"

    def parse(self, stdout, stderr="", action=None):
        findings: list[dict] = []
        dead: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                dead.append(line[:500])
                continue
            tid = d.get("template-id") or d.get("template_id") or "unknown"
            info = d.get("info") or {}
            severity = info.get("severity", "unknown")
            matched = d.get("matched-at") or d.get("matched_at") or d.get("host", "")
            # OPSEC: tech-detect style templates can carry a WAF vendor in
            # their tag list; stamp it so the orchestrator can cool the
            # origin down (httpx remains the primary block-page sensor).
            tags = [str(t) for t in (info.get("tags") or [])]
            extra: dict = {"template_id": tid, "type": d.get("type", "")}
            vendor = opsec.detect_waf(tech=tags)
            if vendor:
                extra["waf"] = vendor
            findings.append(self._finding(
                class_=map_class(tid),
                title=f"{tid}: {info.get('name', tid)}",
                url=matched,
                severity=severity,
                extra=extra,
            ))
        return self._result(
            summary=f"nuclei: {len(findings)} matched, {len(dead)} unparseable",
            findings=findings,
            dead_letter=dead,
        )
