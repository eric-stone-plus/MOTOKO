'ffuf discovers NEW endpoints (assets), not vulnerabilities. Non-2xx/3xx\nstatuses are ignored. Sensitive paths (.env/.git/backup/…) additionally emit\na low-confidence info-disclosure finding.\n\nSupported output shapes:\n\n* ``-json`` emits newline-delimited JSON matches on stdout.\n\n* ``-of json`` writes ONE JSON object — ``{"commandline": ..., "time": ...,\n  "results": [{...}, ...]}`` — not one JSON object per line. Each result\n  carries ``input.FUZZ``, ``status``, ``length``, ``url`` and friends.\n* the default text output prints one hit per line, payload and status TOGETHER::\n\n      admin                   [Status: 200, Size: 1234, Words: 50, Lines: 20, Duration: 120ms]\n\n  (``::``-prefixed lines are ffuf\'s banner/config/progress chrome and are\n  recognised, not data; the ffuf v1 ``* FUZZ:`` continuation line is not part\n  of this format, and a line that does not match lands in ``dead_letter`` —\n  nothing is silently dropped.)'

from __future__ import annotations

import json
import re

from . import Parser, register

_SENSITIVE_PATTERNS = [
    ".env", ".git", ".svn", ".hg", ".htaccess", ".htpasswd", "backup",
    ".bak", ".old", ".swp", "wp-config", "id_rsa", "id_ed25519", ".sql",
    ".dump", "phpinfo", ".pem", ".key", ".crt",
]

# `payload   [Status: 200, Size: 1234, Words: 50, Lines: 20, Duration: 120ms]`
_TEXT_LINE = re.compile(
    r"^(?P<path>\S.*?)\s+\[Status:\s*(?P<status>\d+)"
    r"(?:,\s*Size:\s*(?P<size>\d+))?"
    r"(?:,\s*Words:\s*(?P<words>\d+))?"
    r"(?:,\s*Lines:\s*(?P<lines>\d+))?"
    r"(?:,\s*Duration:\s*(?P<duration>[0-9.]+[a-zA-Zµ]+))?"
    r"\s*\]\s*$"
)


def _is_hit(status: int) -> bool:
    return status in (200, 201, 204, 301, 302, 307, 401, 403)


def _is_sensitive(path: str) -> bool:
    p = path.lower()
    return any(s in p for s in _SENSITIVE_PATTERNS)


@register
class FfufParser(Parser):
    tool = "ffuf"

    def parse(self, stdout, stderr="", action=None):
        assets: list[dict] = []
        findings: list[dict] = []
        dead: list[str] = []
        base_url = self._base_url(action)

        text = (stdout or "").strip()
        if text.startswith("{") or text.startswith("["):
            self._parse_json(text, base_url, assets, findings, dead)
        else:
            self._parse_text(stdout or "", base_url, assets, findings, dead)

        return self._result(
            summary=(f"ffuf: {len(assets)} endpoints, {len(findings)} sensitive, "
                     f"{len(dead)} unparseable"),
            assets=assets,
            findings=findings,
            dead_letter=dead,
        )

    # -- shapes ----------------------------------------------------------
    @staticmethod
    def _base_url(action) -> str:
        base = str((action or {}).get("base_url")
                   or (action or {}).get("url") or "")
        if base.endswith("FUZZ"):
            base = base.rsplit("FUZZ", 1)[0]
        return base

    def _parse_json(self, text: str, base_url: str, assets: list, findings: list,
                    dead: list) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    dead.append(line[:500])
                    continue
                self._parse_json(json.dumps(item), base_url, assets, findings, dead)
            return
        if isinstance(data, dict):
            results = data.get("results")
            if results is None and "status" in data:
                results = [data]
        elif isinstance(data, list):
            results = data          # tolerated shape (ffuf -json pipelines)
        else:
            results = None
        if not isinstance(results, list):
            dead.append(text[:2000])
            return
        for item in results:
            if not isinstance(item, dict):
                dead.append(json.dumps(item)[:500])
                continue
            status = item.get("status")
            if status is None:
                dead.append(json.dumps(item)[:500])
                continue
            try:
                status_code = int(status)
            except (TypeError, ValueError):
                dead.append(json.dumps(item)[:500])
                continue
            if not _is_hit(status_code):
                continue
            url = item.get("url") or self._url_from_input(item, base_url)
            if not url:
                dead.append(json.dumps(item)[:500])
                continue
            self._emit(url, assets, findings,
                       extra={"status_code": status_code,
                              "length": item.get("length")})

    def _parse_text(self, stdout: str, base_url: str, assets: list, findings: list,
                    dead: list) -> None:
        for raw in stdout.splitlines():
            line = raw.strip()
            if not line or line.startswith("::"):
                continue                      # ffuf banner/config/progress chrome
            m = _TEXT_LINE.match(line)
            if not m:
                dead.append(line[:500])
                continue
            status = int(m.group("status"))
            if not _is_hit(status):
                continue
            path = m.group("path").strip()
            if "://" not in path and base_url:
                url = base_url.rstrip("/") + "/" + path.lstrip("/")
            else:
                url = path
            if not url:
                dead.append(line[:500])
                continue
            self._emit(url, assets, findings,
                       extra={"status_code": status,
                              "length": int(m.group("size")) if m.group("size") else None})

    @staticmethod
    def _url_from_input(item: dict, base_url: str) -> str:
        """Reconstruct the hit URL from the FUZZ input when ffuf omitted it."""
        payload = ""
        inp = item.get("input")
        if isinstance(inp, dict) and inp:
            payload = str(next(iter(inp.values())))
        if not payload:
            return ""
        if "://" in payload:
            return payload
        return (base_url.rstrip("/") + "/" + payload.lstrip("/")) if base_url else payload

    def _emit(self, url: str, assets: list[dict], findings: list[dict],
              extra: dict | None = None) -> None:
        if not url:
            return
        assets.append(self._asset(type_="url", value=url, extra=extra or {}))
        if _is_sensitive(url):
            findings.append(self._finding(
                class_="info_disclosure.sensitive_file",
                title=f"Potentially sensitive path: {url}",
                url=url,
                severity="info",
            ))
