"""WPScan JSON parser.

Only structured vulnerability entries become findings. In particular,
``scan_aborted`` and transport/database errors are reported in the summary
and never treated as a vulnerability.

Version and enumeration metadata become INVENTORY assets, never findings:
WPScan reports a component's version without any advisory attached, and a
version number on its own is an attack-surface fact (a plugin directory the
fuzz and nuclei legs can walk), not a vulnerability.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from . import Parser, register

_CVE_NUMBER = re.compile(r"^\d{4}-\d{4,7}$")


def _severity(vuln: dict) -> str:
    cvss = vuln.get("cvss")
    cvss = cvss if isinstance(cvss, dict) else {}
    try:
        score: float | None = float(cvss.get("score"))
    except (TypeError, ValueError):
        score = None
    if score is not None:
        return "critical" if score >= 9 else "high" if score >= 7 else \
            "medium" if score >= 4 else "low"
    return str(vuln.get("severity") or "unknown").lower()


def _cve(vuln: dict) -> str:
    """Normalized ``CVE-YYYY-NNNN`` for one advisory, or "" when it has none.

    WPScan carries the number under ``references.cve`` and a uuid under
    ``id``; only a real CVE may reach ``dedup.compute_dedup_key``, which
    appends it — a uuid there would split one advisory reported by two
    components into two findings and defeat the cross-tool dedup.
    """
    refs = vuln.get("references")
    numbers = refs.get("cve") if isinstance(refs, dict) else None
    if isinstance(numbers, (str, int)):
        numbers = [numbers]
    for number in numbers if isinstance(numbers, list) else []:
        text = str(number).strip().upper()
        if text.startswith("CVE-"):
            return text
        if _CVE_NUMBER.match(text):
            return f"CVE-{text}"
    return ""


def _http_url(value) -> str:
    if not isinstance(value, str) or not value.startswith(("http://", "https://")):
        return ""
    try:
        return value if urlsplit(value).hostname else ""
    except ValueError:
        return ""


@register
class WpscanParser(Parser):
    tool = "wpscan"

    def parse(self, stdout, stderr="", action=None):
        text = (stdout or "").strip()
        if not text:
            return self._result("wpscan: empty output")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return self._result("wpscan: invalid JSON", dead_letter=[text[:500]])
        if not isinstance(data, dict):
            return self._result("wpscan: unexpected JSON shape",
                                dead_letter=[text[:500]])
        target = str(data.get("target_url") or (action or {}).get("url") or "")
        aborted = data.get("scan_aborted")
        if aborted:
            reason = str(aborted if isinstance(aborted, str) else
                         data.get("error") or "scan aborted")[:400]
            return self._result(f"wpscan: scan_aborted ({reason})")

        findings: list[dict] = []
        assets: list[dict] = []
        dead: list[str] = []
        seen: set[tuple[str, str]] = set()

        # WPScan reports advisories per component: core under `version`,
        # enumerated plugins/themes under their slug maps, the detected theme
        # under `main_theme`, and — on older output shapes — a target-wide
        # `vulnerabilities` list. Walk all of them so a core or main_theme
        # advisory cannot hide behind the plugin walk.
        components: list[tuple[str, dict]] = []
        core = data.get("version")
        if core is None:
            pass
        elif isinstance(core, dict):
            components.append(("wordpress", core))
        else:
            dead.append("version: expected an object")
        # Older output shapes carry target-wide advisories with no version
        # block. Both slots share the "wordpress" label, so one advisory
        # reported twice collapses in `seen` instead of being filed twice.
        legacy = data.get("vulnerabilities")
        if legacy is None:
            pass
        elif isinstance(legacy, list):
            components.append(("wordpress", {"vulnerabilities": legacy}))
        else:
            dead.append("vulnerabilities: expected a list")
        for section in ("plugins", "themes"):
            values = data.get(section)
            if values is None:
                continue
            if not isinstance(values, dict):
                dead.append(f"{section}: expected an object")
                continue
            for slug, item in values.items():
                if not isinstance(item, dict):
                    dead.append(f"{section}.{slug}: expected an object")
                    continue
                components.append((f"{section[:-1]}:{slug}", item))
        main_theme = data.get("main_theme")
        if isinstance(main_theme, dict):
            slug = str(main_theme.get("slug") or "main")
            components.append((f"theme:{slug}", main_theme))
        elif main_theme is not None:
            dead.append("main_theme: expected an object")

        for component, item in components:
            vulns = item.get("vulnerabilities")
            if vulns is None:
                pass
            elif not isinstance(vulns, list):
                dead.append(f"{component}: vulnerabilities is not a list")
            else:
                for vuln in vulns:
                    if not isinstance(vuln, dict):
                        dead.append(f"{component}: vulnerability is not an object")
                        continue
                    cve = _cve(vuln)
                    title = str(vuln.get("title") or vuln.get("id")
                                or vuln.get("uuid") or cve or component)
                    if (component, cve or title) in seen:
                        # The detected theme is also enumerated under `themes`,
                        # and one advisory must not be filed twice for it.
                        continue
                    seen.add((component, cve or title))
                    extra: dict = {"component": component,
                                   "references": vuln.get("references")}
                    if cve:
                        extra["cve"] = cve
                    if vuln.get("fixed_in"):
                        extra["fixed_in"] = vuln.get("fixed_in")
                    findings.append(self._finding(
                        class_="cve", title=f"WPScan {component}: {title}",
                        url=target, severity=_severity(vuln), extra=extra))

            # Inventory half: a version is an asset fact, not a vulnerability.
            number = item.get("version")
            number = number.get("number") if isinstance(number, dict) else number
            number = str(number).strip() if number is not None else ""
            if not number:
                continue
            if component == "wordpress":
                location = _http_url(target)
                extra_asset: dict = {"wp_component": "core", "wp_version": number}
                if item.get("status"):
                    extra_asset["wp_status"] = str(item["status"])[:40]
            else:
                location = _http_url(item.get("location"))
                if not location:
                    continue
                kind, _, slug = component.partition(":")
                extra_asset = {"wp_component": f"{kind}:{slug}",
                               "wp_version": number}
                if item.get("outdated"):
                    extra_asset["outdated"] = True
            if location:
                assets.append(self._asset(type_="url", value=location,
                                          extra=extra_asset))

        return self._result(
            f"wpscan: {len(findings)} vulnerability record(s), "
            f"{len(assets)} inventory asset(s), {len(dead)} unparseable",
            assets=assets, findings=findings, dead_letter=dead)
