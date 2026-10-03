'httpx output parser — produces ASSETS (alive URLs), not findings.\n\nSupports ``httpx -json`` (object per line, or a JSON array) and the default\ntext format ``URL [status] [title] [tech1,tech2]``.'

from __future__ import annotations

import json
import re

from .. import opsec
from . import Parser, register

# One [...] group of the text format, matched whole: a multi-word title
# ([Example Title]) never survives line.split() as a single token.
_GROUP = re.compile(r"\[([^\]]*)\]")


def _coerce_tech(value) -> list[str]:
    """Normalize a tech/tech_stack field to a list of str.

    ``opsec.detect_waf`` iterates ``tech``, so a non-scalar that a malformed
    JSONL line carries (an int, a bool, a nested object) must never reach the
    sensor — it raised TypeError out of ``parse()`` and dead-lettered every
    good line in the same observation. A string is the legacy comma-joined
    form; a list/tuple keeps its string members; anything else drops to empty.
    """
    if isinstance(value, str):
        return [t.strip() for t in value.split(",") if t.strip()]
    if isinstance(value, (list, tuple)):
        return [str(t).strip() for t in value
                if t is not None and str(t).strip()]
    return []


@register
class HttpxParser(Parser):
    tool = "httpx"

    def parse(self, stdout, stderr="", action=None):
        assets: list[dict] = []
        dead: list[str] = []
        waf_hits = 0
        text = stdout.strip()

        if text.startswith("["):
            # JSON array form
            try:
                records = json.loads(text)
            except json.JSONDecodeError:
                records = None
            if records is not None:
                for d in records:
                    if not isinstance(d, dict):
                        # A non-object member ("junk" in [{...}, "junk"]) is
                        # target-controlled: record it, never let it raise
                        # out of the parser and dead-letter the whole run.
                        dead.append(str(d)[:500])
                        continue
                    a = self._asset_from_json(d)
                    if a:
                        assets.append(a)
                        if a.get("waf"):
                            waf_hits += 1
                summary = f"httpx: {len(assets)} alive (json)"
                if waf_hits:
                    summary += f", {waf_hits} behind a WAF"
                if dead:
                    summary += f", {len(dead)} unparseable"
                return self._result(summary=summary, assets=assets,
                                    dead_letter=dead)

        # JSONL form (one object per line) or text form
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    a = self._asset_from_json(json.loads(line))
                except json.JSONDecodeError:
                    dead.append(line[:500])
                    continue
                if a:
                    assets.append(a)
                    if a.get("waf"):
                        waf_hits += 1
            else:
                a = self._asset_from_text(line, dead)
                if a:
                    assets.append(a)
                    if a.get("waf"):
                        waf_hits += 1
                else:
                    dead.append(line[:500])
        summary = f"httpx: {len(assets)} alive, {len(dead)} unparseable"
        if waf_hits:
            summary += f", {waf_hits} behind a WAF"
        return self._result(
            summary=summary,
            assets=assets,
            dead_letter=dead,
        )

    def _asset_from_json(self, d: dict) -> dict | None:
        url = d.get("url") or d.get("host") or d.get("input")
        if not url:
            return None
        tech = _coerce_tech(d.get("tech") or d.get("tech_stack"))
        extra = {
            "status_code": d.get("status_code"),
            "title": d.get("title"),
            "tech": tech,
            "webserver": d.get("webserver"),
        }
        vendor = opsec.detect_waf(title=d.get("title") or "",
                                  webserver=d.get("webserver") or "",
                                  tech=tech,
                                  headers=d.get("header") if isinstance(
                                      d.get("header"), dict) else None)
        if vendor:
            extra["waf"] = vendor
        if d.get("http2"):
            extra["http2"] = True
        if str(d.get("cdn_type") or "").lower() == "cloud":
            extra["cloud"] = True
        return self._asset(type_="url", value=url, extra=extra)

    def _asset_from_text(self, line: str,
                         dead: list[str] | None = None) -> dict | None:
        # https://shop.invalid [200] [Page Title] [nginx,react]
        parts = line.split(None, 1)
        if not parts or "://" not in parts[0]:
            return None
        url = parts[0]
        groups = _GROUP.findall(parts[1] if len(parts) > 1 else "")
        status = None
        # ASCII-only: str.isdigit() is True for a superscript or full-width
        # digit, and int() on a non-ASCII-digit form raises ValueError out of
        # parse() — one target-controlled byte dead-lettering the whole
        # observation, against the never-raise contract this file states.
        if groups and groups[0].isascii() and groups[0].isdigit():
            status = int(groups[0])
            groups = groups[1:]
        # The format is positional — [status] [title] [webserver] [tech] — so
        # the title is the group after status and the tech is the last group: a
        # comma-containing title ([Hello, World]) stays a title instead of
        # being shredded into the tech list. httpx prints [] for a missing
        # title AND for missing tech, so an empty group occupies its slot
        # without clobbering what the other slot already parsed.
        title = None
        webserver = None
        tech: list[str] = []
        if len(groups) > 1:
            title = groups[0] or None
            tech = [t.strip() for t in groups[-1].split(",") if t.strip()]
            if len(groups) > 2:
                webserver = groups[1] or None
                if len(groups) > 3 and dead is not None:
                    extras = " ".join(g for g in groups[2:-1] if g)
                    if extras:
                        dead.append("httpx extra groups ignored: " + extras[:400])
        elif len(groups) == 1:
            # One lone group: a comma marks the tech-only output shape
            # ([nginx,react] with no title printed).
            if "," in groups[0]:
                tech = [t.strip() for t in groups[0].split(",") if t.strip()]
            else:
                title = groups[0] or None
        extra = {"status_code": status, "title": title, "tech": tech,
                 "webserver": webserver}
        vendor = opsec.detect_waf(title=title or "", webserver=webserver or "",
                                  tech=tech)
        if vendor:
            extra["waf"] = vendor
        return self._asset(type_="url", value=url, extra=extra)
