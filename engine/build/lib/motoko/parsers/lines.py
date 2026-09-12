"""Line-list parsers — tools that print one host/URL per line.

gau / subfinder / amass / naabu / dnsx all emit bare lists; this module
registers one tiny parser per tool (tool->parser is a single mapping, so a
shared base + per-tool subclasses keeps the registry explicit).

Hosts become assets (type=host or url depending on shape); subdomain tools
on a domain seed mint host assets that re-fire the recon chain.

G10 (P1 batch 1): amass additionally speaks two richer dialects — the
``amass enum`` text output annotates every name with its record type and
addresses (``www.shop.invalid (A) 1.2.3.4``), plus ``[banner]``/``[enum]``
prefixed status lines, and ``amass enum -json`` prints one JSON object per
line. Both are stripped down to the bare host set here; the historical
bare-line output stays first-class.
"""

from __future__ import annotations

import json
import re

from . import Parser, register

_HOST = re.compile(r"^[a-zA-Z0-9._-]+$")

# G10: amass text annotation — '(A 1.2.3.4)' / '(CNAME) edge.invalid.'
_AMASS_ANNOT = re.compile(r"\s*\((?:[A-Za-z0-9]+(?:\s+[0-9a-fA-F.:,]+)?)\)\s*")

# G10: amass status/banner prefixes: '[banner]', '[Enum]', '[wrapped]' …
_AMASS_PREFIX = re.compile(r"^\[[^\]]*\]\s*")


def _line_assets(stdout: str, action=None) -> list[dict]:
    src_host = ""
    for key in ("host", "url"):
        v = (action or {}).get(key)
        if v:
            src_host = v.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] \
                if "://" in v else v
            break
    assets: list[dict] = []
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("http://", "https://")):
            assets.append({"type": "url", "value": line})
        elif _HOST.match(line) and "." in line:
            assets.append({"type": "host", "value": line})
    for a in assets:
        host = a["value"].split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] \
            if "://" in a["value"] else a["value"]
        a["enumerated_host"] = host or src_host
        # P-025: domain-level gate — every subdomain of one registrable
        # domain must not each mint a SUB/GAU hypothesis.
        from ..util import registrable_domain
        a["enumerated_domain"] = registrable_domain(host or src_host)
    return assets


def _line_dead(stdout: str) -> list[str]:
    dead: list[str] = []
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(("http://", "https://")):
            continue
        if not (_HOST.match(line) and "." in line):
            dead.append(line[:300])
    return dead


class _LineListParser(Parser):
    def parse(self, stdout, stderr="", action=None):
        assets = []
        for kw in _line_assets(stdout, action):
            # P-027: _asset takes type_/value/extra, NOT arbitrary **kw —
            # the P-025 dict keys (type/enumerated_host/enumerated_domain)
            # blew up _asset(**kw) and dead-lettered every subfinder run.
            extra = {k: v for k, v in kw.items() if k not in ("type", "value")}
            assets.append(self._asset(type_=kw["type"], value=kw["value"],
                                      extra=extra or None))
        dead = _line_dead(stdout)
        return self._result(
            summary=f"{self.tool}: {len(assets)} hosts, {len(dead)} dead",
            assets=assets, dead_letter=dead)


def _amass_normalize(stdout: str) -> str:
    """G10: fold amass's richer output shapes into the bare-line dialect.

    Per line:
    * ``-json`` object (the line parses as a JSON dict) -> its ``name``
      field, with a host-token fallback for exotic rows;
    * text annotation ``name (RTYPE) addr[, addr...]`` / glued
      ``name(CNAME)target`` -> the bare discovered name;
    * ``[banner]`` / ``[enum]`` style prefixed status lines are stripped
      down to a host-looking token when one is really there, otherwise
      pass through untouched (so version strings / project URLs land in
      the dead letter instead of minting out-of-scope host assets).

    Tokens that are IPv4 or version-shaped never count as the extracted
    host; no input line is silently dropped (parser contract).
    """
    _ipv4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    _version = re.compile(r"^v?\d+(?:\.\d+)+$")
    out: list[str] = []
    for raw in (stdout or "").splitlines():
        orig = line = raw.strip()
        if not line:
            continue
        # -json: one JSON object per line
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                name = str(obj.get("name") or "").strip().rstrip(".")
                if name:
                    out.append(name)
                else:
                    out.append(orig)     # exotic row -> dead letter, not lost
                continue
            # not JSON after all: fall through to the text shapes
        # strip a '[banner]' / '[enum]' style prefix
        prefixed = bool(_AMASS_PREFIX.match(line))
        if prefixed:
            line = _AMASS_PREFIX.sub("", line)
        # strip attached annotations: '(A)', '(A 1.2.3.4)', '(CNAME)' ...
        for _ in range(3):
            stripped = _AMASS_ANNOT.sub(" ", line)
            if stripped == line:
                break
            line = stripped
        line = line.strip()
        if not line:
            out.append(orig)
            continue
        if " " in line or prefixed:
            # leftover tokens: keep the first real host-looking one
            tok = ""
            for t in line.split():
                if "." in t and _HOST.match(t) and "." in t \
                        and not _ipv4.match(t) and not _version.match(t):
                    tok = t.rstrip(".")
                    break
            out.append(tok or orig)
        else:
            out.append(line)
    return "\n".join(out)


@register
class GauParser(_LineListParser):
    tool = "gau"


@register
class SubfinderParser(_LineListParser):
    tool = "subfinder"


@register
class AmassParser(_LineListParser):
    tool = "amass"

    def parse(self, stdout, stderr="", action=None):
        return super().parse(_amass_normalize(stdout), stderr, action)


@register
class NaabuParser(_LineListParser):
    tool = "naabu"


@register
class DnsxParser(_LineListParser):
    tool = "dnsx"
