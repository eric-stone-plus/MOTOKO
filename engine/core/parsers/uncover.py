'uncover — third-party search-engine intel, read as rows and not as a scan.\n\n`uncover` asks provider APIs what the internet has already indexed, so it is the\none recon source that widens the attack surface without sending the target a\nsingle packet. The binary was anchored in the tools-anchor manifest (deploy-host\ndata, deliberately not exported) and the unified backfill script already shelled\nout to it, but no parser was registered, so every run dead-lettered as "no\nparser registered for tool \'uncover\'" — a provider hit and a provider failure\nwere the same row on the graph.\n\nShapes are taken from the pinned release, never from a live run: no binary is\nexecuted to produce them and no fixture here was captured over a socket.\n\n* `tools/bin/uncover` is `github.com/projectdiscovery/uncover v1.2.1`\n  (`go version -m`, which reads the binary\'s build info);\n* at that tag `sources/result.go` declares\n  ``Result{Timestamp int64 `json:"timestamp"`, Source string `json:"source"`,\n  IP string `json:"ip"`, Port int `json:"port"`, Host string `json:"host"`,\n  Url string `json:"url"`, Raw []byte `json:"-"`, Error error `json:"-"`}``\n  and ``JSON()`` marshals it, so `-j` writes exactly those six keys, one object\n  per line, with no `omitempty` — `Raw`/`Error` are never serialised, and a\n  per-result provider error is logged instead of printed;\n* `runner/runner.go`\'s default branch instead renders the operator\'s field\n  template through ``strings.NewReplacer("ip", …, "host", …, "port", …,\n  "url", …)`` and falls back to the bare ``host`` field when the row\'s IP is\n  empty or its port is 0 and the template mentions ip or port, so the text\n  dialect\'s columns are operator-configurable — only the unambiguous shapes are\n  recognised here;\n* the flag help embedded in that same binary reads `show only results in\n  output` (`-silent`, which is what keeps stdout free of the banner),\n  `disable automatic uncover update check` (`-duc`), `limit the number of\n  results to return` (`-l`) and `field to display in output (ip,port,host)`\n  (`-f`).\n\nFour choices are deliberate, because each would otherwise be silent:\n\nA `{`-prefixed line that does not parse is dead-lettered rather than\nreassembled across lines: `-j` is line-delimited, so a partial object means the\nshape moved, and saying so beats guessing.\n'

from __future__ import annotations

import json
import re

from .. import util
from . import Parser, register

# The field-template dialect: `<host|ip>[:<port>]`, bracketed for IPv6 — the
# same line shape naabu prints (parsers/lines.py).
_HOST_PORT = re.compile(r"^(\[[0-9a-fA-F:.%]+\]|[a-zA-Z0-9._-]+):(\d{1,5})$")
# A bare DNS name. ':' is excluded, so an address never matches it.
_HOST = re.compile(r"^[a-zA-Z0-9._-]+$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_V6_CHARS = frozenset("0123456789abcdefABCDEF:.")
_SCHEMED = ("http://", "https://")
_DEAD_LEN = 300


def _host_of(value: str) -> str:
    """Host of a URL or bare name: scheme, userinfo, port and path stripped."""
    if "://" not in value:
        return value
    return value.split("://", 1)[1].split("/", 1)[0].rsplit("@", 1)[-1] \
        .split(":", 1)[0]


def _is_address(value: str) -> bool:
    """True for an IPv4/IPv6 literal — the shapes a domain must not be cut from."""
    if _IPV4.match(value):
        return True
    return ":" in value and all(c in _V6_CHARS for c in value)


def _row(line: str) -> tuple[str, dict]:
    """One output row -> ``(asset value, extra)``, or ``("", {})``.

    Both dialects above land here: a JSON object when the action asked for
    `-j`, otherwise the field template's own text.
    """
    if line.startswith("{") and line.endswith("}"):
        try:
            obj = json.loads(line)
        except ValueError:
            return "", {}
        if not isinstance(obj, dict):
            return "", {}
        url = str(obj.get("url") or "").strip()
        host = str(obj.get("host") or "").strip()
        ip = str(obj.get("ip") or "").strip()
        value = url if url.startswith(_SCHEMED) else (host or ip)
        if not value:
            return "", {}
        extra: dict = {}
        # `ip` is deliberately NOT stamped, though the row carries one:
        # `_fact_view` reads `asset["ip"]`, and the corpus locks that field as
        # one no parser writes (tests/test_rulecheck.py::TestDerivation), so an
        # `ip` fact must stay unproducible and any rule gating on it must be
        # reported dead. The address is used to identify the asset when the row
        # names no host, and then dropped.
        port = obj.get("port")
        # bool is an int subclass: a JSON `true` must not become port 1.
        if isinstance(port, int) and not isinstance(port, bool) \
                and 1 <= port <= 65535:
            extra["port"] = port
        return value, extra
    m = _HOST_PORT.match(line)
    if m:
        port = int(m.group(2))
        if not 1 <= port <= 65535:
            return "", {}
        return m.group(1).strip("[]"), {"port": port}
    if line.startswith(_SCHEMED):
        return line, {}
    if (_HOST.match(line) and "." in line) or _is_address(line):
        return line, {}
    return "", {}


@register
class UncoverParser(Parser):
    tool = "uncover"

    def parse(self, stdout, stderr="", action=None):
        # The queried domain is the action's own host: every row this run
        # returned belongs to it, which is what makes the stamp honest for an
        # address-only row (choice 4 above).
        src_host = ""
        for key in ("host", "url"):
            v = (action or {}).get(key)
            if v:
                src_host = _host_of(str(v))
                break
        assets: list[dict] = []
        dead: list[str] = []
        for raw in (stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            value, extra = _row(line)
            if not value:
                dead.append(line[:_DEAD_LEN])
                continue
            host = _host_of(value)
            extra["enumerated_host"] = host or src_host
            domain_src = src_host if _is_address(host) else host
            if domain_src and not _is_address(domain_src):
                extra["enumerated_domain"] = util.registrable_domain(domain_src)
            assets.append(self._asset(
                type_="url" if value.startswith(_SCHEMED) else "host",
                value=value, extra=extra))
        # With `-silent` stderr is empty; anything on it is a provider or
        # configuration error, which is exactly what must not be dropped.
        for raw in (stderr or "").splitlines():
            line = raw.strip()
            if line:
                dead.append(line[:_DEAD_LEN])
        return self._result(
            summary=f"uncover: {len(assets)} results, {len(dead)} dead",
            assets=assets, dead_letter=dead)
