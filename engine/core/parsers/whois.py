'whois — the registration record as one url-less finding.\n\n* ``%`` comment lines (IANA\'s server preamble) and the\n  ``>>> Last update of whois database: ... <<<`` footer are grammar;\n* a ``NOTICE:``/``TERMS OF USE:`` legal trailer runs to the end of the\n  response and its prose lines carry no field shape — they are part of\n  the response, not drift;\n* a no-match response (``No match for "EXAMPLE.COM".``) is the registry\n  answering "unregistered": a clean negative, not an error. whois 5.6.6\n  exits 0 for it and for a match, and 2 when the query never went out\n  (the refused capture) — which is exactly the base class\'s exit\n  contract, so ``execution_succeeded`` is not overridden.\n\nA ``Key: value`` line whose key is in neither table, outside a legal\ntrailer, is recorded in ``dead_letter``: it may be a field this parser\nshould learn, and the parser contract forbids dropping it silently.'

from __future__ import annotations

import re

from . import Parser, register

# Registry keys copied onto the finding: normalized key -> finding field.
_COPY: dict[str, str] = {
    "domain name": "domain",
    "domain": "domain",                       # IANA style
    "updated date": "updated",
    "creation date": "created",
    "created": "created",                     # IANA style
    "registry expiry date": "expires",
    "expiry date": "expires",
    "expires": "expires",                     # IANA style
    "registrar": "registrar",
    "registrant organization": "registrant_org",
    "registrant organisation": "registrant_org",
    "organisation": "registrant_org",         # IANA style
    "registrant country": "registrant_country",
    "name server": "name_servers",
    "dnssec": "dnssec",
    "domain status": "status",
    "status": "status",                       # RIPE style
}

# Recognized registry grammar that is NOT copied: registry bookkeeping
# (the record's identity lives in the domain and the dates) and the
# contact/PII blocks.
_IGNORE: frozenset[str] = frozenset({
    "registry domain id", "registrar url", "registrar iana id",
    "registrar whois server", "whois server", "referral url", "source",
    "url of the icann whois inaccuracy complaint form",
    # contact / PII blocks — recognized so a real record parses clean,
    # never copied (PII minimization)
    "registrar abuse contact email", "registrar abuse contact phone",
    "registrant name", "registrant street", "registrant city",
    "registrant state/province", "registrant postal code",
    "registrant phone", "registrant phone ext", "registrant fax",
    "registrant fax ext", "registrant email",
    "admin name", "admin organization", "admin street", "admin city",
    "admin state/province", "admin postal code", "admin country",
    "admin phone", "admin phone ext", "admin fax", "admin fax ext",
    "admin email",
    "tech name", "tech organization", "tech street", "tech city",
    "tech state/province", "tech postal code", "tech country",
    "tech phone", "tech phone ext", "tech fax", "tech fax ext",
    "tech email",
})

# Keys that OPEN the legal trailer block; every later line without a
# recognized field shape belongs to it (its prose carries no markers).
_TRAILER_KEYS = frozenset({"notice", "terms", "terms of use",
                           "legal disclaimer"})

# The gTLD status-code footer is grammar, not a field and not drift.
_FOOTER = re.compile(r"(?i)^for more information on whois status codes\b")
_NO_MATCH = re.compile(r'(?i)^no match for\s+"?([^"]*?)"?\.?\s*$')
_MARKER = re.compile(r"^>>>")

_DEAD_LEN = 120


@register
class WhoisParser(Parser):
    tool = "whois"

    def parse(self, stdout, stderr="", action=None):
        action = action or {}
        ctx_domain = str(action.get("domain") or "").strip().lower().rstrip(".")

        fields: dict[str, str] = {}
        servers: list[str] = []
        statuses: list[str] = []
        dead: list[str] = []
        no_match_name = ""
        no_match = False
        saw_field = False
        in_trailer = False

        for raw in (stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            if _MARKER.match(line) or line.startswith("%"):
                continue
            nm = _NO_MATCH.match(line)
            if nm:
                no_match = True
                no_match_name = nm.group(1).strip()
                continue
            if _FOOTER.match(line):
                continue
            if ":" not in line:
                if in_trailer:
                    continue
                dead.append(self._dead(line))
                continue

            key, _, value = line.partition(":")
            key = " ".join(key.split()).lower()
            value = value.strip()
            if key in _TRAILER_KEYS:
                in_trailer = True
                continue
            field = _COPY.get(key)
            if field is not None:
                saw_field = True
                if field == "domain":
                    fields["domain"] = value.lower().rstrip(".")
                elif field == "name_servers":
                    if value:
                        servers.append(value)
                elif field == "status":
                    if value:
                        statuses.append(value)
                else:
                    fields[field] = value
                continue
            if key in _IGNORE:
                saw_field = True
                continue
            if in_trailer:
                continue
            dead.append(self._dead(line))

        domain = fields.get("domain") or ctx_domain

        if saw_field:
            title = f"whois registration record for {domain or 'the domain'}"
            registrar = fields.get("registrar", "")
            if registrar:
                title += f" — registrar {registrar}"
            finding = self._finding(
                class_="fingerprint",
                title=title,
                url="",
                severity="info",
                extra={
                    "domain": domain,
                    "registrar": registrar,
                    "registrant_org": fields.get("registrant_org", ""),
                    "registrant_country": fields.get("registrant_country", ""),
                    "created": fields.get("created", ""),
                    "updated": fields.get("updated", ""),
                    "expires": fields.get("expires", ""),
                    "dnssec": fields.get("dnssec", ""),
                    "name_servers": servers,
                    "status": statuses,
                },
            )
            bits = [f"whois: registration record for {domain or 'the domain'}"]
            if registrar:
                bits.append(f"— registrar {registrar}")
            if servers:
                bits.append(f"— {len(servers)} name server(s)")
            if statuses:
                bits.append(f"— {len(statuses)} status value(s)")
            if fields.get("dnssec"):
                bits.append(f"— DNSSEC {fields['dnssec']}")
            return self._result(" ".join(bits), findings=[finding],
                                dead_letter=dead)

        if no_match:
            name = no_match_name or ctx_domain or "the domain"
            return self._result(
                f"whois: no match for {name} — the domain is unregistered or "
                "not found in the registry; nothing to fingerprint",
                dead_letter=dead)

        if dead:
            return self._result(
                f"whois: no registration record recognized — "
                f"{len(dead)} line(s) dead-lettered", dead_letter=dead)

        return self._result("whois: no registration record in output")

    @staticmethod
    def _dead(line: str) -> str:
        return f"unparsed whois line ({len(line)} chars): {line[:_DEAD_LEN]}"
