"dnsrecon — DNS records become host assets; a successful AXFR a finding.\n\nTwo grammars live in one transcript, quoted from the installed printers:\n\n* **std section** (``cli.py``, the ``-t std`` path): ``\\t TYPE name\n  address`` for SOA/NS/A/AAAA, ``\\t MX exchange address``, ``\\t TXT\n  name strings…``, ``\\t SPF strings…``, ``\\t SRV name target address\n  port``.\n* **zone-transfer section** (``lib/dnshelper.py``): the same record\n  types with different field layouts — ``\\t MX fqdn exchange address``,\n  ``\\t TXT strings…`` (the name is not printed), ``\\t SRV fqdn target\n  port weight address`` — plus records the std path never prints\n  (CNAME, PTR, HINFO, the DNSSEC set). dnsrecon 1.6.0 calls\n  ``zone_transfer()`` twice per run, so every zone record appears twice;\n  minting dedups by name.\n\nWhat it emits, and what it deliberately does not:\n\n* in-domain names become ``host`` assets carrying the same\n  ``enumerated_host``/``enumerated_domain`` stamps the line parsers\n  apply, so a run that mints at least one in-domain name closes the enum\n  rules' domain gate; a run that mints none leaves it open (a std\n  transcript whose only names are out-of-domain provider servers is the\n  ordinary case), and a re-fire stays bounded by the per-(rule, asset)\n  attempt cap;\n* names OUTSIDE the target's registrable domain are not minted (provider\n  nameservers, CNAME targets): they are infrastructure the manual\n  WHOIS/ASN gate vets before anything probes them;\n* service labels (``_sip._tcp``, ``_dmarc``, ``_domainkey``) are not\n  hosts and are not minted;\n* a successful AXFR becomes one finding per successful nameserver\n  (class ``info_disclosure.dns_zone_transfer``, url-less like the other\n  disclosure parsers); a failed transfer is the ordinary outcome and is\n  only counted in the summary;\n* record types the parser does not model (HINFO and the rest of the\n  zone printer's long tail) are recognized, counted and named in the\n  summary — they are the tool's grammar, not drift. A line that is not\n  a loguru line, or a record line whose type token is unknown, goes to\n  ``dead_letter``.\n\nExit contract: 0 is success even when nothing answered (the real\ncapture); 1 with the tool's own ``Could not resolve domain`` verdict is\na clean NXDOMAIN negative; any other nonzero code is a failure."

from __future__ import annotations

import re

from . import Parser, register
from ..util import registrable_domain

# loguru line: "2026-10-16T09:10:00.000000+0000 INFO <message>".
_LOG = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4}\s+"
    r"(TRACE|DEBUG|INFO|SUCCESS|WARNING|ERROR|CRITICAL)\s(.*)$")

# Record types whose lines this parser mints hosts from.
_MODELED = frozenset({"A", "AAAA", "SOA", "NS", "MX", "TXT", "SPF", "PTR",
                      "SRV", "CNAME"})
# Record types dnsrecon's zone printer emits but this parser does not
# model: recognized, counted and named in the summary, never dead-lettered.
_UNMODELED = frozenset({
    "HINFO", "WKS", "RP", "AFSDB", "LOC", "X25", "ISDN", "RT", "NSAP",
    "NAPTR", "CERT", "SIG", "RRSIG", "DNSKEY", "DS", "NSEC", "NSEC3",
    "NSEC3PARAM", "IPSECKEY",
})

# A token that can be a DNS name (no '=' or ';', which TXT values carry).
_NAME_TOKEN = re.compile(r"^[A-Za-z0-9_@*.-]+$")

_DEAD_LEN = 120


def _record_name(rtype: str, tokens: list[str], domain: str) -> str:
    """The hostname a record line names, or '' when its layout carries none.

    Dispatch is per type because the std and zone sections differ:
    MX std ``MX exchange address`` / zone ``MX fqdn exchange address``
    (the exchange is the host, at index 1 or 2); SRV std ``SRV name
    target address port`` / zone ``SRV fqdn target port weight address``
    (the target is index 2 in both, ``no_ip`` included); TXT is printed
    with its name only in the std section, where the second token is the
    queried target. The zone section shares this branch and the same token
    position holds the VALUE's first word there: an in-domain FQDN sitting
    in that position (``TXT www.example.com is our CDN``) mints like any
    other in-domain name the transcript names — the suffix check is what
    bounds it, and dropping the branch would lose the std section's
    queried-target mint. Pinned by
    ``test_a_zone_txt_value_naming_an_in_domain_host_mints_it``.
    """
    if rtype in ("SOA", "NS", "A", "AAAA", "PTR", "CNAME"):
        return tokens[1] if len(tokens) > 1 else ""
    if rtype == "MX":
        if len(tokens) >= 4:
            return tokens[2]
        return tokens[1] if len(tokens) >= 3 else ""
    if rtype == "SRV":
        return tokens[2] if len(tokens) > 2 else ""
    if rtype == "TXT":
        if len(tokens) >= 3 and _NAME_TOKEN.match(tokens[1]):
            cand = tokens[1].strip(".").lower()
            if cand == domain or cand.endswith("." + domain):
                return tokens[1]
        return ""
    return ""   # SPF and the unmodeled set carry no name


def _normalize(name: str, domain: str) -> str:
    """Lowercase a record name; ``@`` (and ``@.``) is the zone origin."""
    n = name.strip().strip(".").lower()
    if n.startswith("@"):
        n = n[1:].lstrip(".")
    return n or domain


def _in_domain(name: str, domain: str) -> bool:
    return bool(domain) and (name == domain or name.endswith("." + domain))


@register
class DnsreconParser(Parser):
    tool = "dnsrecon"

    def parse(self, stdout, stderr="", action=None):
        action = action or {}
        ctx_domain = str(action.get("domain") or "").strip().lower().rstrip(".")

        text = f"{stderr or ''}{stdout or ''}"
        domain = ctx_domain
        assets: list[dict] = []
        findings: list[dict] = []
        dead: list[str] = []
        minted: set[str] = set()
        unmodeled: set[str] = set()
        zt_ok: set[str] = set()
        zt_fail: set[str] = set()
        errors = 0
        current_ns = ""

        def mint(name: str) -> None:
            if name in minted:
                return
            minted.add(name)
            assets.append(self._asset(type_="host", value=name, extra={
                "enumerated_host": name,
                "enumerated_domain": registrable_domain(name),
            }))

        for raw in text.splitlines():
            if not raw.strip():
                continue
            # Match the UNstripped line: loguru emits bare "INFO  " lines
            # (an empty message), and rstrip would eat the separator the
            # regex needs.
            m = _LOG.match(raw)
            if not m:
                dead.append(self._dead(raw.rstrip()))
                continue
            level, msg = m.group(1), m.group(2).rstrip()
            if not msg:
                continue
            if level == "ERROR":
                errors += 1

            if msg.startswith("\t"):
                tokens = msg.strip().split()
                rtype = tokens[0] if tokens else ""
                if rtype in _UNMODELED:
                    unmodeled.add(rtype)
                    continue
                if rtype not in _MODELED:
                    dead.append(self._dead(raw.rstrip()))
                    continue
                name = _record_name(rtype, tokens, domain)
                if not name:
                    continue
                norm = _normalize(name, domain)
                # Out-of-domain names are provider infrastructure, and a
                # service label is not a host: neither is minted.
                if _in_domain(norm, domain) and not norm.startswith("_"):
                    mint(norm)
                continue

            # Narration: the tool's own channel. The state it carries is
            # tracked; everything else is absorbed (the summary accounts
            # for the error count).
            if msg.startswith("Starting enumeration for domain: "):
                logged = msg.split("domain: ", 1)[1].strip().lower().rstrip(".")
                if not domain:
                    domain = logged
                continue
            if msg.startswith("Trying NS server "):
                current_ns = msg.split("Trying NS server ", 1)[1].strip()
                continue
            if msg.endswith(" Has port 53 TCP Open"):
                current_ns = msg.split(" Has port 53 TCP Open", 1)[0].strip()
                continue
            if msg.startswith("Zone Transfer was successful"):
                if current_ns:
                    zt_ok.add(current_ns)
                continue
            if msg.startswith("Zone Transfer Failed"):
                if current_ns:
                    zt_fail.add(current_ns)
                continue

        for ns in sorted(zt_ok):
            findings.append(self._finding(
                class_="info_disclosure.dns_zone_transfer",
                title=(f"DNS zone transfer (AXFR) succeeded for "
                       f"{domain or 'the domain'} from {ns}"),
                url="",
                severity="high",
                extra={"domain": domain, "ns_server": ns,
                       "zone_transfer": "success"},
            ))

        bits = [f"dnsrecon: {domain or 'unknown domain'}"]
        if assets:
            bits.append(f"— {len(assets)} host(s)")
        if zt_ok:
            bits.append("— zone transfer succeeded from "
                        + ", ".join(sorted(zt_ok)))
        elif zt_fail:
            bits.append(f"— zone transfer failed on {len(zt_fail)} server(s)")
        if unmodeled:
            bits.append("— unmodeled record type(s): "
                        + ", ".join(sorted(unmodeled)))
        if errors:
            bits.append(f"— {errors} error-level diagnostic(s)")
        if not assets and not zt_ok and not zt_fail:
            bits.append("— no records answered")

        return self._result(" ".join(bits), assets=assets, findings=findings,
                            dead_letter=dead)

    def execution_succeeded(self, exit_code, stdout, stderr, action):
        if exit_code == 0:
            return True
        # The tool's own NXDOMAIN verdict (dns_sec_check) exits 1: a clean
        # negative. Any other nonzero exit is a real failure.
        if exit_code == 1 and "Could not resolve domain" in \
                f"{stderr or ''}{stdout or ''}":
            return True
        return False

    @staticmethod
    def _dead(line: str) -> str:
        return f"unparsed dnsrecon line ({len(line)} chars): {line[:_DEAD_LEN]}"
