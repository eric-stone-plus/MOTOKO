"""ASN aggregation analyser — RIR whois ∪ BGP clustering for an IP list.

The method this module makes reproducible comes from the Korean engagement
de-anonymisation: for every IP, take the RIR **registration** view and the
BGP **announcement** view, and read them as a UNION.  Neither view alone is
sufficient — in that case one address was registered to a Korean ISP and
only its BGP origin named ``Arisk Communications inc.`` (AS395793), while
another was registered to Arisk inside a GTT block announced by AS3257.
Four of nine addresses collapsed onto one entity only when both views were
merged, and the per-IP whois-vs-BGP **disagreements are the point of the
tool**, not a footnote.

Layering: everything above the two fetch functions is pure — parsers are
tolerant of junk and never raise, and the analysis runs offline against a
TTL cache.  Only :func:`fetch_whois_text` and :func:`fetch_ripestat` touch
the network, so the whole pipeline is testable without a socket.

Discipline:

* one canonical User-Agent, aliased from ``core.opsec.DEFAULT_UA`` (never
  a second literal; ``MOTOKO_UA`` overrides it for an engagement);
* a polite minimum interval between lookups, plus an on-disk TTL cache so
  a repeat run re-reads nothing;
* a whois response is reduced to the fields it contributes at parse time —
  nothing prints or logs the raw text.

Nothing here is target intel: the module is generic tooling over public
registry data.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from . import opsec

#: One canonical User-Agent for every request this module makes.  The repo
#: already owns this string (``core/opsec.py``); alias it rather than
#: spelling a second one, so the engagement-wide ``MOTOKO_UA`` discipline
#: holds for this tool too.
UA = opsec.DEFAULT_UA


def user_agent() -> str:
    """The per-engagement User-Agent (``MOTOKO_UA`` overrides the default)."""
    return os.environ.get("MOTOKO_UA", UA)


# ---------------------------------------------------------------------------
# Structured records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WhoisRecord:
    """The registration view of one IP, reduced to the fields it uses."""

    rir: str = ""
    asn: int | None = None
    as_name: str = ""
    org: str = ""
    orgs: tuple[str, ...] = ()
    netname: str = ""
    country: str = ""
    city: str = ""
    state: str = ""
    cidr: str = ""
    referral: str = ""
    route_cidrs: tuple[str, ...] = ()
    route_origins: tuple[int, ...] = ()

    def as_dict(self) -> dict:
        return {
            "rir": self.rir, "asn": self.asn, "as_name": self.as_name,
            "org": self.org, "orgs": list(self.orgs),
            "netname": self.netname, "country": self.country,
            "city": self.city, "state": self.state, "cidr": self.cidr,
            "referral": self.referral, "route_cidrs": list(self.route_cidrs),
            "route_origins": list(self.route_origins),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "WhoisRecord":
        if not isinstance(data, dict):
            return cls()
        return cls(
            rir=str(data.get("rir") or ""),
            asn=_as_int(data.get("asn")),
            as_name=str(data.get("as_name") or ""),
            org=str(data.get("org") or ""),
            orgs=_str_tuple(data.get("orgs")),
            netname=str(data.get("netname") or ""),
            country=str(data.get("country") or ""),
            city=str(data.get("city") or ""),
            state=str(data.get("state") or ""),
            cidr=str(data.get("cidr") or ""),
            referral=str(data.get("referral") or ""),
            route_cidrs=_str_tuple(data.get("route_cidrs")),
            route_origins=_int_tuple(data.get("route_origins")),
        )


@dataclass(frozen=True)
class PrefixView:
    """The BGP announcement view of one IP (RIPEstat ``prefix-overview``).

    ``resource`` is the aligned prefix the live answer carries (the query
    is made with the IP, the answer names the covering prefix), and
    ``prefix`` is that CIDR — the announced prefix the union uses.  The
    live shape has no ``prefix`` key at all.
    """

    resource: str = ""
    prefix: str = ""
    asn: int | None = None
    as_name: str = ""
    announced: bool = False
    status: str = ""

    def as_dict(self) -> dict:
        return {"resource": self.resource, "prefix": self.prefix,
                "asn": self.asn, "as_name": self.as_name,
                "announced": self.announced, "status": self.status}

    @classmethod
    def from_dict(cls, data: Any) -> "PrefixView":
        if not isinstance(data, dict):
            return cls()
        return cls(resource=str(data.get("resource") or ""),
                   prefix=str(data.get("prefix") or ""),
                   asn=_as_int(data.get("asn")),
                   as_name=str(data.get("as_name") or ""),
                   announced=bool(data.get("announced")),
                   status=str(data.get("status") or ""))


@dataclass(frozen=True)
class AnnouncedPrefixes:
    """RIPEstat ``announced-prefixes`` for one AS."""

    asn: int | None = None
    prefixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ASOverview:
    """RIPEstat ``as-overview`` for one AS."""

    asn: int | None = None
    name: str = ""
    holder: str = ""
    announced: bool = False


# ---------------------------------------------------------------------------
# Small tolerant helpers
# ---------------------------------------------------------------------------


def _as_int(value: Any) -> int | None:
    """First integer in ``value`` — ``395793``, ``"AS395793"`` or ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        m = re.search(r"\d+", value)
        if m:
            return int(m.group())
    return None


def _str_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value if isinstance(v, (str, int)))
    return ()


def _int_tuple(value: Any) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    out: list[int] = []
    for item in value:
        n = _as_int(item)
        if n is not None and n not in out:
            out.append(n)
    return tuple(out)


_RANGE = re.compile(r"^(\S+)\s*-\s*(\S+)$")


def _range_to_cidr(start: str, end: str) -> str:
    """The smallest CIDR covering an ``a - b`` range, or ``""``."""
    try:
        a = ipaddress.ip_address(start.strip())
        b = ipaddress.ip_address(end.strip())
    except ValueError:
        return ""
    if a.version != b.version or int(a) > int(b):
        return ""
    diff = int(a) ^ int(b)
    prefix = a.max_prefixlen if diff == 0 else a.max_prefixlen - diff.bit_length()
    net = ipaddress.ip_network(f"{a}/{prefix}", strict=False)
    if int(net.network_address) <= int(a) and int(b) <= int(net.broadcast_address):
        return str(net)
    return ""


def _cidr_of(value: Any) -> str:
    """Canonical CIDR of a network, a range or a bare address; ``""`` else."""
    if not isinstance(value, str):
        return ""
    v = value.strip()
    if not v:
        return ""
    try:
        return str(ipaddress.ip_network(v, strict=False))
    except ValueError:
        pass
    m = _RANGE.match(v)
    if m:
        return _range_to_cidr(m.group(1), m.group(2))
    return ""


def _payload_dict(payload: Any) -> dict:
    """A RIPEstat payload as a dict; junk becomes ``{}``, never an error."""
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, (str, bytes)):
        try:
            data = json.loads(payload)
        except (ValueError, TypeError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}
    return {}


def _data_of(payload: Any) -> dict:
    """The ``data`` object of a RIPEstat envelope, or ``{}``."""
    data = _payload_dict(payload).get("data")
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# whois parsing
# ---------------------------------------------------------------------------

# ``network:Field:Value`` lines of an rwhois referral answer.  One physical
# line can carry several fields, separated by two or more spaces
# (``network:City:LOS ANGELES  network:State:CA``), so the value ends at the
# next ``network:`` token or the line end.
_RWHOIS_FIELD = re.compile(
    r"network:([A-Za-z][A-Za-z-]*):(.*?)(?=\s{2,}network:|\r?$)", re.M)
_CLASSIC_KEY = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*)$")

#: (rir, markers) — checked in order against the lowercased response.
_RIR_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("arin", ("arin whois data", "rdap.arin.net", "whois.arin.net")),
    ("ripe", ("ripe database", "whois.ripe.net", "docs.db.ripe.net")),
    ("apnic", ("whois.apnic.net", "apnic whois service")),
    ("lacnic", ("whois.lacnic.net",)),
    ("afrinic", ("whois.afrinic.net", "afrinic whois")),
)


def _detect_rir(text: str, hint: str = "") -> str:
    if hint:
        return hint.strip().lower()
    low = text.lower()
    for name, markers in _RIR_MARKERS:
        if any(marker in low for marker in markers):
            return name
    return ""


def _pick_block(blocks: Sequence[tuple[str, int]], ip: str) -> str:
    """Most specific block covering ``ip``; ties prefer the lower rank."""
    nets: list[tuple[ipaddress._BaseNetwork, int]] = []
    for cidr, rank in blocks:
        try:
            nets.append((ipaddress.ip_network(cidr), rank))
        except ValueError:
            continue
    if not nets:
        return ""
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        if addr is not None:
            covering = [(n, r) for n, r in nets if addr in n]
            if covering:
                nets = covering
    nets.sort(key=lambda item: (-item[0].prefixlen, item[1]))
    return str(nets[0][0])


def _rpsl_blocks(text: str) -> list[dict[str, list[str]]]:
    """Split a whois response into RPSL objects (blank-line separated).

    Each object becomes ``{lowercased key: [values]}``.  A route object's
    ``descr`` describes the route holder, not the address registration, so
    the object boundary is load-bearing: without it a route object's descr
    would make the registration view look like it agrees with BGP.
    """
    blocks: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            if current:
                blocks.append(current)
                current = {}
            continue
        if line[0] in "#%" or line.lower().startswith("network:"):
            continue
        m = _CLASSIC_KEY.match(line)
        if not m:
            continue
        current.setdefault(m.group(1).lower(), []).append(m.group(2).strip())
    if current:
        blocks.append(current)
    return blocks


def _priority(cidr: str, addr: Any) -> int:
    """Prefix length of ``cidr`` when it covers ``addr``; ``-1`` otherwise.

    The score orders the registration blocks of one response: the block
    whose CIDR covers the queried IP most specifically is the one that
    names the entity the address was actually assigned to.
    """
    if addr is None or not cidr:
        return -1
    try:
        net = ipaddress.ip_network(cidr)
    except ValueError:
        return -1
    if addr not in net:
        return -1
    return net.prefixlen


def parse_whois(text: Any, *, ip: str = "", rir: str = "") -> WhoisRecord:
    """Parse one RIR (or rwhois referral) response into a record.

    Tolerant by contract: junk input yields an empty/partial record and
    never raises.  The record keeps only the fields the analyser uses.

    Display fields (org, netname, country, city, state) come from the most
    specific registration block covering ``ip``.  An RIR answer for one
    address lists the allocation chain outer-to-inner (ARIN's parent /19 ->
    sub-delegation /20 -> reassigned customer /20; an APNIC stub -> the
    RIPE netblock it was transferred to), and the downstream-most block is
    the registration that names the entity — that is exactly the case's
    ``NetLab`` rwhois answer and the ARIN ``GTT-ARISK-NET`` sub-delegation.
    Ties go to the first such block in the response; every block's orgs
    stay in ``orgs`` for entity matching.  The rwhois layer, when present,
    is the downstream-most registration of all and outranks every block.
    """
    if not isinstance(text, str) or not text.strip():
        return WhoisRecord(rir=rir)

    addr = None
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None

    rwhois: dict[str, str] = {}
    for m in _RWHOIS_FIELD.finditer(text):
        key = m.group(1).lower()
        value = m.group(2).strip()
        if value and key not in rwhois:
            rwhois[key] = value

    # Display-field candidates sort on (rwhois flag, -priority, class,
    # order): lower wins.  ``class`` breaks ties inside one priority —
    # OrgName beats a free-text descr/owner, which beats the netblock
    # metadata ``Organization:`` and the reassignment's ``CustName:``.
    orgs: list[tuple[int, int, int, int, str]] = []
    netnames: list[tuple[int, int, int, int, str]] = []
    countries: list[tuple[int, int, int, int, str]] = []
    cities: list[tuple[int, int, int, int, str]] = []
    states: list[tuple[int, int, int, int, str]] = []
    order = 0

    def add(bucket: list, value: str, prio: int, *,
            klass: int = 0, is_rwhois: int = 1) -> None:
        nonlocal order
        value = str(value or "").strip()
        if value and not any(item[4] == value for item in bucket):
            bucket.append((is_rwhois, -prio, klass, order, value))
        order += 1

    def pick(bucket: list) -> str:
        return min(bucket, key=lambda item: item[:4])[4] if bucket else ""

    referral = as_name = ""
    explicit_asn: int | None = None
    origin_asn: int | None = None
    route_origins: list[int] = []
    route_cidrs: list[str] = []
    blocks: list[tuple[str, int]] = []

    # The rwhois layer is the downstream-most registration, so its entity
    # and location outrank every RIR block; the RIR layer fills the gaps.
    for key, value in rwhois.items():
        if key in ("org-name", "orgname"):
            add(orgs, value, 0, is_rwhois=0)
        elif key == "ip-network":
            cidr = _cidr_of(value)
            if cidr:
                blocks.append((cidr, 0))
        elif key == "city":
            add(cities, value, 0, is_rwhois=0)
        elif key == "state":
            add(states, value, 0, is_rwhois=0)
        elif key == "country":
            add(countries, value, 0, is_rwhois=0)

    context = ""
    for fields in _rpsl_blocks(text):
        keys = set(fields)
        own = ""
        for key in ("netrange", "inetnum", "cidr"):
            for value in fields.get(key, []):
                parts = re.split(r"[,\s]+", value) if key == "cidr" else [value]
                for part in parts:
                    cidr = _cidr_of(part)
                    if not cidr:
                        continue
                    if not own or ipaddress.ip_network(cidr).prefixlen > \
                            ipaddress.ip_network(own).prefixlen:
                        own = cidr
        if own:
            context = own
        prio = _priority(context, addr)

        if "role" in keys or "person" in keys or "nic-hdl" in keys:
            continue                                   # contact object
        if "route" in keys or "origin" in keys:
            for value in fields.get("route", []):
                cidr = _cidr_of(value)
                if cidr and cidr not in route_cidrs:
                    route_cidrs.append(cidr)
            for value in fields.get("origin", []):
                n = _as_int(value)
                if n is not None and n not in route_origins:
                    route_origins.append(n)
            continue                                   # route object
        for value in fields.get("referralserver", []):
            if not referral:
                referral = value
        if "asnumber" in keys or "aut-num" in keys:    # AS object
            if explicit_asn is None:
                for value in fields.get("asnumber", []) + fields.get("aut-num", []):
                    n = _as_int(value)
                    if n is not None:
                        explicit_asn = n
                        break
            if not as_name:
                for value in fields.get("asname", []) + fields.get("as-name", []):
                    if value:
                        as_name = value
                        break
            for key in ("orgname", "descr", "owner"):
                for value in fields.get(key, []):
                    add(orgs, value, prio, klass=1)
            continue
        # registration object: netblock, OrgName block or rwhois answer
        for value in fields.get("netname", []):
            add(netnames, value, prio)
        for value in fields.get("orgname", []):
            add(orgs, value, prio)
        for key in ("descr", "owner", "org-name"):
            for value in fields.get(key, []):
                add(orgs, value, prio, klass=1)
        for key in ("organization", "custname"):
            for value in fields.get(key, []):
                add(orgs, value, prio, klass=2)
        for value in fields.get("country", []):
            add(countries, value, prio)
        for value in fields.get("city", []):
            add(cities, value, prio)
        for key in ("stateprov", "state"):
            for value in fields.get(key, []):
                add(states, value, prio)
        for value in fields.get("cidr", []):
            for part in re.split(r"[,\s]+", value):
                cidr = _cidr_of(part)
                if cidr:
                    blocks.append((cidr, 1))
        for key in ("netrange", "inetnum"):
            for value in fields.get(key, []):
                cidr = _cidr_of(value)
                if cidr:
                    blocks.append((cidr, 1))
        if origin_asn is None:
            for value in fields.get("originas", []):
                origin_asn = _as_int(value)
                if origin_asn is not None:
                    break

    org_list = [item[4] for item in sorted(orgs, key=lambda item: item[:4])]
    return WhoisRecord(
        rir=_detect_rir(text, rir),
        asn=explicit_asn if explicit_asn is not None else origin_asn,
        as_name=as_name,
        org=org_list[0] if org_list else "",
        orgs=tuple(org_list),
        netname=pick(netnames),
        country=pick(countries),
        city=pick(cities),
        state=pick(states),
        cidr=_pick_block(blocks, ip),
        referral=referral,
        route_cidrs=tuple(route_cidrs),
        route_origins=tuple(route_origins),
    )


# ---------------------------------------------------------------------------
# RIPEstat data.json parsing
# ---------------------------------------------------------------------------


def parse_prefix_overview(payload: Any) -> PrefixView:
    'Parse a RIPEstat ``prefix-overview`` answer for one IP.'
    doc = _payload_dict(payload)
    data = _data_of(doc)
    resource = str(data.get("resource") or "")
    prefix = _cidr_of(data.get("prefix"))
    if not prefix and "/" in resource:
        prefix = _cidr_of(resource)
    asn: int | None = None
    holder = ""
    raw_asns = data.get("asns")
    entries = raw_asns if isinstance(raw_asns, list) else []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        asn = _as_int(entry.get("asn"))
        holder = str(entry.get("holder") or "")
        break
    return PrefixView(
        resource=resource,
        prefix=prefix,
        asn=asn,
        as_name=holder,
        announced=bool(data.get("announced")),
        status=str(doc.get("status") or ""),
    )


def parse_announced_prefixes(payload: Any) -> AnnouncedPrefixes:
    """Parse a RIPEstat ``announced-prefixes`` answer for one AS."""
    data = _data_of(payload)
    asn = _as_int(data.get("asn"))
    if asn is None:
        asn = _as_int(data.get("resource"))
    prefixes: list[str] = []
    raw_prefixes = data.get("prefixes")
    raw = raw_prefixes if isinstance(raw_prefixes, list) else []
    for entry in raw:
        value = entry.get("prefix") if isinstance(entry, dict) else entry
        cidr = _cidr_of(value)
        if cidr and cidr not in prefixes:
            prefixes.append(cidr)
    return AnnouncedPrefixes(asn=asn, prefixes=tuple(prefixes))


def parse_as_overview(payload: Any) -> ASOverview:
    """Parse a RIPEstat ``as-overview`` answer for one AS."""
    data = _data_of(payload)
    asn = _as_int(data.get("asn"))
    if asn is None:
        asn = _as_int(data.get("resource"))
    return ASOverview(
        asn=asn,
        name=str(data.get("name") or ""),
        holder=str(data.get("holder") or ""),
        announced=bool(data.get("announced")),
    )


# ---------------------------------------------------------------------------
# Union view: per-IP record, entity clustering, disagreements
# ---------------------------------------------------------------------------

#: Legal-form tokens that carry no identity; stripped from the end of a
#: normalized entity name so "Arisk Communications inc." and
#: "ARISK-COMMUNICATIONS-INC" are one entity.
_LEGAL_SUFFIXES = frozenset({
    "inc", "incorporated", "llc", "ltd", "limited", "co", "corp",
    "corporation", "company", "gmbh", "kk", "pte", "pty", "plc", "sa",
    "sas", "bv", "nv", "ag", "oy", "ab",
})


def normalize_entity(value: Any) -> str:
    """Case/punctuation-insensitive entity key (legal form stripped).

    ``"ARISK-COMMUNICATIONS-INC - Arisk Communications inc."`` is split on
    the ``" - "`` separator before this is applied, so both halves reduce
    to ``"arisk communications"``.
    """
    s = str(value or "").casefold().replace("&", " and ")
    s = re.sub(r"\([^)]*\)", " ", s)          # drop "(AC-5396)" qualifiers
    s = s.replace(".", "")
    s = re.sub(r"[^a-z0-9]+", " ", s)
    parts = s.split()
    while parts and parts[-1] in _LEGAL_SUFFIXES:
        parts.pop()
    return " ".join(parts)


def entity_variants(value: Any) -> list[str]:
    """Raw entity spellings inside one field (RIPEstat holders are
    ``"AS-NAME - Holder"``)."""
    out: list[str] = []
    for part in re.split(r"\s+-\s+", str(value or "")):
        part = part.strip()
        if part:
            out.append(part)
    return out


def _entity_tokens(values: Iterable[Any]) -> dict[str, list[str]]:
    """Normalized token -> the original spellings that produced it."""
    out: dict[str, list[str]] = {}
    for value in values:
        for variant in entity_variants(value):
            key = normalize_entity(variant)
            if len(key) >= 3:
                out.setdefault(key, []).append(variant)
    return out


def _pick_label(originals: Sequence[str]) -> str:
    """A readable label for a cluster key (prefer mixed case + spaces)."""
    for raw in originals:
        if " " in raw and raw != raw.upper():
            return raw
    return originals[0] if originals else ""


@dataclass(frozen=True)
class IPRecord:
    """One IP in the union view: BGP origin plus whois registration.

    The flat fields (``asn``/``as_name``/``prefix``) are the announced view
    where it exists and the registration view otherwise; ``org``/``country``
    stay registration facts, and the per-view fields keep the evidence the
    disagreements are computed from.
    """

    ip: str
    asn: int | None = None
    as_name: str = ""
    prefix: str = ""
    rir: str = ""
    org: str = ""
    country: str = ""
    city: str = ""
    whois_asn: int | None = None
    whois_route_origins: tuple[int, ...] = ()
    whois_entity: str = ""
    whois_orgs: tuple[str, ...] = ()
    whois_netname: str = ""
    whois_as_name: str = ""
    whois_cidr: str = ""
    bgp_asn: int | None = None
    bgp_entity: str = ""
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "ip": self.ip, "asn": self.asn, "as_name": self.as_name,
            "prefix": self.prefix, "rir": self.rir, "org": self.org,
            "country": self.country, "city": self.city,
            "whois_asn": self.whois_asn,
            "whois_route_origins": list(self.whois_route_origins),
            "whois_entity": self.whois_entity,
            "whois_orgs": list(self.whois_orgs),
            "whois_netname": self.whois_netname,
            "whois_as_name": self.whois_as_name,
            "whois_cidr": self.whois_cidr,
            "bgp_asn": self.bgp_asn, "bgp_entity": self.bgp_entity,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class EntityCluster:
    """Multiple IPs sharing one normalized entity name."""

    key: str
    label: str
    ips: tuple[str, ...]
    views: dict

    def as_dict(self) -> dict:
        return {"key": self.key, "label": self.label,
                "ips": list(self.ips),
                "views": {k: list(v) for k, v in self.views.items()}}


@dataclass(frozen=True)
class ASCluster:
    """One AS origin announcing multiple prefixes across multiple IPs."""

    asn: int
    as_name: str
    ips: tuple[str, ...]
    prefixes: tuple[str, ...]

    def as_dict(self) -> dict:
        return {"asn": self.asn, "as_name": self.as_name,
                "ips": list(self.ips), "prefixes": list(self.prefixes)}


@dataclass(frozen=True)
class Disagreement:
    """One field where the whois and the BGP views tell different stories."""

    ip: str
    field: str
    whois: str
    bgp: str

    def as_dict(self) -> dict:
        return {"ip": self.ip, "field": self.field,
                "whois": self.whois, "bgp": self.bgp}


@dataclass(frozen=True)
class AnalysisResult:
    records: tuple[IPRecord, ...] = ()
    entity_clusters: tuple[EntityCluster, ...] = ()
    as_clusters: tuple[ASCluster, ...] = ()
    disagreements: tuple[Disagreement, ...] = ()

    def as_dict(self) -> dict:
        return {
            "ips": [r.as_dict() for r in self.records],
            "entity_clusters": [c.as_dict() for c in self.entity_clusters],
            "as_clusters": [c.as_dict() for c in self.as_clusters],
            "disagreements": [d.as_dict() for d in self.disagreements],
        }


def merge_record(ip: str, whois: WhoisRecord | None = None,
                 bgp: PrefixView | None = None,
                 errors: Sequence[str] = ()) -> IPRecord:
    """One IP's union record: announced view over registration view."""
    whois = whois or WhoisRecord()
    bgp = bgp or PrefixView()
    return IPRecord(
        ip=ip,
        asn=bgp.asn if bgp.asn is not None else whois.asn,
        as_name=bgp.as_name or whois.as_name,
        prefix=bgp.prefix or whois.cidr,
        rir=whois.rir,
        org=whois.org,
        country=whois.country,
        city=whois.city,
        whois_asn=whois.asn,
        whois_route_origins=whois.route_origins,
        whois_entity=whois.org or whois.netname or whois.as_name,
        whois_orgs=whois.orgs,
        whois_netname=whois.netname,
        whois_as_name=whois.as_name,
        whois_cidr=whois.cidr,
        bgp_asn=bgp.asn,
        bgp_entity=bgp.as_name,
        errors=tuple(errors),
    )


def _whois_tokens(rec: IPRecord) -> dict[str, list[str]]:
    return _entity_tokens([rec.whois_entity, *rec.whois_orgs,
                           rec.whois_netname, rec.whois_as_name])


def _bgp_tokens(rec: IPRecord) -> dict[str, list[str]]:
    return _entity_tokens([rec.bgp_entity])


def _cidrs_overlap(a: str, b: str) -> bool:
    """True when two CIDR strings contain one another (or cannot be read)."""
    try:
        net_a = ipaddress.ip_network(a)
        net_b = ipaddress.ip_network(b)
    except ValueError:
        return True
    if net_a.version != net_b.version:
        return False
    return net_a.subnet_of(net_b) or net_b.subnet_of(net_a)  # type: ignore[arg-type]


def _names_agree(a: str, b: str) -> bool:
    """True when two normalized names denote the same entity.

    Exact equality, or one token sequence is a contiguous run inside the
    other: RIPEstat holders sometimes glue the AS name in front of the
    holder name (``"Westeros Westeros Communications (THAILAND) CO.,
    LTD."``), and that doubling is an upstream artifact, not a
    disagreement.
    """
    if not a or not b:
        return False
    if a == b:
        return True
    tokens_a, tokens_b = a.split(), b.split()
    if len(tokens_a) > len(tokens_b):
        tokens_a, tokens_b = tokens_b, tokens_a
    span = len(tokens_a)
    return any(tokens_b[i:i + span] == tokens_a
               for i in range(len(tokens_b) - span + 1))


def _disagreements(rec: IPRecord) -> list[Disagreement]:
    """Where the two views disagree — the list this tool exists for.

    The entity check compares the two names the record actually shows
    (``whois_entity`` vs ``bgp_entity``), so the list cannot contradict
    the table; the ``orgs`` tuple stays a matching pool for clustering.
    """
    out: list[Disagreement] = []
    whois_tokens = set(_entity_tokens([rec.whois_entity]))
    bgp_tokens = set(_bgp_tokens(rec))
    if rec.whois_entity and rec.bgp_entity and whois_tokens and bgp_tokens \
            and not any(_names_agree(a, b)
                        for a in whois_tokens for b in bgp_tokens):
        out.append(Disagreement(rec.ip, "entity", rec.whois_entity,
                                rec.bgp_entity))
    if rec.whois_asn is not None and rec.bgp_asn is not None \
            and rec.whois_asn != rec.bgp_asn:
        out.append(Disagreement(rec.ip, "asn", f"AS{rec.whois_asn}",
                                f"AS{rec.bgp_asn}"))
    if rec.whois_route_origins and rec.bgp_asn is not None \
            and rec.bgp_asn not in rec.whois_route_origins:
        origins = ", ".join(f"AS{n}" for n in rec.whois_route_origins)
        out.append(Disagreement(rec.ip, "route_origin", origins,
                                f"AS{rec.bgp_asn}"))
    if rec.whois_cidr and rec.prefix \
            and not _cidrs_overlap(rec.whois_cidr, rec.prefix):
        out.append(Disagreement(rec.ip, "prefix", rec.whois_cidr,
                                rec.prefix))
    return out


def build_analysis(records: Sequence[IPRecord]) -> AnalysisResult:
    """Cluster an IP list by entity and by AS, and list the disagreements.

    * entity cluster — one normalized entity name across two or more IPs,
      with the ``views`` map saying which view contributed each IP (the
      case's decisive output);
    * AS cluster — one AS origin announcing two or more distinct prefixes;
    * disagreements — whois vs BGP, per field, kept separate on purpose.
    """
    records = tuple(records)

    groups: dict[str, dict] = {}
    for rec in records:
        for view, tokens in (("whois", _whois_tokens(rec)),
                             ("bgp", _bgp_tokens(rec))):
            for key, originals in tokens.items():
                group = groups.setdefault(key, {
                    "ips": [], "views": {"whois": [], "bgp": []},
                    "originals": [],
                })
                if rec.ip not in group["ips"]:
                    group["ips"].append(rec.ip)
                if rec.ip not in group["views"][view]:
                    group["views"][view].append(rec.ip)
                group["originals"].extend(originals)

    entity_clusters = [
        EntityCluster(key=key, label=_pick_label(group["originals"]),
                      ips=tuple(group["ips"]),
                      views={view: tuple(ips)
                             for view, ips in group["views"].items()})
        for key, group in groups.items() if len(group["ips"]) >= 2
    ]
    entity_clusters.sort(key=lambda c: (-len(c.ips), c.key))

    by_asn: dict[int, dict] = {}
    for rec in records:
        if rec.asn is None:
            continue
        entry = by_asn.setdefault(rec.asn, {
            "as_name": "", "ips": [], "prefixes": []})
        if rec.as_name and not entry["as_name"]:
            entry["as_name"] = rec.as_name
        if rec.ip not in entry["ips"]:
            entry["ips"].append(rec.ip)
        if rec.prefix and rec.prefix not in entry["prefixes"]:
            entry["prefixes"].append(rec.prefix)
    as_clusters = [
        ASCluster(asn=asn, as_name=entry["as_name"],
                  ips=tuple(entry["ips"]), prefixes=tuple(entry["prefixes"]))
        for asn, entry in by_asn.items()
        if len(entry["ips"]) >= 2 and len(entry["prefixes"]) >= 2
    ]
    as_clusters.sort(key=lambda c: (-len(c.ips), c.asn))

    disagreements: list[Disagreement] = []
    for rec in records:
        disagreements.extend(_disagreements(rec))

    return AnalysisResult(records=records,
                          entity_clusters=tuple(entity_clusters),
                          as_clusters=tuple(as_clusters),
                          disagreements=tuple(disagreements))


# ---------------------------------------------------------------------------
# On-disk TTL cache and the lookup client
# ---------------------------------------------------------------------------


class OfflineDataMissing(RuntimeError):
    """Offline mode was asked for a lookup whose cache entry is missing.

    The caller must refuse (and say what is missing) rather than guess.
    """


class Cache:
    """One JSON file per key, with a TTL.

    The cached value is the PARSED record, so a second lookup neither
    fetches nor parses again.  A missing, unreadable or corrupt entry is
    simply a miss — the cache never raises.
    """

    def __init__(self, root: str | Path, ttl: float, *, clock=time.time):
        self.root = Path(root)
        self.ttl = float(ttl)
        self._clock = clock

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
        return self.root / f"{digest}.json"

    def get(self, key: str, *, allow_stale: bool = False) -> dict | None:
        """The cached value, or ``None`` (expired unless ``allow_stale``)."""
        try:
            with open(self._path(key), "r", encoding="utf-8") as fh:
                entry = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(entry, dict) or entry.get("key") != key:
            return None
        data = entry.get("data")
        fetched_at = entry.get("fetched_at")
        if not isinstance(data, dict) or not isinstance(fetched_at, (int, float)):
            return None
        if not allow_stale and self._clock() - fetched_at > self.ttl:
            return None
        return data

    def put(self, key: str, data: dict) -> None:
        """Store one parsed record; a cache that cannot write is a miss."""
        entry = {"key": key, "fetched_at": self._clock(), "data": data}
        path = self._path(key)
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(entry, sort_keys=True), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass


class _RateLimiter:
    """A polite minimum gap between two network lookups."""

    def __init__(self, min_interval: float, *, clock=time.monotonic,
                 sleep=time.sleep):
        self.min_interval = max(0.0, float(min_interval))
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    def wait(self) -> None:
        now = self._clock()
        if self._last is not None and self.min_interval > 0:
            gap = self.min_interval - (now - self._last)
            if gap > 0:
                self._sleep(gap)
                now = self._clock()
        self._last = now


class ClusterClient:
    """Cached, rate-limited lookups: whois + RIPEstat -> union records.

    Network IO is injected (``whois_fetch`` / ``ripestat_fetch``), so the
    whole pipeline runs offline in tests and in ``offline=True`` mode.
    """

    def __init__(self, cache: Cache, *, offline: bool = False,
                 min_interval: float = 1.0, whois_fetch=None,
                 ripestat_fetch=None, sleep=time.sleep):
        self.cache = cache
        self.offline = bool(offline)
        self.whois_fetch = whois_fetch or fetch_whois_text
        self.ripestat_fetch = ripestat_fetch or fetch_ripestat
        self.limiter = _RateLimiter(min_interval, sleep=sleep)

    def _cached(self, key: str, fetch: Callable[[], str],
                parse: Callable[[str], Any]) -> dict:
        hit = self.cache.get(key, allow_stale=self.offline)
        if hit is not None:
            return hit
        if self.offline:
            raise OfflineDataMissing(key)
        self.limiter.wait()
        data = parse(fetch()).as_dict()
        self.cache.put(key, data)
        return data

    def whois(self, ip: str) -> WhoisRecord:
        data = self._cached(
            f"whois:{ip}",
            lambda: self.whois_fetch(ip),
            lambda text: parse_whois(text, ip=ip))
        return WhoisRecord.from_dict(data)

    def prefix_view(self, ip: str) -> PrefixView:
        data = self._cached(
            f"ripestat:prefix-overview:{ip}",
            lambda: self.ripestat_fetch("prefix-overview", ip),
            lambda text: parse_prefix_overview(text))
        return PrefixView.from_dict(data)

    def record(self, ip: str) -> IPRecord:
        """The union record of one IP; a failed lookup is recorded, not fatal.

        In offline mode a missing cache entry raises
        :class:`OfflineDataMissing` instead of degrading to a guess.
        """
        errors: list[str] = []
        whois: WhoisRecord | None = None
        bgp: PrefixView | None = None
        try:
            whois = self.whois(ip)
        except OfflineDataMissing:
            raise
        except Exception as exc:            # lookup failure -> partial record
            errors.append(f"whois: {type(exc).__name__}: {exc}")
        try:
            bgp = self.prefix_view(ip)
        except OfflineDataMissing:
            raise
        except Exception as exc:
            errors.append(f"ripestat: {type(exc).__name__}: {exc}")
        return merge_record(ip, whois, bgp, errors=errors)

    def analyze(self, ips: Iterable[str]) -> AnalysisResult:
        """Union-view every IP, then cluster (order of ``ips`` is kept)."""
        return build_analysis([self.record(ip) for ip in ips])

    def missing_offline_keys(self, ips: Iterable[str]) -> list[str]:
        """The cache keys an offline ``analyze`` would still need.

        The CLI lists these and refuses instead of guessing; stale entries
        count as present (offline mode reads them by design).
        """
        missing: list[str] = []
        for ip in ips:
            for key in (f"whois:{ip}", f"ripestat:prefix-overview:{ip}"):
                if self.cache.get(key, allow_stale=True) is None:
                    missing.append(key)
        return missing


# ---------------------------------------------------------------------------
# Network IO — the only functions in this module that leave the process
# ---------------------------------------------------------------------------

IANA_WHOIS = "whois.iana.org"
WHOIS_TIMEOUT = 20.0
RIPESTAT_TIMEOUT = 20.0
RIPESTAT_URL = ("https://stat.ripe.net/data/{endpoint}/data.json"
                "?resource={resource}")

_RWHOIS_REF = re.compile(r"(?im)^referralserver:\s*(\S+)")


def _whois_query(server: str, query: str, *, port: int = 43,
                 timeout: float = WHOIS_TIMEOUT) -> str:
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode("ascii", "ignore"))
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def _socket_whois(ip: str, *, timeout: float = WHOIS_TIMEOUT) -> str:
    """Stdlib fallback: IANA -> RIR -> one referral (rwhois best effort)."""
    iana = _whois_query(IANA_WHOIS, ip, timeout=timeout)
    refer = ""
    for line in iana.splitlines():
        low = line.lower()
        if low.startswith(("refer:", "whois:")):
            refer = line.split(":", 1)[1].strip()
            break
    if not refer:
        return iana
    rir_text = _whois_query(refer, ip, timeout=timeout)
    text = iana + "\n" + rir_text
    m = _RWHOIS_REF.search(rir_text)
    if not m:
        return text
    url = urllib.parse.urlparse(m.group(1))
    if url.scheme != "rwhois" or not url.hostname:
        return text
    try:
        rwhois = _whois_query(url.hostname, ip,
                              port=url.port or 4321, timeout=timeout)
    except OSError:
        return text
    return text + "\n" + rwhois


def fetch_whois_text(ip: str, *, timeout: float = WHOIS_TIMEOUT) -> str:
    """RIR whois text for one IP.

    Prefers the system ``whois`` client when present: it walks IANA -> RIR
    and follows the ``rwhois://`` referral that carries the downstream
    customer (the case's ``NetLab`` answer).  Falls back to a stdlib
    socket walk, which follows the same referral on a best-effort basis.
    """
    client = shutil.which("whois")
    if client:
        proc = subprocess.run([client, ip], capture_output=True, text=True,
                              timeout=timeout)
        return proc.stdout or ""
    return _socket_whois(ip, timeout=timeout)


def fetch_ripestat(endpoint: str, resource: str, *,
                   timeout: float = RIPESTAT_TIMEOUT) -> str:
    """One RIPEstat ``data.json`` response body, with the canonical UA."""
    url = RIPESTAT_URL.format(endpoint=urllib.parse.quote(endpoint, safe=""),
                              resource=urllib.parse.quote(resource, safe=""))
    req = urllib.request.Request(url, headers={
        "User-Agent": user_agent(), "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")
