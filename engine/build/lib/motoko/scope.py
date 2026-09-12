"""Scope guard — post-resolution checks, NOT string-suffix matching.

grok review missed-item #1: a suffix matcher lets ``notshop.invalid`` and
``shop.invalid.attacker.tld`` through. This guard matches on **label
boundaries** for domains and on parsed IP membership for CIDRs, checks every
hop of a redirect chain, and checks certificate SANs. ``out_of_scope`` wins
over ``in_scope``.

F03 (kimi S4 / qwen SEC-04): a name being in scope is NOT sufficient —
``shop.invalid`` can resolve into a CIDR that is explicitly out of scope, and
a host with several A records must not be cleared because ONE of them is in
scope. So:

* every resolution result is checked against the out list;
* on the discovery path (no in-scope domain match) ALL results must be in
  scope (∀, not ∃);
* results are cached per host for a short TTL, and the guard hands back the
  address it cleared (``detail["bind_ip"]``) so the caller connects to what
  was actually checked instead of re-resolving (TOCTOU window).

DNS resolution is injectable so the logic is unit-testable without a live
resolver; the orchestrator passes the real ``socket`` resolver.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    detail: dict = field(default_factory=dict)


def _try_ip(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _try_network(s: str):
    try:
        return ipaddress.ip_network(s.strip(), strict=False)
    except ValueError:
        return None


def _domain_matches(host: str, domain: str) -> bool:
    """Label-boundary match: ``api.shop.invalid`` matches ``shop.invalid``,
    but ``notshop.invalid`` and ``shop.invalid.evil.tld`` do NOT."""
    h = (host or "").lower().rstrip(".")
    d = (domain or "").lower().rstrip(".")
    if not h or not d:
        return False
    return h == d or h.endswith("." + d)


def default_resolver(host: str) -> list[str]:
    """Resolve a hostname to IPv4/IPv6 addresses (real DNS)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


class ScopeGuard:
    def __init__(self, in_scope: list[str] | None = None,
                 out_of_scope: list[str] | None = None,
                 resolver=None, dns_ttl: float = 30.0):
        in_scope = in_scope or []
        out_of_scope = out_of_scope or []
        self.in_domains: list[str] = []
        self.in_ips: list[ipaddress._BaseAddress] = []
        self.in_cidrs: list[ipaddress._BaseNetwork] = []
        self.out_domains: list[str] = []
        self.out_ips: list[ipaddress._BaseAddress] = []
        self.out_cidrs: list[ipaddress._BaseNetwork] = []
        self.resolver = resolver or default_resolver
        self.dns_ttl = float(dns_ttl)
        self._dns_cache: dict[str, tuple[float, list[str]]] = {}

        for s in in_scope:
            ip = _try_ip(s)
            net = _try_network(s)
            if ip:
                self.in_ips.append(ip)
            elif net:
                self.in_cidrs.append(net)
            else:
                self.in_domains.append(s)
        for s in out_of_scope:
            ip = _try_ip(s)
            net = _try_network(s)
            if ip:
                self.out_ips.append(ip)
            elif net:
                self.out_cidrs.append(net)
            else:
                self.out_domains.append(s)

    # -- primitives ----------------------------------------------------
    def _excluded(self, ip: str) -> str | None:
        """Return a reason when ``ip`` is explicitly out of scope, else None."""
        addr = _try_ip(ip)
        if addr is None:
            return f"not an IP address: {ip!r}"
        for n in self.out_cidrs:
            if addr in n:
                return f"IP {ip} in out-of-scope CIDR {n}"
        for a in self.out_ips:
            if addr == a:
                return f"IP {ip} is out of scope"
        return None

    def check_ip(self, ip: str) -> ScopeDecision:
        addr = _try_ip(ip)
        if addr is None:
            return ScopeDecision(False, f"not an IP address: {ip!r}")
        # out-of-scope wins over a matching in-scope CIDR
        excluded = self._excluded(ip)
        if excluded:
            return ScopeDecision(False, excluded)
        for n in self.in_cidrs:
            if addr in n:
                return ScopeDecision(True, f"IP {ip} in CIDR {n}")
        for a in self.in_ips:
            if addr == a:
                return ScopeDecision(True, f"IP {ip} in scope")
        return ScopeDecision(False, f"IP {ip} not in any in-scope CIDR/address")

    def _resolve(self, host: str) -> list[str]:
        """Resolve with a short per-host cache (F03: query volume + TOCTOU)."""
        now = time.monotonic()
        hit = self._dns_cache.get(host)
        if hit is not None and (now - hit[0]) < self.dns_ttl:
            return list(hit[1])
        ips = list(self.resolver(host) or [])
        self._dns_cache[host] = (now, ips)
        return ips

    def check_host(self, host: str) -> ScopeDecision:
        h = (host or "").lower().rstrip(".")
        if not h:
            return ScopeDecision(False, "empty host")
        # out-of-scope first
        for d in self.out_domains:
            if _domain_matches(h, d):
                return ScopeDecision(False, f"host {h} matches out-of-scope {d}")
        # literal IP?
        if _try_ip(h) is not None:
            return self.check_ip(h)
        # in-scope domain label match — STILL resolve (F03): an authorized
        # name may point at an unauthorized address.
        if any(_domain_matches(h, d) for d in self.in_domains):
            ips = self._resolve(h)
            for ip in ips:
                excluded = self._excluded(ip)
                if excluded:
                    return ScopeDecision(
                        False, f"host {h} matches an in-scope domain but {excluded}")
            return ScopeDecision(
                True, f"host {h} matches in-scope domain (resolved {ips or 'nothing'})",
                detail={"resolved_ips": ips, "bind_ip": ips[0] if ips else None})
        # discovery path: no domain match, so EVERY resolved address must be
        # in scope (any single in-scope A record no longer vouches for the rest)
        ips = self._resolve(h)
        if not ips:
            return ScopeDecision(
                False, f"host {h} not in scope (no domain match, no resolution)")
        for ip in ips:
            d = self.check_ip(ip)
            if not d.allowed:
                return ScopeDecision(False, f"host {h} resolves to {ip}: {d.reason}")
        return ScopeDecision(
            True, f"host {h} resolves only to in-scope addresses",
            detail={"resolved_ips": ips, "bind_ip": ips[0]})

    def check_asset(self, asset: dict | None) -> ScopeDecision:
        """Structured-target check for non-HTTP actions (F01).

        Takes the resolved asset entity (the orchestrator looks the id up) and
        checks whichever target it carries: URL, IP, or hostname. An asset
        without a checkable target is refused, never assumed safe.
        """
        if not asset:
            return ScopeDecision(False, "asset not found")
        value = str(asset.get("value") or "")
        if value.startswith(("http://", "https://")):
            return self.check_url(value)
        ip = asset.get("ip")
        if ip:
            return self.check_ip(str(ip))
        if value:
            return self.check_ip(value) if _try_ip(value) else self.check_host(value)
        return ScopeDecision(False, f"asset {asset.get('id')!r} has no checkable target")

    def check_url(self, url: str) -> ScopeDecision:
        if not url:
            return ScopeDecision(False, "empty url")
        u = urlparse(url)
        host = u.netloc.split("@")[-1]
        # strip port if present
        if ":" in host and not host.startswith("["):
            host = host.rsplit(":", 1)[0]
        elif host.startswith("[") and "]" in host:
            host = host[1:host.index("]")]
        return self.check_host(host)

    def check_redirect_chain(self, urls: list[str]) -> ScopeDecision:
        """Every hop must be in scope — one out-of-scope hop rejects the chain."""
        for url in urls:
            d = self.check_url(url)
            if not d.allowed:
                return ScopeDecision(False, f"redirect hop {url!r} out of scope: {d.reason}")
        return ScopeDecision(True, f"redirect chain ({len(urls)} hops) in scope")

    def check_sans(self, sans: list[str]) -> ScopeDecision:
        """Certificate SAN check: at least one SAN must match an in-scope domain."""
        if not sans:
            return ScopeDecision(False, "no SANs to check")
        for san in sans:
            for d in self.in_domains:
                if _domain_matches(san, d):
                    return ScopeDecision(True, f"SAN {san} matches in-scope {d}")
        return ScopeDecision(False, f"no SAN matches in-scope domains: {sans[:3]}")
