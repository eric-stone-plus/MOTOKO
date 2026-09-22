'Scope guard — post-resolution checks, NOT string-suffix matching.\n\n* every resolution result is checked against the out list;\n* on the discovery path (no in-scope domain match) ALL results must be in\n  scope (∀, not ∃);\n* results are cached per host for a short TTL, and the guard hands back the\n  address it cleared (``detail["bind_ip"]``) so the caller connects to what\n  was actually checked instead of re-resolving (TOCTOU window).\n\nDNS resolution is injectable so the logic is unit-testable without a live\nresolver; the orchestrator passes the real ``socket`` resolver.\n'

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
    if d.startswith("*.") and "*" not in d[2:]:
        suffix = d[2:]
        if not h.endswith("." + suffix):
            return False
        prefix = h[:-(len(suffix) + 1)]
        return bool(prefix) and "." not in prefix
    return h == d or h.endswith("." + d)


def _san_covers(san: str, domain: str) -> bool:
    """Return whether a certificate SAN covers a scope-domain name.

    Certificate wildcards match exactly one left-most label.  Treating the
    literal ``*`` as an ordinary label misses an excluded name such as
    ``partner.example.com`` when the certificate presents ``*.example.com``.
    """
    s = (san or "").lower().rstrip(".")
    d = (domain or "").lower().rstrip(".")
    if s.startswith("*.") and "*" not in s[2:]:
        suffix = s[2:]
        if d == suffix:
            # The wildcard is subordinate to the scoped base.  A certificate
            # for ``*.example.com`` is relevant to an ``example.com`` scope
            # even though the wildcard does not cover the apex itself.
            return True
        if not d.endswith("." + suffix):
            return False
        prefix = d[:-(len(suffix) + 1)]
        return bool(prefix) and "." not in prefix
    return _domain_matches(s, d)


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
                return ScopeDecision(True, f"IP {ip} in CIDR {n}",
                                     detail={"bind_ip": str(addr)})
        for a in self.in_ips:
            if addr == a:
                return ScopeDecision(True, f"IP {ip} in scope",
                                     detail={"bind_ip": str(addr)})
        return ScopeDecision(False, f"IP {ip} not in any in-scope CIDR/address")

    def _resolve(self, host: str) -> list[str]:
        ''
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
        '        Takes the resolved asset entity (the orchestrator looks the id up) and\n        checks whichever target it carries: URL, IP, or hostname. An asset\n        without a checkable target is refused, never assumed safe.\n        '
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
        """Require an in-scope SAN while honoring explicit exclusions first.

        A certificate can cover both an authorized host and a deliberately
        excluded sibling.  Treating the first matching SAN as sufficient would
        let that excluded name back into the action path.  SANs are therefore
        evaluated with the same precedence as ``check_host``: any explicit
        out-of-scope match rejects the certificate, then at least one
        in-scope match is required.
        """
        if not sans:
            return ScopeDecision(False, "no SANs to check")
        normalized = [str(san).strip().lower().rstrip(".")
                      for san in sans if isinstance(san, str) and san.strip()]
        for san in normalized:
            for d in self.out_domains:
                # An excluded SAN must be present as a name.  A wildcard SAN
                # describes its covered children but does not itself assert
                # the excluded base name; treating it as every sibling would
                # make a normal ``*.example.com`` certificate unusable for an
                # otherwise in-scope ``example.com`` engagement.
                if _domain_matches(san, d):
                    return ScopeDecision(
                        False, f"SAN {san} matches out-of-scope {d}")
        for san in normalized:
            for d in self.in_domains:
                if _san_covers(san, d):
                    return ScopeDecision(True, f"SAN {san} matches in-scope {d}")
        return ScopeDecision(False, f"no SAN matches in-scope domains: {normalized[:3]}")
