"""Scope guard tests — the suffix-bypass cases are the point.

Run:  python3 tests/test_scope.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko.scope import ScopeGuard  # noqa: E402


def guard(in_scope=None, out_of_scope=None, resolver=None) -> ScopeGuard:
    return ScopeGuard(
        in_scope or ["example.com", "10.0.0.0/24"],
        out_of_scope or ["partner.example.com"],
        resolver=resolver,
    )


class TestScopeGuard(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(guard().check_host("example.com").allowed)

    def test_subdomain(self):
        self.assertTrue(guard().check_host("api.example.com").allowed)

    def test_deep_subdomain(self):
        self.assertTrue(guard().check_host("a.b.c.example.com").allowed)

    def test_notexample_rejected(self):
        # label-boundary: "notexample.com" is NOT a subdomain of "example.com"
        self.assertFalse(guard().check_host("notexample.com").allowed)

    def test_evil_tld_rejected(self):
        # "example.com.evil.tld" is a subdomain of evil.tld, not example.com
        self.assertFalse(guard().check_host("example.com.evil.tld").allowed)

    def test_out_of_scope_wins(self):
        self.assertFalse(guard().check_host("partner.example.com").allowed)

    def test_ip_in_cidr(self):
        self.assertTrue(guard().check_ip("10.0.0.5").allowed)

    def test_ip_out_cidr(self):
        self.assertFalse(guard().check_ip("10.1.0.5").allowed)

    def test_url(self):
        self.assertTrue(guard().check_url("https://api.example.com/x?y=1").allowed)

    def test_url_with_port(self):
        self.assertTrue(guard().check_url("https://example.com:8443/x").allowed)

    def test_redirect_chain_ok(self):
        self.assertTrue(guard().check_redirect_chain(
            ["https://a.example.com", "https://b.example.com"]).allowed)

    def test_redirect_chain_offscope_hop(self):
        self.assertFalse(guard().check_redirect_chain(
            ["https://a.example.com", "https://evil.com"]).allowed)

    def test_san_ok(self):
        self.assertTrue(guard().check_sans(["*.example.com"]).allowed)

    def test_san_bad(self):
        self.assertFalse(guard().check_sans(["*.evil.com"]).allowed)

    def test_resolved_ip_in_scope(self):
        g = guard(resolver=lambda h: ["10.0.0.5"])
        self.assertTrue(g.check_host("some.internal.host").allowed)

    def test_resolved_ip_out_of_scope(self):
        g = guard(resolver=lambda h: ["8.8.8.8"])
        self.assertFalse(g.check_host("some.internal.host").allowed)

    def test_empty_host(self):
        self.assertFalse(guard().check_host("").allowed)


class TestScopeGuardResolution(unittest.TestCase):
    """F03: a domain match no longer short-circuits resolution, and the
    resolution path uses ALL-records semantics instead of ANY."""

    def test_domain_hit_still_resolves_and_out_list_wins(self):
        g = ScopeGuard(["example.com"], ["10.0.0.0/8"], resolver=lambda h: ["10.1.2.3"])
        d = g.check_host("example.com")
        self.assertFalse(d.allowed, "in-scope domain resolved into an out-of-scope CIDR")

    def test_domain_hit_with_clean_resolution_is_allowed(self):
        g = ScopeGuard(["example.com"], ["10.0.0.0/8"],
                       resolver=lambda h: ["93.184.216.34"])
        d = g.check_host("example.com")
        self.assertTrue(d.allowed, d.reason)
        self.assertEqual(d.detail["resolved_ips"], ["93.184.216.34"])

    def test_bind_ip_is_returned_for_the_connection(self):
        g = ScopeGuard(["example.com"], [], resolver=lambda h: ["93.184.216.34", "93.184.216.35"])
        d = g.check_host("example.com")
        self.assertTrue(d.allowed)
        self.assertEqual(d.detail["bind_ip"], "93.184.216.34")

    def test_every_resolved_address_must_be_in_scope(self):
        # ANY semantics let one in-scope A record vouch for the rest.
        g = ScopeGuard(["10.0.0.0/24"], [], resolver=lambda h: ["10.0.0.5", "8.8.8.8"])
        self.assertFalse(g.check_host("app.internal").allowed)
        g2 = ScopeGuard(["10.0.0.0/24"], [], resolver=lambda h: ["10.0.0.5", "10.0.0.9"])
        self.assertTrue(g2.check_host("app.internal").allowed)

    def test_resolution_is_cached_for_the_ttl(self):
        calls = []

        def resolver(host):
            calls.append(host)
            return ["10.0.0.5"]

        g = ScopeGuard(["10.0.0.0/24"], [], resolver=resolver, dns_ttl=60)
        g.check_host("app.internal")
        g.check_host("app.internal")
        self.assertEqual(len(calls), 1, "resolution was not cached")

    def test_expired_cache_re_resolves(self):
        calls = []

        def resolver(host):
            calls.append(host)
            return ["10.0.0.5"]

        g = ScopeGuard(["10.0.0.0/24"], [], resolver=resolver, dns_ttl=-1)
        g.check_host("app.internal")
        g.check_host("app.internal")
        self.assertEqual(len(calls), 2)

    def test_check_asset_for_non_http_actions(self):
        g = ScopeGuard(["example.com", "10.0.0.0/24"], ["evil.example.com"],
                       resolver=lambda h: [])
        self.assertTrue(g.check_asset(
            {"id": "a1", "value": "https://api.example.com"}).allowed)
        self.assertTrue(g.check_asset({"id": "a2", "value": "10.0.0.9"}).allowed)
        self.assertTrue(g.check_asset(
            {"id": "a3", "value": "api.example.com", "ip": "10.0.0.9"}).allowed)
        self.assertFalse(g.check_asset({"id": "a4", "value": "evil.example.com"}).allowed)
        self.assertFalse(g.check_asset({"id": "a5", "value": "evil.com"}).allowed)
        # a target we cannot check is refused, not assumed safe
        self.assertFalse(g.check_asset({"id": "a6", "value": ""}).allowed)
        self.assertFalse(g.check_asset(None).allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
