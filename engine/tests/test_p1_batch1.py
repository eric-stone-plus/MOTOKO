"""P1 batch-1 regressions: M1-asset-link, G9 ACT same-command dedup,
G10 amass banner/JSON parser shapes.

Run:  python3 tests/test_p1_batch1.py
"""

from __future__ import annotations

import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
RULES = Path(__file__).resolve().parents[1] / "rules"

from motoko import db, schema  # noqa: E402
from motoko.cli import ingest_strix_findings  # noqa: E402
from motoko.orchestrator import Orchestrator, _command_fingerprint  # noqa: E402
from motoko.parsers import get_parser  # noqa: E402


class TestM1AssetLink(unittest.TestCase):
    """M1-asset-link: strix ingest must link findings to their asset
    through the SHARED lookup, so the class fact reaches _fact_view."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.eng = "eng-m1"
        db.init_engagement(self.root, self.eng, name="m1",
                           in_scope=["example.com.cn"], out_of_scope=[])
        self.w = db.Database(db.engagement_dir(self.root, self.eng) / "graph.db")

    def tearDown(self):
        self.w.close()
        self.tmp.cleanup()

    def _seed_asset(self, value="https://job.example.com.cn"):
        self.w.upsert_entity({
            "id": "ast_job", "kind": "asset", "engagement_id": self.eng,
            "state": "active", "type": "url", "value": value,
            "frontier": False,
        })

    def _finding(self, url="https://job.example.com.cn/login"):
        return {"class": "vuln.strix_confirmed", "title": "broken auth",
                "url": url, "severity": "high"}

    def test_ingest_links_finding_to_asset(self):
        self._seed_asset()
        kept, dups = ingest_strix_findings(self.w, [self._finding()], self.eng)
        self.assertEqual((kept, dups), (1, 0))
        rows = self.w.query_entities(kind="finding", engagement_id=self.eng)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("asset_id"), "ast_job",
                         "finding was not linked to its asset")
        edges = self.w.get_edges(from_id=rows[0]["id"], rel="discovered_on")
        self.assertEqual(len(edges), 1, "no discovered_on edge written")
        self.assertEqual(edges[0]["to_id"], "ast_job")
        self.assertIn(edges[0]["rel"], schema.EDGE_RELS)

    def test_class_fact_reaches_fact_view(self):
        self._seed_asset()
        ingest_strix_findings(self.w, [self._finding()], self.eng)
        self.w.commit()
        self.w.close()
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES)
        try:
            assets = orch.writer.query_entities(kind="asset",
                                                engagement_id=self.eng)
            self.assertEqual(len(assets), 1)
            facts = orch._fact_view(assets[0], assets)
        finally:
            orch.close()
        self.assertEqual(facts.get("class"), "vuln.strix_confirmed",
                         "strix class fact invisible to _fact_view")

    def test_finding_without_matching_asset_gets_no_link(self):
        kept, _ = ingest_strix_findings(
            self.w, [self._finding(url="https://elsewhere.example.org")],
            self.eng)
        self.assertEqual(kept, 1)
        rows = self.w.query_entities(kind="finding", engagement_id=self.eng)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0].get("asset_id"))
        self.assertEqual(self.w.get_edges(rel="discovered_on"), [])

    def test_orchestrator_delegates_to_shared_module(self):
        # anti-copy-paste regression: the orchestrator method must call the
        # shared helper, not carry its own lookup loop.
        src = inspect.getsource(Orchestrator._asset_id_for_url)
        self.assertIn("asset_link.asset_id_for_url", src)
        self.assertNotIn("for a in", src, "lookup loop duplicated")

    def test_shared_lookup_matches_orchestrator_semantics(self):
        self._seed_asset("https://api.example.com")
        import motoko.asset_link as _al
        orch = Orchestrator(self.eng, root=self.root, rules_dir=RULES)
        try:
            shared = lambda u: _al.asset_id_for_url(  # noqa: E731
                orch.writer, u, engagement_id=self.eng)
            self.assertEqual(shared("https://api.example.com/x"), "ast_job")
            self.assertEqual(shared("http://api.example.com:8080/y"),
                             "ast_job")
            self.assertIsNone(shared("https://other.example.com"))
        finally:
            orch.close()

    def test_docstring_reports_the_m1_delta_as_fixed(self):
        doc = inspect.getdoc(ingest_strix_findings) or ""
        self.assertIn("_asset_id_for_url", doc)
        self.assertIn("discovered_on", doc)


class TestActCommandDedup(unittest.TestCase):
    """G9: two identical commands in one cycle -> the second records an
    act.dedup event and never becomes a tool_run; a different target is
    not deduped; the seen-set does not survive into the next cycle."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="motoko-dedup-"))
        self.eng = "eng-dedup"
        db.init_engagement(self.root, self.eng, name="dedup",
                           in_scope=["example.com"], out_of_scope=[])

    def tearDown(self):
        pass

    def _orch(self, calls):
        return Orchestrator(self.eng, root=self.root, rules_dir=RULES,
                            executor=lambda h, a: calls.append(a),
                            resolver=lambda h: [])

    def _counts(self, orch):
        dedup = orch.writer.conn.execute(
            "SELECT COUNT(*) c FROM events WHERE kind='act.dedup'"
        ).fetchone()["c"]
        runs = orch.writer.conn.execute(
            "SELECT COUNT(*) c FROM tool_run").fetchone()["c"]
        return dedup, runs

    def _hyp(self, hyp_id, url):
        return {"id": hyp_id, "kind": "hypothesis", "engagement_id": self.eng,
                "state": "proposed", "url": url,
                "actions": [{"tool": "nuclei", "cmd": "nuclei -u {url}"}]}

    def test_second_identical_command_is_deduped(self):
        calls: list = []
        orch = self._orch(calls)
        try:
            h1 = self._hyp("hyp_d1", "https://app.example.com/x")
            h2 = self._hyp("hyp_d2", "https://app.example.com/x")
            orch.writer.upsert_entity(h1)
            orch.writer.upsert_entity(h2)
            orch._act([h1, h2])
            dedup, runs = self._counts(orch)
            row = orch.writer.conn.execute(
                "SELECT entity_id, payload FROM events WHERE kind='act.dedup'"
            ).fetchone()
        finally:
            orch.close()
        self.assertEqual(runs, 1, "duplicate command produced a tool_run")
        self.assertEqual(len(calls), 1, "executor ran the duplicate")
        self.assertEqual(dedup, 1, "no act.dedup event recorded")
        self.assertEqual(row["entity_id"], "hyp_d2")
        payload = json.loads(row["payload"])
        self.assertEqual(payload["tool"], "nuclei")
        self.assertEqual(payload["target"], {"url": "https://app.example.com/x"})
        self.assertIn("app.example.com", payload["command"])

    def test_same_target_different_hypothesis_wedged_state_retires(self):
        # the deduped hypothesis must not stall in 'testing' forever: with
        # zero started runs it retires as done (all-blocked path).
        orch = self._orch([])
        try:
            h1 = self._hyp("hyp_r1", "https://app.example.com/x")
            h2 = self._hyp("hyp_r2", "https://app.example.com/x")
            orch.writer.upsert_entity(h1)
            orch.writer.upsert_entity(h2)
            orch._act([h1, h2])
            h2_after = orch.writer.get_entity("hyp_r2")
        finally:
            orch.close()
        self.assertEqual(h2_after.get("state"), "done")

    def test_different_targets_are_not_deduped(self):
        calls: list = []
        orch = self._orch(calls)
        try:
            h1 = self._hyp("hyp_t1", "https://app.example.com/x")
            h2 = self._hyp("hyp_t2", "https://api.example.com/y")
            orch.writer.upsert_entity(h1)
            orch.writer.upsert_entity(h2)
            orch._act([h1, h2])
            dedup, runs = self._counts(orch)
        finally:
            orch.close()
        self.assertEqual(runs, 2, "a different target was wrongly deduped")
        self.assertEqual(len(calls), 2)
        self.assertEqual(dedup, 0)

    def test_targetless_argv_does_not_collapse_distinct_targets(self):
        # the command carries no {url} placeholder, so identical argv cannot
        # witness the target: the STRUCTURED target must still separate the
        # fingerprints (two different hosts each get their run).
        calls: list = []
        orch = self._orch(calls)
        try:
            hyps = []
            for i, url in enumerate(("https://app.example.com",
                                     "https://api.example.com")):
                h = {"id": f"hyp_np{i}", "kind": "hypothesis",
                     "engagement_id": self.eng, "state": "proposed", "url": url,
                     "actions": [{"tool": "nuclei", "cmd": "nuclei -l list.txt"}]}
                orch.writer.upsert_entity(h)
                hyps.append(h)
            orch._act(hyps)          # same cycle: one shared seen-set
            dedup, runs = self._counts(orch)
        finally:
            orch.close()
        self.assertEqual(runs, 2, "distinct targets collapsed by argv only")
        self.assertEqual(dedup, 0)

    def test_seen_set_is_per_cycle(self):
        calls: list = []
        orch = self._orch(calls)
        try:
            h = self._hyp("hyp_c1", "https://app.example.com/x")
            orch.writer.upsert_entity(h)
            orch._act([h])
            orch._act([h])          # next cycle: dedup set must be fresh
            dedup, runs = self._counts(orch)
        finally:
            orch.close()
        self.assertEqual(runs, 2, "next-cycle re-run was blocked")
        self.assertEqual(dedup, 0)

    def test_fingerprint_distinguishes_target_and_argv(self):
        a = _command_fingerprint("nuclei", ("url", "https://a.example.com"),
                                 ["nuclei", "-u", "https://a.example.com"])
        b = _command_fingerprint("nuclei", ("url", "https://b.example.com"),
                                 ["nuclei", "-u", "https://b.example.com"])
        c = _command_fingerprint("nuclei", ("url", "https://a.example.com"),
                                 ["nuclei", "-u", "https://a.example.com", "-silent"])
        d = _command_fingerprint("nuclei", ("url", "https://a.example.com"),
                                 ["nuclei", "-u", "https://a.example.com"])
        self.assertNotEqual(a, b, "different targets collided")
        self.assertNotEqual(a, c, "different argv collided")
        self.assertEqual(a, d, "identical commands did not collide")
        e = _command_fingerprint("httpx", ("url", "https://a.example.com"),
                                 ["nuclei", "-u", "https://a.example.com"])
        self.assertNotEqual(a, e, "different tools collided")


class TestAmassParserShapes(unittest.TestCase):
    """G10: amass enum text-banner, -json-per-line, and bare-line forms
    must all yield the discovered subdomains."""

    def setUp(self):
        self.p = get_parser("amass")
        self.assertIsNotNone(self.p)

    def _values(self, out):
        return [a["value"] for a in self.p.parse(out, action={}).assets]

    def test_text_banner_form(self):
        out = "\n".join([
            "[banner] OWASP Amass v3.23.0 https://owasp.org/www-project-amass",
            "[banner] Data sources: 45",
            "www.example.com (A) 1.2.3.4",
            "api.example.com (A) 1.2.3.4, 5.6.7.8",
            "mail.example.com (MX) mx1.example.net",
            "vpn.example.com (CNAME) edge.example.net",
        ])
        values = self._values(out)
        for host in ("www.example.com", "api.example.com",
                     "mail.example.com", "vpn.example.com"):
            self.assertIn(host, values)
        parsed = self.p.parse(out, action={})
        self.assertNotIn("v3.23.0", values, "version token minted as host")
        self.assertNotIn("1.2.3.4", values, "address minted as host")
        self.assertNotIn("mx1.example.net", values,
                         "annotation target minted as host")
        self.assertTrue(parsed.dead_letter,
                        "banner lines vanished (silently dropped)")

    def test_prefixed_status_line_with_a_name(self):
        values = self._values(
            "[enum] found sub.example.com via crtsh")
        self.assertIn("sub.example.com", values)

    def test_json_lines_form(self):
        out = "\n".join([
            '{"name":"www.example.com","domain":"example.com",'
            '"addresses":[{"ip":"1.2.3.4","asn":15169,"desc":"GOOGLE"}],'
            '"source":"Census"}',
            '{"name":"vpn.example.com","domain":"example.com",'
            '"addresses":[],"source":"Census"}',
            "not json at all",
        ])
        values = self._values(out)
        self.assertIn("www.example.com", values)
        self.assertIn("vpn.example.com", values)
        parsed = self.p.parse(out, action={})
        self.assertIn("not json at all", parsed.dead_letter)

    def test_json_exotic_row_without_name_is_dead_lettered(self):
        parsed = self.p.parse('{"timestamp":"2026-09-12T00:00:00Z"}',
                              action={})
        self.assertEqual(parsed.assets, [])
        self.assertTrue(parsed.dead_letter)

    def test_bare_lines_still_parse(self):
        values = self._values("a.example.com\nb.example.com\n")
        self.assertEqual(values, ["a.example.com", "b.example.com"])
        self.assertEqual(self.p.parse("a.example.com\n", action={}).dead_letter,
                         [])

    def test_bare_form_stamps_enum_markers(self):
        r = self.p.parse("docsub.example.com.cn\n", action={"host": "example.com.cn"})
        self.assertEqual(r.assets[0]["enumerated_host"], "docsub.example.com.cn")
        self.assertEqual(r.assets[0]["enumerated_domain"], "example.com.cn")

    def test_glued_annotation_form(self):
        values = self._values("www.example.com(CNAME)edge.example.net")
        self.assertIn("www.example.com", values)
        self.assertNotIn("edge.example.net", values)


if __name__ == "__main__":
    unittest.main(verbosity=2)
