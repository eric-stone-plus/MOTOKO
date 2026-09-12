"""R5 M5/M8: rule hygiene.

M5 — a rule's ``tool`` must be the actual binary name (the executor resolves
it with ``shutil.which``); drifted names silently never execute.
M8 — every nuclei action must pass ``-jsonl`` (the nuclei parser only eats
JSONL; text output would dead-letter).

Run:  python3 tests/test_rules.py
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
RULES = Path(__file__).resolve().parents[1] / "rules"

# tool name in the rule file -> the real binary it must name
RENAMED = {
    "aws_cli": "aws",
    "bloodhound_python": "bloodhound-python",
    "enumerate_iam": "enumerate-iam",
    "git_dumper": "git-dumper",
    "kiterunner": "kr",
}


def load_rules() -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(RULES.rglob("*.json"))]


class TestRuleToolNames(unittest.TestCase):
    def test_no_drifted_tool_names(self):
        seen: dict[str, str] = {}
        for rule in load_rules():
            for action in (rule.get("then") or {}).get("actions", []):
                tool = action.get("tool", "")
                seen[tool] = rule["id"]
        for bad in RENAMED:
            self.assertNotIn(bad, seen,
                             f"rule {seen.get(bad)} still names tool {bad!r}")

    def test_renamed_tools_now_match_the_binaries(self):
        by_id = {r["id"]: r for r in load_rules()}
        expected = {
            "R-CHAIN-SSRF-CLOUD": "aws",
            "R-ACC-AD-USER-001": "bloodhound-python",
            "R-ACC-CLOUD-001": "enumerate-iam",
            "R-TECH-GIT-001": "git-dumper",
            "R-TECH-SWAGGER-001": "kr",
        }
        for rid, tool in expected.items():
            tools = [a["tool"] for a in by_id[rid]["then"]["actions"]]
            self.assertIn(tool, tools, f"{rid} is missing tool {tool!r}")

    def test_cmds_still_use_the_real_binary(self):
        by_id = {r["id"]: r for r in load_rules()}
        self.assertIn("git-dumper", by_id["R-TECH-GIT-001"]["then"]["actions"][0]["cmd"])
        self.assertIn("bloodhound-python",
                      by_id["R-ACC-AD-USER-001"]["then"]["actions"][0]["cmd"])
        self.assertIn("enumerate-iam",
                      by_id["R-ACC-CLOUD-001"]["then"]["actions"][0]["cmd"])
        self.assertIn("kr ", by_id["R-TECH-SWAGGER-001"]["then"]["actions"][0]["cmd"])
        self.assertIn("aws ", by_id["R-CHAIN-SSRF-CLOUD"]["then"]["actions"][1]["cmd"])


class TestNucleiJsonl(unittest.TestCase):
    def test_every_nuclei_action_requests_jsonl(self):
        offenders: list[str] = []
        for rule in load_rules():
            for action in (rule.get("then") or {}).get("actions", []):
                cmd = action.get("cmd", "")
                if cmd.split()[:1] == ["nuclei"] or action.get("tool") == "nuclei":
                    if "-jsonl" not in cmd.split():
                        offenders.append(f"{rule['id']}: {cmd}")
        self.assertEqual(offenders, [],
                         "nuclei commands without -jsonl: " + "; ".join(offenders))


class TestConditionEvaluation(unittest.TestCase):
    """Regression: nested boolean groups and operator aliases.

    ``_match`` used to handle ``all``/``any`` at the top level only, while
    ``_eval`` understood leaves alone. A group nested INSIDE an all/any list
    therefore fell through to the leaf path, where ``fact``/``value`` were both
    None and ``op`` defaulted to ``"eq"`` — so it evaluated ``None == None``
    and returned True unconditionally. R-CTX-STRIX-DEEP-001 has such a nested
    ``{"all": [...]}`` inside its ``any``, which made the whole rule fire on
    EVERY fact view and proposed ``strix -m deep`` (timeout 7200, and strix is
    the only token consumer) for every asset regardless of evidence.
    """

    def setUp(self):
        from motoko.hypothesis_engine import HypothesisEngine
        self.engine_cls = HypothesisEngine
        self.engine = HypothesisEngine(RULES)

    def _fired(self, facts: dict) -> set:
        return {h["rule_id"] for h in self.engine.generate(facts)}

    def test_no_rule_fires_on_an_empty_fact_view(self):
        # The invariant that would have caught this bug on day one: with no
        # evidence there is nothing to match, so nothing may fire. A rule that
        # fires here is fire-always, and burns quota on every asset.
        for facts in ({}, {"tech": ["unknown_stack"]}, {"frontier": False}):
            self.assertEqual(self._fired(facts), set(),
                             f"rule fired with no supporting evidence: facts={facts}")

    def test_nested_group_requires_its_own_conditions(self):
        rid = "R-CTX-STRIX-DEEP-001"
        # branch 2 of its "any" is a nested all: frontier==true AND type==url
        self.assertIn(rid, self._fired({"frontier": True, "type": "url"}))
        # half of a nested all must not fire it
        self.assertNotIn(rid, self._fired({"frontier": True, "type": "host"}))
        self.assertNotIn(rid, self._fired({"frontier": False, "type": "url"}))
        # the two leaf branches still work
        self.assertIn(rid, self._fired({"class": ["vuln.strix_confirmed"]}))
        self.assertIn(rid, self._fired({"class": ["cve_reported"]}))

    def test_deeply_nested_groups_evaluate(self):
        e = self.engine_cls.__new__(self.engine_cls)
        cond = {"all": [{"any": [{"fact": "a", "op": "eq", "value": 1},
                                 {"not": {"fact": "b", "op": "eq", "value": 2}}]},
                        {"fact": "c", "op": "contains", "value": "x"}]}
        self.assertTrue(e._eval(cond, {"a": 1, "c": ["xyz"]}))
        self.assertFalse(e._eval(cond, {"a": 9, "b": 2, "c": ["xyz"]}))

    def test_leaf_without_a_fact_is_false_never_true(self):
        e = self.engine_cls.__new__(self.engine_cls)
        for cond in ({}, {"op": "eq"}, {"op": "eq", "value": None},
                     {"value": "x"}, {"op": "contains"}):
            self.assertFalse(e._eval(cond, {}), f"factless leaf matched: {cond}")
            self.assertFalse(e._eval(cond, {"anything": 1}), f"factless leaf matched: {cond}")

    def test_double_equals_and_not_equals_are_supported(self):
        # Rules are hand-authored data; "==" used to fall through to a silent
        # False, i.e. the condition never matched and nothing said so.
        e = self.engine_cls.__new__(self.engine_cls)
        self.assertTrue(e._eval({"fact": "frontier", "op": "==", "value": True},
                                {"frontier": True}))
        self.assertFalse(e._eval({"fact": "frontier", "op": "==", "value": True},
                                 {"frontier": False}))
        self.assertTrue(e._eval({"fact": "type", "op": "!=", "value": "url"},
                                {"type": "host"}))

    def test_unsupported_op_fails_loudly(self):
        # A typo'd operator must raise, not silently never-match: the old
        # `return False` fallthrough is how "==" went unnoticed.
        e = self.engine_cls.__new__(self.engine_cls)
        with self.assertRaises(ValueError):
            e._eval({"fact": "x", "op": "gt", "value": 1}, {"x": 2})

    def test_every_shipped_rule_uses_a_supported_op(self):
        supported = {"eq", "==", "ne", "!=", "contains", "matches", "in", "intersects"}

        def ops(cond, acc):
            if not isinstance(cond, dict):
                return
            for k in ("all", "any"):
                for sub in cond.get(k, []) or []:
                    ops(sub, acc)
            if "not" in cond:
                ops(cond["not"], acc)
            if "fact" in cond:
                acc.add(cond.get("op", "eq"))

        bad: list[str] = []
        for rule in load_rules():
            acc: set = set()
            ops(rule.get("when") or {}, acc)
            for op in acc - supported:
                bad.append(f"{rule['id']}: op={op!r}")
        self.assertEqual(bad, [], "rules using unsupported ops: " + "; ".join(bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)
