"""Hypothesis engine — deterministic rule matching (kimi: rules are data).

Rules are JSON files under ``rules/<category>/*.json`` (stdlib-only, no
PyYAML dependency on the headless deploy box). Matching is pure Python
assertion evaluation over a fact view; there is NO decision tree and NO LLM
in the fast path. An LLM planner only runs on rule-missed nodes (orchestrator
layer), and its output must land back in this same hypothesis schema.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import util


class HypothesisEngine:
    def __init__(self, rules_dir: Path | str):
        self.rules_dir = Path(rules_dir)
        self.rules: list[dict] = self._load()

    def _load(self) -> list[dict]:
        rules: list[dict] = []
        seen: set[str] = set()
        for path in sorted(self.rules_dir.rglob("*.json")):
            try:
                rule = json.loads(path.read_text())
            except json.JSONDecodeError as e:
                raise ValueError(f"bad rule file {path}: {e}") from e
            # Round-3 audit P0-1: two files shipped the same rule id (the
            # P-030 round left a tech/ copy next to the scan/ rewrite) and
            # every asset silently got the baseline scan TWICE. A duplicate
            # id is a rule-authoring defect: fail loudly at load time.
            rid = rule.get("id")
            if rid:
                if rid in seen:
                    raise ValueError(
                        f"duplicate rule id {rid!r} in {path} — retire one "
                        "copy (rules.retired/) before running")
                seen.add(rid)
            rules.append(rule)
        return rules

    def rule_count(self) -> int:
        return len(self.rules)

    def generate(self, facts: dict) -> list[dict]:
        """Return proposed hypotheses for every rule matching the fact view."""
        hyps = []
        for rule in self.rules:
            if self._match(rule, facts):
                hyps.append(self._hypothesis(rule))
        return hyps

    # -- matching ------------------------------------------------------
    def _match(self, rule: dict, facts: dict) -> bool:
        when = rule.get("when", {})
        if not when:
            return False  # explicit conditions required (no fire-everything)
        # Delegate to the one recursive evaluator. This used to duplicate the
        # all/any handling here while _eval only understood leaves — so a group
        # nested INSIDE an all/any fell through to the leaf path and silently
        # degenerated to True. One evaluator, any nesting depth.
        return self._eval(when, facts)

    def _eval(self, cond: dict, facts: dict) -> bool:
        # Boolean groups, at any depth. A member of an all/any list may itself
        # be a group.
        if "all" in cond:
            return all(self._eval(c, facts) for c in cond["all"])
        if "any" in cond:
            return any(self._eval(c, facts) for c in cond["any"])
        if "not" in cond:
            return not self._eval(cond["not"], facts)

        fact = cond.get("fact")
        if fact is None:
            # Malformed leaf: it names no fact, so there is no evidence it
            # could match. Must be False — returning True here is exactly what
            # made R-CTX-STRIX-DEEP-001's nested {"all": [...]} evaluate as
            # `None == None`, turning its "any" into fire-always and proposing
            # `strix -m deep` (timeout 7200, the only token consumer) for every
            # asset in the graph regardless of evidence.
            return False
        op = cond.get("op", "eq")
        value = cond.get("value")
        actual = facts.get(fact)

        # "==" / "!=" are accepted as aliases: rules are hand-authored data and
        # an unsupported op used to fall through to `return False`, i.e. the
        # condition silently never matched instead of raising.
        if op in ("eq", "=="):
            if isinstance(actual, list):
                return value in actual
            return actual == value
        if op in ("ne", "!="):
            if isinstance(actual, list):
                return value not in actual
            return actual != value
        if op == "contains":
            if isinstance(actual, list):
                return any(str(value).lower() in str(x).lower() for x in actual)
            return str(value).lower() in str(actual or "").lower()
        if op == "matches":
            return re.search(value, str(actual or "")) is not None
        if op == "in":
            return actual in (value if isinstance(value, list) else [value])
        if op == "intersects":
            # actual list shares >=1 element with value list
            if not isinstance(actual, list):
                return False
            return bool(set(actual) & set(value if isinstance(value, list) else [value]))
        raise ValueError(f"rule condition uses unsupported op {op!r} (fact={fact!r})")

    # -- hypothesis construction --------------------------------------
    def _hypothesis(self, rule: dict) -> dict:
        then = rule.get("then", {})
        return {
            "id": util.new_id("hypothesis"),
            "kind": "hypothesis",
            "state": "proposed",
            "rule_id": rule["id"],
            "category": rule.get("category", "tech"),
            "statement": then.get("hypothesis", rule.get("name", rule["id"])),
            "actions": then.get("actions", []),
            "chain_hint": then.get("chain_hint", []),
            "on_hit_class": then.get("on_hit_class"),
            "priority": self._score(then),
        }

    @staticmethod
    def _score(then: dict) -> float:
        pri = then.get("priority", {})
        impact = float(pri.get("impact", 0.5))
        cost = float(pri.get("cost", 0.5))
        p = impact * 80.0 / (cost + 0.1)
        return round(max(0.0, min(100.0, p)), 2)
