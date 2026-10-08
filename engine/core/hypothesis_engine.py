"""Hypothesis engine — deterministic rule matching (rules are data).

Rules are JSON files under ``rules/<category>/*.json`` (stdlib-only, no
PyYAML dependency on the headless deploy box). Matching is pure Python
assertion evaluation over a fact view; there is NO decision tree and NO LLM
in this path — the orchestrator's EXPAND beat is rule matching only (no
planner exists today). A future planner would have to land its output back
in this same hypothesis schema.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import util


class HypothesisEngine:
    def __init__(self, rules_dir: Path | str, *, validate: bool = True):
        self.rules_dir = Path(rules_dir)
        self.validate = validate
        self.rules: list[dict] = self._load()

    def _load(self) -> list[dict]:
        if not self.rules_dir.is_dir():
            # rglob on a missing directory yields NOTHING instead of
            # raising, so a broken install (or a typo'd --rules-dir)
            # silently loaded zero rules and every run proposed nothing
            # while exiting clean. RuntimeError, not ValueError: this is
            # the one corpus defect an operator reaches from the CLI
            # (a wrong --rules-dir), and cmd_run renders RuntimeError as
            # a refusal — message + exit 2, no traceback — while the
            # bad-file/duplicate-id ValueErrors below stay tracebacks,
            # as they always were.
            raise RuntimeError(
                f"rules directory not found: {self.rules_dir} — refusing "
                "to load an empty corpus from a path that does not exist "
                "(bundled corpus: engine/rules/, installed wheel: the "
                "core/rules package data; or pass --rules-dir)")
        rules: list[dict] = []
        seen: set[str] = set()
        for path in sorted(self.rules_dir.rglob("*.json")):
            try:
                rule = json.loads(path.read_text())
            except json.JSONDecodeError as e:
                raise ValueError(f"bad rule file {path}: {e}") from e
            # A top-level non-object (a JSON list, say) used to die as
            # `AttributeError: 'list' object has no attribute 'get'` in THIS
            # loop — before the gate, so the corpus report never saw it. It is
            # a structurally dead rule file and gets the same treatment as a
            # duplicate id: refused here, with the name.
            if not isinstance(rule, dict):
                raise ValueError(
                    f"bad rule file {path}: top-level JSON is "
                    f"{type(rule).__name__}, not an object")
            rid = rule.get("id")
            if rid:
                if rid in seen:
                    raise ValueError(
                        f"duplicate rule id {rid!r} in {path} — retire one "
                        "copy: move it out of the corpus and record its id "
                        "and reason in the RETIRED_RULES tombstone "
                        "(core/rulecheck.py) before running")
                seen.add(rid)
            rules.append(rule)
        if self.validate:
            self._load_gate()
        return rules

    def _load_gate(self) -> None:
        '        Runs AFTER the per-file loop so a duplicate id is still reported as a\n        duplicate (test_opsec pins that message) rather than as whatever the\n        gate would make of two copies. Every defect is named in one ValueError:\n        an author fixing a corpus should see the whole list, not the first row.\n\n        The gate is ``rulecheck.load_gate`` — one place owns the fatal set, so\n        the load gate and ``motoko rules --report`` can never disagree about\n        what a defect means. Only authoring defects are fatal; a missing tool on\n        this host is deployment, not code.\n        '
        from . import rulecheck

        fatal = rulecheck.load_gate(self.rules_dir)
        if not fatal:
            return
        rows = "\n".join(
            f"  [{i.code}] {i.rule_id}: {i.message}" for i in fatal)
        raise ValueError(
            f"rules corpus at {self.rules_dir} carries {len(fatal)} "
            f"structurally dead rule(s) and will not be loaded:\n{rows}\n"
            "(run `python3 -m core rules --report` for the full corpus "
            "report, including non-fatal rows)")

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
