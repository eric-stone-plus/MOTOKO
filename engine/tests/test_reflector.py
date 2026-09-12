"""Reflector tests — strict schema, propose-only enforcement, config seam.

Run:  python3 tests/test_reflector.py
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko.reflector import (  # noqa: E402
    build_prompt, make_reflector, parse_proposals, reflector_from_env,
)


class TestParseProposals(unittest.TestCase):
    def test_valid_propose(self):
        out = parse_proposals(
            '{"proposals": [{"action": "propose_hypothesis",'
            ' "statement": "check spring actuator", "priority": 80}]}')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["action"], "propose_hypothesis")
        self.assertEqual(out[0]["statement"], "check spring actuator")

    def test_valid_adjust(self):
        out = parse_proposals(
            '{"proposals": [{"action": "adjust_priority",'
            ' "entity_id": "hyp_x", "priority": 50}]}')
        self.assertEqual(out, [{"action": "adjust_priority",
                                "entity_id": "hyp_x", "priority": 50.0}])

    def test_unknown_action_dropped(self):
        # anything outside the two allowed actions is fail-closed
        out = parse_proposals(
            '{"proposals": [{"action": "advance_finding", "entity_id": "fnd_1"},'
            ' {"action": "propose_hypothesis", "statement": "ok", "priority": 5}]}')
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["action"], "propose_hypothesis")

    def test_missing_fields_dropped(self):
        out = parse_proposals(
            '{"proposals": [{"action": "propose_hypothesis", "priority": 5}]}')
        self.assertEqual(out, [])

    def test_bad_json_returns_empty(self):
        self.assertEqual(parse_proposals("not json"), [])
        self.assertEqual(parse_proposals(""), [])

    def test_non_dict_proposals_dropped(self):
        out = parse_proposals('{"proposals": ["nope"]}')
        self.assertEqual(out, [])

    def test_wrong_priority_type_dropped(self):
        out = parse_proposals(
            '{"proposals": [{"action": "propose_hypothesis",'
            ' "statement": "x", "priority": "high"}]}')
        self.assertEqual(out, [])

    def test_missing_proposals_key(self):
        self.assertEqual(parse_proposals('{"other": 1}'), [])

    def test_cap_on_proposal_count(self):
        items = [{"action": "adjust_priority", "entity_id": f"h{i}",
                  "priority": 1.0} for i in range(50)]
        out = parse_proposals('{"proposals": ' +
                              repr(items).replace("'", '"') + '}')
        self.assertLessEqual(len(out), 8)


class TestReflectorCallable(unittest.TestCase):
    class FakeView:
        def __init__(self):
            self.proposed: list[dict] = []
            self.adjusted: list[tuple] = []

        def query_entities(self, **kw):
            return []

        def propose_hypothesis(self, h):
            self.proposed.append(h)

        def adjust_priority(self, eid, pri):
            self.adjusted.append((eid, pri))

    def test_proposals_applied(self):
        def fake_call(prompt, **kw):
            return ('{"proposals": [{"action": "propose_hypothesis",'
                    ' "statement": "probe actuator", "priority": 70}]}')
        view = self.FakeView()
        refl = make_reflector(model="m", base_url="https://x", api_key="k",
                              _call=fake_call)
        refl(view, "eng")
        self.assertEqual(len(view.proposed), 1)
        self.assertEqual(view.proposed[0]["statement"], "probe actuator")

    def test_invalid_llm_output_is_noop(self):
        def fake_call(prompt, **kw):
            return '{"proposals": [{"action": "drop_tables", "x": 1}]}'
        view = self.FakeView()
        refl = make_reflector(model="m", base_url="https://x", api_key="k",
                              _call=fake_call)
        refl(view, "eng")
        self.assertEqual(view.proposed, [])
        self.assertEqual(view.adjusted, [])

    def test_transport_failure_is_noop(self):
        def fake_call(prompt, **kw):
            return None
        view = self.FakeView()
        refl = make_reflector(model="m", base_url="https://x", api_key="k",
                              _call=fake_call)
        refl(view, "eng")   # must not raise
        self.assertEqual(view.proposed, [])

    def test_prompt_contains_state(self):
        view = self.FakeView()
        prompt = build_prompt(view, "eng-x")
        self.assertIn("eng-x", prompt)
        self.assertIn("proposals", prompt)


class TestReflectorFromEnv(unittest.TestCase):
    """R5 M10: the endpoint is an operator decision — no built-in provider
    default. Missing model OR missing base_url disables the reflector."""

    def test_missing_model_disables(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(reflector_from_env())

    def test_missing_base_url_disables(self):
        env = {"MOTOKO_REFLECTOR_MODEL": "some-model",
               "MOTOKO_REFLECTOR_KEY_ENV": "R5_TEST_KEY",
               "R5_TEST_KEY": "secret"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsNone(reflector_from_env(),
                              "a reflector was built without an explicit "
                              "MOTOKO_REFLECTOR_BASE_URL")

    def test_explicit_base_url_enables(self):
        env = {"MOTOKO_REFLECTOR_MODEL": "some-model",
               "MOTOKO_REFLECTOR_BASE_URL": "https://llm.example.com/anthropic",
               "MOTOKO_REFLECTOR_KEY_ENV": "R5_TEST_KEY",
               "R5_TEST_KEY": "secret"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertTrue(callable(reflector_from_env()))

    def test_missing_key_disables(self):
        env = {"MOTOKO_REFLECTOR_MODEL": "some-model",
               "MOTOKO_REFLECTOR_BASE_URL": "https://llm.example.com/anthropic",
               "MOTOKO_REFLECTOR_KEY_ENV": "R5_TEST_KEY"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIsNone(reflector_from_env())


if __name__ == "__main__":
    unittest.main(verbosity=2)
