"""LLM reflector — propose-only, structured tool-calling (deployment hard rule).

The reflector is an OPTIONAL LLM consulted during the REFLECT beat. It may
only propose hypotheses and adjust priorities; it can never drive a finding
transition, and it never sees the writer — it receives the
``ProposeOnlyView`` (F04).

Model / endpoint / key are deliberately NOT hardcoded (the operator swaps
providers — the Xiaomi token-plan mimo package today, something else
tomorrow). They come from the caller, the CLI flags, or the environment;
this module has no defaults for them.

Deployment hard rule (R3 KL-P0-1): the LLM answers with a STRICT JSON
schema — ``{"proposals": [...]}`` where each item is exactly one of

    {"action": "propose_hypothesis", "statement": str, "priority": number}
    {"action": "adjust_priority",   "entity_id": str, "priority": number}

The engine interprets that JSON; it never executes model-generated Python.
Anything that fails schema validation is dropped (fail-closed, no-op).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

# --- schema (the ONLY surface the LLM may drive) -----------------------
_ALLOWED_ACTIONS = ("propose_hypothesis", "adjust_priority")
_MAX_PROPOSALS = 8


def parse_proposals(text: str) -> list[dict]:
    """Strictly validate an LLM answer into proposal dicts (fail-closed).

    Returns [] for anything that is not valid JSON with a ``proposals``
    list of exactly-shaped items — no partial credit, no coercion.
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    items = data.get("proposals")
    if not isinstance(items, list):
        return []
    out: list[dict] = []
    for item in items[: _MAX_PROPOSALS]:
        if not isinstance(item, dict):
            continue
        action = item.get("action")
        if action not in _ALLOWED_ACTIONS:
            continue
        if action == "propose_hypothesis":
            statement = item.get("statement")
            if not isinstance(statement, str) or not statement.strip():
                continue
            pri = item.get("priority")
            if not isinstance(pri, (int, float)):
                continue
            out.append({"action": action, "statement": statement.strip(),
                        "priority": float(pri)})
        else:  # adjust_priority
            eid = item.get("entity_id")
            pri = item.get("priority")
            if not isinstance(eid, str) or not isinstance(pri, (int, float)):
                continue
            out.append({"action": action, "entity_id": eid,
                        "priority": float(pri)})
    return out


# --- LLM call (anthropic messages wire; endpoint-agnostic) -------------
def _call_llm(prompt: str, *, model: str, base_url: str, api_key: str,
              timeout: float = 120) -> str | None:
    url = base_url.rstrip("/") + "/v1/messages"
    body = {
        "model": model,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError,
            ValueError, TimeoutError):
        return None
    parts = [c.get("text", "") for c in data.get("content", [])
             if isinstance(c, dict) and c.get("type") == "text"]
    return "".join(parts) or None


# --- prompt (machine state only, <=2KB digest spirit) ------------------
def build_prompt(view, engagement_id: str,
                 failure_lines: list[str] | None = None) -> str:
    hyps = view.query_entities(kind="hypothesis", engagement_id=engagement_id,
                               state="proposed")
    findings = view.query_entities(kind="finding", engagement_id=engagement_id)
    by_state: dict[str, int] = {}
    for f in findings:
        st = f.get("state") or "?"
        by_state[st] = by_state.get(st, 0) + 1
    assets = view.query_entities(kind="asset", engagement_id=engagement_id)
    frontier = [a.get("value", "") for a in assets if a.get("frontier")][:10]
    lines = [
        "You are the MOTOKO planning reflector. Propose next recon steps.",
        f"Engagement: {engagement_id}",
        f"Finding states: {json.dumps(by_state, ensure_ascii=False)}",
        f"Frontier assets (first 10): {json.dumps(frontier, ensure_ascii=False)}",
        f"Open proposed hypotheses: {len(hyps)}",
    ]
    # R3: failure context. Computed by the orchestrator (which owns the writer)
    # and passed in read-only — the reflector still cannot reach the graph, it
    # just stops planning blind to what already failed and why.
    lines.extend(failure_lines or [])
    lines += [
        "Reply with JSON ONLY, schema:",
        '{"proposals": [',
        '  {"action": "propose_hypothesis", "statement": "<what to verify>", "priority": <0-100>},',
        '  {"action": "adjust_priority", "entity_id": "<existing entity id>", "priority": <0-100>}',
        "]}",
        "No other keys, no other actions, no markdown fences.",
    ]
    return "\n".join(lines)


def make_reflector(*, model: str, base_url: str, api_key: str,
                   timeout: float = 120, _call=None):
    """Factory: returns a reflector callable with the given endpoint config.

    Nothing is hardcoded — swap model/base_url/key per deployment. The
    callable signature matches what the orchestrator injects:
    ``reflector(view, engagement_id)``. ``_call`` is a test seam for the
    LLM transport (defaults to the real anthropic-messages HTTP call).

    R3: the returned callable also accepts an optional ``failure_lines=``
    keyword. The orchestrator probes for it (``_accepts_failure_lines``) and
    only passes it when supported, so a 2-arg reflector — including every
    pre-R3 test stub — keeps working unchanged.
    """
    _transport = _call or _call_llm

    def _reflect(view, engagement_id: str,
                 failure_lines: list[str] | None = None) -> None:
        prompt = build_prompt(view, engagement_id, failure_lines=failure_lines)
        text = _transport(prompt, model=model, base_url=base_url,
                          api_key=api_key, timeout=timeout)
        if not text:
            return
        for prop in parse_proposals(text):
            if prop["action"] == "propose_hypothesis":
                view.propose_hypothesis({
                    "statement": prop["statement"],
                    "priority": prop["priority"],
                })
            else:
                view.adjust_priority(prop["entity_id"], prop["priority"])

    return _reflect


def reflector_from_env():
    """Config from the environment (no hardcoded model/endpoint/key).

    Reads:
        MOTOKO_REFLECTOR_MODEL     (required to enable)
        MOTOKO_REFLECTOR_BASE_URL  (required to enable — the provider is an
                                    operator decision, never a default)
        MOTOKO_REFLECTOR_KEY_ENV   (env var NAME holding the key;
                                    default XIAOMI_API_KEY)
    Returns None when the model OR the base_url is unset (reflector
    disabled — same fail-closed posture as a missing key).
    """
    model = os.environ.get("MOTOKO_REFLECTOR_MODEL", "").strip()
    if not model:
        return None
    base_url = os.environ.get("MOTOKO_REFLECTOR_BASE_URL", "").strip()
    if not base_url:
        return None
    key_env = os.environ.get("MOTOKO_REFLECTOR_KEY_ENV", "").strip() or "XIAOMI_API_KEY"
    api_key = os.environ.get(key_env, "").strip()
    if not api_key:
        return None
    return make_reflector(model=model, base_url=base_url, api_key=api_key)
