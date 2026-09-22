"""Validate every response leaf before it enters host conversation history."""
from __future__ import annotations

import re
from .client import ERRORS, KINDS, OPERATIONS, STATES, _integer, _number

STOP_REASONS = {"not_started", "cycle_budget", "wave_budget", "wave_boundary", "waiting", "exhausted", "interrupted", "other"}
DOCTOR_CATEGORIES = {"python", "storage", "temporary_storage", "tools", "verification_backends",
    "container", "audit_config", "linter", "credentials", "reflector", "wordlists", "engagements", "egress", "other"}
EVENT_KINDS = {"entity.upsert", "entity.transition", "entity.priority", "edge.added", "finding.duplicate_seen",
    "scan.wave.completed", "graph_health", "observation_dead_letter", "scope_blocked",
    "verification_blocked", "verification_unblocked", "validation_error", "act.dependency_invalid",
    "act.dependency_blocked", "act.template_invalid", "act.placeholder_refused", "act.executor_error",
    "act.dedup", "reflector.error", "mint.placeholder_unsatisfiable", "mint.tool_broken_skip",
    "tool_run.broken_wrapper", "opsec_canary_skip", "opsec_cooldown_skip", "waf_detected",
    "completeness_stamp_withheld", "scope.set", "failure_recovery",
    "hypothesis_retire_error", "rule_attempts_bump_error", "rule_hit_class",
    "rule_hit_class_error", "rule_hit_class_skipped", "sync_runs_failed",
    "reflector.proposal_refused", "opsec_cooldown_restore_error",
    "opsec_cooldown_persist_error", "other"}
HEALTH_KINDS = {"no_graph", "orphan_assets", "tool_without_parser", "dead_letter_volume", "stuck_testing",
    "on_hit_class_orphan", "service_no_consumer", "scope_blocked_volume", "verification_blocked",
    "dangling_edges", "uningested_observations", "runtime_error_event", "other"}


def obj(value, required, optional=()):
    return isinstance(value, dict) and set(required) <= value.keys() <= set(required) | set(optional)


def count(value):
    return _integer(value, 0, 2**53 - 1)


def enum(value, choices):
    return isinstance(value, str) and value in choices


def mapping(value, key_check, value_check, limit=512):
    return (isinstance(value, dict) and len(value) <= limit
            and all(key_check(k) and value_check(v) for k, v in value.items()))


def items(value, check, limit=100):
    return isinstance(value, list) and len(value) <= limit and all(check(v) for v in value)


def identifier(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def rule_id(value):
    return identifier(value, r"R-[A-Z0-9][A-Z0-9_-]{0,79}")


def entity_ref(value):
    return value is None or identifier(value, r"entity-[a-f0-9]{20}")


def rule_stats(value):
    return (obj(value, (), ("runs", "done", "failed", "discoveries", "duration_s"))
            and all(_number(v, 0, 86_400) if k == "duration_s" else count(v) for k, v in value.items()))


def wave(value):
    if not obj(value, ("stop_reason",), ("wave", "cycles", "pending", "priority_offsets", "chain_bonuses", "rules")):
        return False
    return (enum(value["stop_reason"], STOP_REASONS)
        and all(count(value[k]) for k in ("wave", "cycles", "pending") if k in value)
        and all(mapping(value[k], rule_id, lambda v: _number(v, -30, 15))
                for k in ("priority_offsets", "chain_bonuses") if k in value)
        and ("rules" not in value or mapping(value["rules"], rule_id, rule_stats)))


def query_item(value):
    return (obj(value, ("ref", "kind", "state"), ("confidence", "priority"))
        and entity_ref(value["ref"]) and enum(value["kind"], KINDS | {"other"})
        and enum(value["state"], STATES | {"other"})
        and all(_number(value[k], -1e9, 1e9) for k in ("confidence", "priority") if k in value))


def event_item(value):
    return (obj(value, ("seq", "kind", "entity_ref"), ("wave",)) and count(value["seq"])
        and enum(value["kind"], EVENT_KINDS) and entity_ref(value["entity_ref"])
        and ("wave" not in value or value["kind"] == "scan.wave.completed" and wave(value["wave"])))


def check_result(operation, data, ok):
    if obj(data, ("error",)):
        return not ok and enum(data["error"], ERRORS)
    if operation == "capabilities":
        return (obj(data, ("operations", "transport", "max_request_bytes", "max_response_bytes",
                           "max_requests_per_process", "mutating_operations", "disconnect_cancels"))
            and data["transport"] == "stdio" and data["disconnect_cancels"] is True
            and items(data["operations"], lambda v: enum(v, OPERATIONS), len(OPERATIONS))
            and data["mutating_operations"] == ["run"]
            and data["max_request_bytes"] == 65536 and data["max_response_bytes"] == 65536
            and _integer(data["max_requests_per_process"], 2, 32))
    if operation == "doctor":
        return (obj(data, ("checks", "failures"), ("scope",)) and count(data["failures"])
            and ("scope" not in data or enum(data["scope"], {"scan", "full"}))
            and items(data["checks"], lambda v: obj(v, ("category", "counts"))
                and enum(v["category"], DOCTOR_CATEGORIES)
                and obj(v["counts"], ("OK", "WARN", "FAIL")) and all(count(n) for n in v["counts"].values())))
    if operation == "rules":
        return (obj(data, ("rules_total", "fireable", "counts", "by_code"))
            and count(data["rules_total"]) and count(data["fireable"])
            and obj(data["counts"], ("HIGH", "MEDIUM", "LOW")) and all(count(n) for n in data["counts"].values())
            and mapping(data["by_code"], lambda k: identifier(k, r"[a-z][a-z_]{0,63}"), count))
    if operation == "digest":
        return (obj(data, ("counts", "last_event", "latest_wave")) and count(data["last_event"])
            and mapping(data["counts"], lambda k: enum(k, KINDS | {"other"}),
                lambda v: mapping(v, lambda k: enum(k, STATES | {"other"}), count))
            and (data["latest_wave"] is None or wave(data["latest_wave"])))
    if operation in {"query", "events"}:
        return (obj(data, ("items", "has_more", "next_cursor")) and type(data["has_more"]) is bool
            and count(data["next_cursor"]) and items(data["items"], query_item if operation == "query" else event_item))
    if operation == "health":
        return (obj(data, ("issues", "issue_count")) and count(data["issue_count"])
            and items(data["issues"], lambda v: obj(v, ("severity", "kind"))
                and enum(v["severity"], {"HIGH", "MEDIUM", "LOW", "other"}) and enum(v["kind"], HEALTH_KINDS)))
    if operation == "run":
        return (obj(data, ("stop_reason",), ("cycle", "findings", "hypotheses", "pending", "retry_after_s",
            "by_state", "waves", "waves_total", "waves_truncated"))
            and enum(data["stop_reason"], STOP_REASONS)
            and all(count(data[k]) for k in ("cycle", "findings", "hypotheses", "pending", "waves_total") if k in data)
            and ("retry_after_s" not in data or _number(data["retry_after_s"], 0, 86_400))
            and ("by_state" not in data or mapping(data["by_state"], lambda k: enum(k, STATES), count))
            and ("waves" not in data or items(data["waves"], wave, 4))
            and ("waves_truncated" not in data or type(data["waves_truncated"]) is bool))
    return False
