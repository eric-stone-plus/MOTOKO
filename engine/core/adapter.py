"""Local, versioned supervisor protocol. No sockets and no raw evidence output.

Only this engine-side module reads the graph. Host plugins send JSON through
inherited pipes, receive aggregate metadata, and never import the scheduler.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import os
import select
import signal
import sys
import threading
from dataclasses import dataclass
from typing import Any

from . import db, util

PROTOCOL = "motoko/1"
MAX_FRAME_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUESTS = 32
READ_OPERATIONS = frozenset({"capabilities", "doctor", "rules", "digest", "query", "events", "health"})
MUTATING_OPERATIONS = frozenset({"run"})
OPERATIONS = READ_OPERATIONS | MUTATING_OPERATIONS
KINDS = frozenset({"asset", "finding", "hypothesis", "evidence", "access", "path"})
STATES = frozenset({"active", "candidate", "triaged", "reproduced", "verified", "exploitable",
    "confirmed_impact", "false_positive", "duplicate", "out_of_scope", "wont_test",
    "proposed", "testing", "done", "rejected", "error", "timeout", "failed"})
STOP_REASONS = frozenset({"not_started", "cycle_budget", "wave_budget", "wave_boundary", "waiting", "exhausted", "interrupted"})
# Unknown kinds are deliberately collapsed; event payloads may hold arbitrary
# target-controlled strings and are never copied into the wire response.
EVENT_KINDS = frozenset({
    "entity.upsert", "entity.transition", "edge.add", "finding.duplicate_seen",
    "scan.wave.completed", "graph_health", "observation_dead_letter",
    "scope_blocked", "verification_blocked", "verification_unblocked", "validation_error",
    "act.dependency_invalid", "act.dependency_blocked", "act.template_invalid",
    "act.placeholder_refused", "act.executor_error", "act.dedup", "reflector.error",
    "mint.placeholder_unsatisfiable", "mint.tool_broken_skip", "tool_run.broken_wrapper",
    "opsec_canary_skip", "opsec_cooldown_skip", "waf_detected", "completeness_stamp_withheld",
})
HEALTH_KINDS = frozenset({"no_graph", "orphan_assets", "tool_without_parser", "dead_letter_volume",
    "stuck_testing", "on_hit_class_orphan", "service_no_consumer", "scope_blocked_volume",
    "verification_blocked", "dangling_edges", "uningested_observations"})


class AdapterError(ValueError):
    """A request is invalid; values must never be interpolated in its message."""


class AdapterStopped(BaseException):
    """Unwind all engine/tool finally blocks on timeout or host cancellation."""

    def __init__(self, code: int):
        self.code = code


@dataclass(frozen=True)
class AdapterRequest:
    operation: str
    engagement_id: str | None = None
    options: dict[str, Any] | None = None


def _int(value, minimum=0, maximum=10_000_000):
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _bounded_int(options, key, default, maximum, minimum=1):
    value = options.get(key, default)
    if not _int(value, minimum, maximum):
        raise AdapterError("integer option is outside its allowed range")
    return value


def validate(request: AdapterRequest) -> dict:
    op = request.operation
    if not isinstance(op, str) or op not in OPERATIONS:
        raise AdapterError("unsupported operation")
    if request.options is not None and not isinstance(request.options, dict):
        raise AdapterError("options must be an object")
    options = dict(request.options or {})
    if op in {"capabilities", "doctor", "rules"}:
        if request.engagement_id is not None:
            raise AdapterError("this operation does not accept an engagement")
    else:
        try:
            db.engagement_dir(db.default_root(), request.engagement_id)
        except (ValueError, TypeError):
            raise AdapterError("invalid engagement identifier") from None
    allowed = {
        "capabilities": set(), "doctor": set(), "rules": {"json"}, "digest": set(),
        "health": set(), "query": {"kind", "state", "limit", "after"},
        "events": {"limit", "after"},
        "run": {"max_cycles", "wave_cycles", "max_waves", "timeout", "wall_timeout"},
    }[op]
    if set(options) - allowed:
        raise AdapterError("unsupported option")
    if "json" in options and options["json"] is not True:
        raise AdapterError("rules always returns JSON")
    if op in {"query", "events"}:
        options["limit"] = _bounded_int(options, "limit", 20, 100)
        if "after" in options:
            options["after"] = _bounded_int(options, "after", 0, 2**63 - 1, 0)
    if op == "query":
        if "kind" in options and (not isinstance(options["kind"], str) or options["kind"] not in KINDS):
            raise AdapterError("invalid entity kind")
        if "state" in options and (not isinstance(options["state"], str) or options["state"] not in STATES):
            raise AdapterError("invalid entity state")
    if op == "run":
        for key, default, maximum in (("max_cycles", 20, 1000), ("wave_cycles", 5, 100), ("max_waves", 4, 100)):
            options[key] = _bounded_int(options, key, default, maximum)
        for key, default in (("timeout", 300), ("wall_timeout", 600)):
            value = options.get(key, default)
            if not _number(value) or not 0 < value <= 3600:
                raise AdapterError("timeout must be finite and in (0, 3600]")
            options[key] = value
    return options


def _ref(value):
    return "entity-" + hashlib.sha256(str(value).encode()).hexdigest()[:20] if value else None


def _enum(value, choices):
    return value if isinstance(value, str) and value in choices else "other"


def _rules_ids():
    from .hypothesis_engine import HypothesisEngine
    return {r["id"] for r in HypothesisEngine(util.default_rules_dir()).rules}


def project_wave(value, rule_ids):
    if not isinstance(value, dict):
        return {}
    result = {key: value[key] for key in ("wave", "cycles", "pending") if _int(value.get(key))}
    result["stop_reason"] = _enum(value.get("stop_reason"), STOP_REASONS)
    for key in ("priority_offsets", "chain_bonuses"):
        mapping = value.get(key)
        if isinstance(mapping, dict):
            result[key] = {rid: max(-30.0, min(15.0, v)) for rid, v in mapping.items()
                           if rid in rule_ids and _number(v)}
    rules = value.get("rules")
    if isinstance(rules, dict):
        result["rules"] = {}
        for rid, stats in rules.items():
            if rid not in rule_ids or not isinstance(stats, dict):
                continue
            row = {k: stats[k] for k in ("runs", "done", "failed", "discoveries") if _int(stats.get(k))}
            if _number(stats.get("duration_s")) and 0 <= stats["duration_s"] <= 86_400:
                row["duration_s"] = stats["duration_s"]
            result["rules"][rid] = row
    return result


def project_summary(value):
    if not isinstance(value, dict) or value.get("stop_reason") not in STOP_REASONS:
        raise AdapterError("malformed engine summary")
    result = {k: value[k] for k in ("cycle", "findings", "hypotheses", "pending") if _int(value.get(k))}
    result["stop_reason"] = value["stop_reason"]
    if _number(value.get("retry_after_s")) and 0 <= value["retry_after_s"] <= 86_400:
        result["retry_after_s"] = value["retry_after_s"]
    by_state = value.get("by_state")
    if isinstance(by_state, dict):
        result["by_state"] = {k: v for k, v in by_state.items() if k in STATES and _int(v)}
    waves = value.get("waves")
    if isinstance(waves, list):
        rule_ids = _rules_ids()
        result["waves"] = [project_wave(wave, rule_ids) for wave in waves[-4:]]
        result["waves_total"] = len(waves)
        result["waves_truncated"] = len(waves) > 4
    return result


class _Discard(io.TextIOBase):
    """Keep incidental engine diagnostics out of the protocol without buffering."""

    def write(self, value):
        return len(value)



def _read(request, options):
    op = request.operation
    if op == "capabilities":
        return 0, {"operations": sorted(OPERATIONS), "transport": "stdio",
                   "max_request_bytes": MAX_FRAME_BYTES, "max_response_bytes": MAX_RESPONSE_BYTES,
                   "max_requests_per_process": MAX_REQUESTS, "mutating_operations": ["run"],
                   "disconnect_cancels": True}
    if op == "doctor":
        from .doctor import check_environment
        checks = []
        failures = 0
        for category, rows in check_environment():
            counts = {level: sum(row[0] == level for row in rows)
                      for level in ("OK", "WARN", "FAIL")}
            failures += counts["FAIL"]
            checks.append({"category": category, "counts": counts})
        return int(bool(failures)), {"checks": checks, "failures": failures}
    if op == "rules":
        from .rulecheck import check_corpus
        report = check_corpus(util.default_rules_dir())
        return 0, {"rules_total": report.rules_total, "fireable": len(report.fireable),
                   "counts": {level: report.count(level) for level in ("HIGH", "MEDIUM", "LOW")},
                   "by_code": report.by_code()}
    graph = db.engagement_dir(db.default_root(), request.engagement_id) / "graph.db"
    if not graph.is_file():
        return 2, {"error": "engagement_not_found"}
    if op == "health":
        from .graph_health import check_health
        report = check_health(request.engagement_id)
        return 0, {"issues": [{"severity": _enum(i.severity, {"HIGH", "MEDIUM", "LOW"}),
                                "kind": _enum(i.kind, HEALTH_KINDS)} for i in report.issues[:100]],
                   "issue_count": len(report.issues)}
    ro = db.Database(graph, read_only=True)
    try:
        if op == "digest":
            rows = ro.conn.execute("SELECT kind, state, COUNT(*) n FROM entities WHERE engagement_id=? GROUP BY kind,state",
                                   (request.engagement_id,)).fetchall()
            counts = {}
            for row in rows:
                kind, state = _enum(row["kind"], KINDS), _enum(row["state"], STATES)
                states = counts.setdefault(kind, {})
                states[state] = states.get(state, 0) + row["n"]
            last = ro.conn.execute("SELECT seq FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            wave = ro.conn.execute("SELECT payload FROM events WHERE kind='scan.wave.completed' AND entity_id=? ORDER BY seq DESC LIMIT 1",
                                   (request.engagement_id,)).fetchone()
            return 0, {"counts": counts, "last_event": last["seq"] if last else 0,
                       "latest_wave": project_wave(json.loads(wave["payload"]), _rules_ids()) if wave else None}
        if op == "query":
            clauses, params = ["engagement_id=?", "rowid> ?"], [request.engagement_id, options.get("after", 0)]
            for key in ("kind", "state"):
                if key in options:
                    clauses.append(key + "=?")
                    params.append(options[key])
            rows = ro.conn.execute("SELECT rowid cursor,id,kind,state,confidence,priority FROM entities WHERE " +
                " AND ".join(clauses) + " ORDER BY rowid LIMIT ?", (*params, options["limit"] + 1)).fetchall()
            selected = rows[:options["limit"]]
            items = []
            for row in selected:
                item = {"ref": _ref(row["id"]), "kind": _enum(row["kind"], KINDS), "state": _enum(row["state"], STATES)}
                for key in ("confidence", "priority"):
                    if _number(row[key]):
                        item[key] = row[key]
                items.append(item)
            return 0, {"items": items, "has_more": len(rows) > options["limit"],
                       "next_cursor": selected[-1]["cursor"] if selected else options.get("after", 0)}
        after = options.get("after")
        rows = ro.conn.execute("SELECT seq,kind,entity_id,payload FROM events WHERE seq>? ORDER BY seq " +
            ("ASC" if after is not None else "DESC") + " LIMIT ?", (after or 0, options["limit"] + 1)).fetchall()
        selected = rows[:options["limit"]]
        if after is None:
            selected = list(reversed(selected))
        rule_ids = _rules_ids()
        items = []
        for row in selected:
            kind = _enum(row["kind"], EVENT_KINDS)
            item = {"seq": row["seq"], "kind": kind, "entity_ref": _ref(row["entity_id"])}
            if kind == "scan.wave.completed":
                item["wave"] = project_wave(json.loads(row["payload"]), rule_ids)
            items.append(item)
        return 0, {"items": items, "has_more": after is not None and len(rows) > options["limit"],
                   "next_cursor": selected[-1]["seq"] if selected else (after or 0)}
    finally:
        ro.close()


def dispatch(request: AdapterRequest) -> dict:
    options = validate(request)
    if request.operation == "run":
        from .orchestrator import run_engagement
        graph = db.engagement_dir(db.default_root(), request.engagement_id) / "graph.db"
        if not graph.is_file():
            code, result = 2, {"error": "engagement_not_found"}
        else:
            summary = run_engagement(request.engagement_id,
                **{key: options[key] for key in ("max_cycles", "wave_cycles", "max_waves", "timeout")})
            code, result = 0, {"summary": project_summary(summary)}
    else:
        code, data = _read(request, options)
        result = {"result": data}
    return {"protocol": PROTOCOL, "operation": request.operation, "ok": code == 0, "exit_code": code, **result}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(value):
    raise AdapterError("non-finite JSON number")


def parse_request(raw, *, require_version=False):
    if len(raw.encode("utf-8") if isinstance(raw, str) else raw) > MAX_FRAME_BYTES:
        raise AdapterError("request too large")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    payload = json.loads(raw, object_pairs_hook=_object, parse_constant=_bad_constant)
    if not isinstance(payload, dict) or set(payload) - {"protocol", "request_id", "operation", "engagement_id", "options"}:
        raise AdapterError("invalid request fields")
    if payload.get("protocol", None if require_version else PROTOCOL) != PROTOCOL:
        raise AdapterError("unsupported protocol version")
    request_id = payload.get("request_id")
    # IDs are correlation integers, never caller-supplied free text.
    if (require_version or "request_id" in payload) and not _int(request_id, 0, 2**53 - 1):
        raise AdapterError("invalid request id")
    request = AdapterRequest(payload.get("operation"), payload.get("engagement_id"), payload.get("options"))
    validate(request)
    return request, request_id


@contextlib.contextmanager
def _deadline(seconds):
    """CLI main-thread boundary: let engine finally blocks reap their tools."""
    def stop(signum, _frame):
        raise AdapterStopped(124 if signum == signal.SIGALRM else 130)
    signals = [signal.SIGTERM, signal.SIGINT, signal.SIGALRM]
    # SSH and other pipe transports commonly deliver SIGHUP when the host
    # disconnects. Treat it like cancellation so the orchestrator's finally
    # blocks close scanners and release the writer lease before exit.
    if hasattr(signal, "SIGHUP"):
        signals.append(signal.SIGHUP)
    saved = {s: signal.signal(s, stop) for s in signals}
    old_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *old_timer)
        for sig, handler in saved.items():
            signal.signal(sig, handler)


@contextlib.contextmanager
def _connection_lease(fd):
    """Watch pipe closure without consuming input or requiring SSH to send HUP.

    This mode requires the supervisor to keep stdin open until the response.
    Plain JSONL pipelines remain available without the explicit lease flag.
    The monitor ends before the main thread restores its signal handlers.
    """
    if fd is None:
        yield
        return
    finished = threading.Event()
    poll = select.poll()
    poll.register(fd, select.POLLHUP | select.POLLERR | getattr(select, "POLLRDHUP", 0))

    def watch():
        while not finished.is_set():
            if poll.poll(50) and not finished.is_set():
                os.kill(os.getpid(), signal.SIGTERM)
                return

    monitor = threading.Thread(target=watch, name="motoko-connection-lease", daemon=True)
    monitor.start()
    try:
        yield
    finally:
        finished.set()
        monitor.join()


def handle_frame(raw, *, require_version=False, disconnect_fd=None):
    request_id = None
    try:
        request, request_id = parse_request(raw, require_version=require_version)
        options = validate(request)
        with _deadline(options.get("wall_timeout", 90)), _connection_lease(disconnect_fd), \
                contextlib.redirect_stdout(_Discard()), contextlib.redirect_stderr(_Discard()):
            response = dispatch(request)
    except (AdapterError, ValueError, TypeError, UnicodeError, RecursionError):
        response = {"ok": False, "exit_code": 2, "error": "invalid_request_or_result"}
    except (AdapterStopped, KeyboardInterrupt) as exc:
        code = getattr(exc, "code", 130)
        response = {"ok": False, "exit_code": code,
                    "error": {124: "deadline_exceeded", 130: "cancelled"}.get(code, "response_too_large")}
    except Exception:
        response = {"ok": False, "exit_code": 3, "error": "engine_unavailable"}
    response.update(protocol=PROTOCOL, request_id=request_id)
    if len(json.dumps(response, ensure_ascii=True, allow_nan=False).encode()) + 1 > MAX_RESPONSE_BYTES:
        return {"protocol": PROTOCOL, "request_id": request_id, "ok": False,
                "exit_code": 3, "error": "response_too_large"}
    return response


def serve_lines(instream=None, outstream=None, *, disconnect_cancels=False):
    """Sequential JSONL; oversize frames close the pipe without draining input."""
    instream = instream if instream is not None else sys.stdin.buffer
    outstream = outstream if outstream is not None else sys.stdout
    overall = 0
    for _ in range(MAX_REQUESTS):
        try:
            with _deadline(30):
                raw = instream.readline(MAX_FRAME_BYTES + 1)
        except (AdapterStopped, KeyboardInterrupt) as exc:
            code = getattr(exc, "code", 130)
            raw = b""
            response = {"protocol": PROTOCOL, "request_id": None, "ok": False,
                        "exit_code": code, "error": "deadline_exceeded" if code == 124 else "cancelled"}
        else:
            if not raw:
                break
            response = handle_frame(raw if raw.endswith(b"\n") else b"", require_version=True,
                                    disconnect_fd=instream.fileno() if disconnect_cancels else None)
        try:
            outstream.write(json.dumps(response, ensure_ascii=True, allow_nan=False) + "\n")
            outstream.flush()
        except BrokenPipeError:
            return 130
        overall = max(overall, response["exit_code"])
        if len(raw) > MAX_FRAME_BYTES or response["exit_code"] in {124, 130}:
            break
    return overall
