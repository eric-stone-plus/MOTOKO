'    proposed 2859   testing 341   error 0   timeout 0   done 0\n\nSeparately, ``reflector.build_prompt`` showed the LLM only finding-states,\nfrontier assets and a hypothesis count. Failures never reached the planner, so\nno reflection could adapt to them.\n\nTwo invariants this module is written against:\n\nRun:  python3 tests/test_failure.py\n'

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# exit codes the executor writes with specific meanings (see executor.py):
#   -1  bad action shape        -2 non-str argv / spawn TypeError
#   126 OSError on spawn        127 binary not found (or podman missing)
#   124/-15/-9 timeout kill     everything else nonzero = the tool itself failed
_SPAWN_CODES = frozenset({-1, -2, 126})
_MISSING_CODES = frozenset({127})
_TIMEOUT_CODES = frozenset({124, -15, -9})

# A tool whose declared per-run budget reaches this is "expensive": a blind
# retry costs more than the information it can return. strix -m deep (7200s)
# is why this constant exists.
EXPENSIVE_TIMEOUT_S = 1800.0

NEVER_RETRY = frozenset({"scope_blocked", "tool_missing", "spawn_error"})

# Hypotheses in flight occupy these tool_run statuses; only terminal ones may
# be recycled, or a live strix session would be re-planned underneath itself.
_INFLIGHT = ("pending", "running", "queued")

_TRANSIENT_MARKERS = (
    "rate limit", "429", "too many requests", "connection reset", "timed out",
    "timeout", "temporarily", "econn", "503", "502", "broken pipe", "tls",
    "ssl", "eof occurred", "connection refused",
)

# The target itself pushing back (distinct from a protocol-level 429, which
# stays transient): WAF pages, captchas, denial phrasing. Checked BEFORE the
# transient markers — "blocked" outranks "connection reset" on the same
# stderr, because the former means the target is steering.
_DETECTED_MARKERS = (
    "waf", "web application firewall", "captcha", "access denied",
    "blocked by", "request blocked", "403 forbidden",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Failure:
    """One classified failure plus the policy that applies to it."""

    cls: str
    reason: str
    retryable: bool
    max_attempts: int
    tool_run_id: str | None = None
    hypothesis_id: str | None = None
    tool: str | None = None

    def as_dict(self) -> dict:
        return {
            "class": self.cls, "reason": self.reason,
            "retryable": self.retryable, "max_attempts": self.max_attempts,
            "tool_run_id": self.tool_run_id,
            "hypothesis_id": self.hypothesis_id, "tool": self.tool,
        }


@dataclass
class FailureDigest:
    """Compact machine-state summary for the reflector prompt (<=2KB spirit).

    Counts by class plus the worst offenders — never raw stderr: enough to
    change strategy, not enough to blow the prompt budget or leak tool output
    into the LLM context.
    """

    by_class: dict[str, int] = field(default_factory=dict)
    stuck_testing: int = 0
    worst_tools: list[tuple[str, int]] = field(default_factory=list)
    recycled: int = 0
    abandoned: int = 0
    read_errors: int = 0

    def is_empty(self) -> bool:
        return not (self.by_class or self.stuck_testing or self.recycled
                    or self.abandoned or self.read_errors)

    def as_dict(self) -> dict:
        return {
            "by_class": dict(self.by_class),
            "stuck_testing": self.stuck_testing,
            "worst_tools": [{"tool": t, "failures": n} for t, n in self.worst_tools],
            "recycled": self.recycled, "abandoned": self.abandoned,
            "read_errors": self.read_errors,
        }

    def prompt_lines(self) -> list[str]:
        if self.is_empty():
            return []
        lines = []
        if self.by_class:
            lines.append("Failure classes: "
                         + json.dumps(self.by_class, ensure_ascii=False))
        if self.stuck_testing:
            lines.append(f"Hypotheses stalled in state=testing: {self.stuck_testing}")
        if self.worst_tools:
            lines.append("Most-failing tools: "
                         + ", ".join(f"{t}={n}" for t, n in self.worst_tools))
        if self.recycled or self.abandoned:
            lines.append(f"Recovery this beat: recycled={self.recycled} "
                         f"abandoned={self.abandoned}")
        if self.read_errors:
            lines.append(f"Failure-scan read errors: {self.read_errors} "
                         "(digest is partial)")
        if self.by_class.get("detected"):
            lines.append(
                f"Targets actively blocking us (class=detected): "
                f"{self.by_class['detected']} run(s). Do NOT re-propose "
                "actions against those origins — the OPSEC cooldown owns "
                "them; retrying sharpens the target's signature.")
        lines.append(
            "Do not re-propose a step whose tool is scope_blocked, "
            "tool_missing, spawn_error or detected: those are deterministic "
            "or defender-driven, retrying cannot succeed.")
        return lines


def classify(*, status: str | None, exit_code: int | None = None,
             stderr_text: str | None = None, command: str | None = None,
             tool: str | None = None,
             tool_timeout: float | None = None) -> Failure:
    """Map a finished ``tool_run`` onto a failure class and its policy.

    Order matters: scope first (compliance outranks everything), then the
    deterministic classes, then timeout, then the generic nonzero exit.
    """
    err = (stderr_text or "").lower()

    if "scope_blocked" in err or "out of scope" in err or "not in scope" in err:
        return Failure("scope_blocked",
                       "authorization boundary refused the target",
                       retryable=False, max_attempts=0, tool=tool)

    if exit_code in _MISSING_CODES:
        return Failure("tool_missing",
                       f"binary not found: {tool or 'unknown'} "
                       "(install it, or disable the rule that needs it)",
                       retryable=False, max_attempts=0, tool=tool)

    if exit_code in _SPAWN_CODES:
        return Failure("spawn_error",
                       f"rule-authoring defect (exit {exit_code}): the action "
                       "could not be spawned at all — it fails identically "
                       "every time",
                       retryable=False, max_attempts=0, tool=tool)

    if status == "timeout" or exit_code in _TIMEOUT_CODES:
        expensive = bool(tool_timeout and tool_timeout >= EXPENSIVE_TIMEOUT_S)
        return Failure("tool_timeout",
                       f"exceeded its {tool_timeout}s budget"
                       + ("; too expensive to blind-retry" if expensive else ""),
                       retryable=not expensive,
                       max_attempts=0 if expensive else 1, tool=tool)

    if status == "error" or (exit_code not in (0, None)):
        if any(m in err for m in _DETECTED_MARKERS):
            return Failure("detected",
                           "target-side blocking observed (WAF/captcha/"
                           "denial) — origin should cool down, not retry",
                           retryable=False, max_attempts=0, tool=tool)
        transient = any(m in err for m in _TRANSIENT_MARKERS)
        return Failure("tool_error",
                       "transient-looking tool failure" if transient
                       else f"tool exited {exit_code}",
                       retryable=True, max_attempts=2, tool=tool)

    return Failure("tool_error", f"unclassified status={status!r} exit={exit_code}",
                   retryable=False, max_attempts=0, tool=tool)


def _tail_file(ref: str | None, n: int = 2048) -> str | None:
    """Last ``n`` bytes of a stderr ref — classification needs a signature,
    not the whole log."""
    if not ref:
        return None
    p = Path(ref)
    try:
        if not p.is_file():
            return None
        size = p.stat().st_size
        with p.open("rb") as fh:
            if size > n:
                fh.seek(size - n)
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return None


def _conn_of(writer) -> sqlite3.Connection:
    return writer.conn if hasattr(writer, "conn") else writer


def _hyp_timeouts(con: sqlite3.Connection, engagement_id: str) -> dict[str, dict[str, float]]:
    """``{hyp_id: {tool: declared_timeout}}`` from each hypothesis's actions.

    Rules carry the budget (``action['timeout']``, e.g. strix deep = 7200) but
    ``tool_run`` stores no timeout column, and actions have no ``id`` to join
    on — so match by tool name within the owning hypothesis. The actions live
    in the ``data`` column, not in typed columns.
    """
    out: dict[str, dict[str, float]] = {}
    rows = con.execute(
        "SELECT id, data FROM entities WHERE kind='hypothesis' AND engagement_id=?",
        (engagement_id,)).fetchall()
    for r in rows:
        try:
            payload = json.loads(r["data"] or "{}")
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        per: dict[str, float] = {}
        for a in payload.get("actions") or []:
            if not isinstance(a, dict):
                continue
            t, tool = a.get("timeout"), a.get("tool")
            if isinstance(t, (int, float)) and t > 0 and tool:
                per[str(tool)] = max(per.get(str(tool), 0.0), float(t))
        if per:
            out[r["id"]] = per
    return out


def scan_tool_runs(writer, engagement_id: str, *, limit: int = 500) -> list[Failure]:
    """Classify every non-``done`` tool_run for the engagement.

    Read-side only. A missing/locked ``tool_run`` table degrades to an empty
    list rather than killing the loop, and ``build_digest`` counts that.
    """
    con = _conn_of(writer)
    try:
        rows = con.execute(
            """SELECT tr.id, tr.hypothesis_id, tr.tool, tr.command, tr.status,
                      tr.exit_code, tr.stderr_ref
                 FROM tool_run tr
                 JOIN entities e ON e.id = tr.hypothesis_id
                WHERE e.engagement_id = ?
                  AND tr.status != 'done'
                ORDER BY tr.created_at DESC LIMIT ?""",
            (engagement_id, limit)).fetchall()
        timeouts = _hyp_timeouts(con, engagement_id)
    except sqlite3.Error:
        return []

    out: list[Failure] = []
    for r in rows:
        hyp_id, tool = r["hypothesis_id"], r["tool"]
        tmo = (timeouts.get(hyp_id) or {}).get(tool)
        f = classify(status=r["status"], exit_code=r["exit_code"],
                     stderr_text=_tail_file(r["stderr_ref"]),
                     command=r["command"], tool=tool, tool_timeout=tmo)
        out.append(Failure(f.cls, f.reason, f.retryable, f.max_attempts,
                           tool_run_id=r["id"], hypothesis_id=hyp_id, tool=tool))
    return out


def recycle_stuck_hypotheses(writer, engagement_id: str, *,
                             priority_penalty: float = 25.0,
                             max_attempts: int = 3) -> tuple[int, int]:
    '      * attempts remain -> back to ``proposed`` at reduced priority, so the\n        planner can route around it;\n      * attempts exhausted -> ``rejected`` with a reason, so it stops counting\n        as open work and shows up in the health sweep as abandoned.\n\n    Requires a ``db.Database`` WRITER: state changes go through\n    ``upsert_entity`` so they are event-logged and kind-frozen. Attempt\n    counters live in the domain payload (the ``data`` column).\n\n    Raises on a real schema/writer fault instead of returning (0, 0) — see the\n    module docstring for why silence here is the bug, not the safety.\n    Returns ``(recycled, abandoned)``.\n    '
    con = _conn_of(writer)
    inflight_marks = ",".join("?" * len(_INFLIGHT))
    rows = con.execute(
        f"""SELECT h.id,
                   (SELECT COUNT(*) FROM tool_run tr
                     WHERE tr.hypothesis_id = h.id
                       AND tr.status IN ({inflight_marks})) AS inflight,
                   (SELECT COUNT(*) FROM tool_run tr
                     WHERE tr.hypothesis_id = h.id AND tr.status != 'done') AS bad,
                   (SELECT COUNT(*) FROM tool_run tr
                     WHERE tr.hypothesis_id = h.id) AS total
              FROM entities h
             WHERE h.kind='hypothesis' AND h.state='testing'
               AND h.engagement_id = ?""",
        (*_INFLIGHT, engagement_id)).fetchall()

    recycled = abandoned = 0
    for r in rows:
        if r["inflight"]:
            continue                      # still running — never re-plan a live run
        if not r["total"]:
            continue                      # never dispatched; not a failure
        ent = writer.get_entity(r["id"])
        if not ent or ent.get("kind") != "hypothesis":
            continue
        if ent.get("state") != "testing":
            continue                      # raced with another beat

        cls = str(ent.get("failure_class") or "")
        if cls in NEVER_RETRY:
            ent["state"] = "rejected"
            ent["reject_reason"] = f"{cls} is deterministic — no retry"
            ent["finished_at"] = _now()
            writer.upsert_entity(ent)
            abandoned += 1
            continue
        attempts = int(ent.get("attempts") or 0) + 1
        ent["attempts"] = attempts
        ent["last_failure"] = _now()
        ent["failure_class"] = "strategy_error"
        if r["bad"]:
            ent["failure_note"] = f"{r['bad']}/{r['total']} tool runs failed"

        if attempts >= max_attempts:
            ent["state"] = "rejected"
            ent["reject_reason"] = (
                f"abandoned after {attempts} attempts "
                f"({r['bad']}/{r['total']} tool runs failed)")
            abandoned += 1
            aid = ent.get("asset_id")
            rid = ent.get("rule_id")
            if aid and rid:
                asset = writer.get_entity(aid)
                if asset and asset.get("kind") == "asset":
                    counts = dict(asset.get("attempts_by_rule") or {})
                    counts[rid] = int(counts.get(rid, 0)) + 1
                    asset["attempts_by_rule"] = counts
                    writer.upsert_entity(asset)
        else:
            prio = ent.get("priority")
            prio = float(prio) if isinstance(prio, (int, float)) else 50.0
            ent["state"] = "proposed"
            ent["priority"] = max(1.0, prio - float(priority_penalty))
            ent["recycled_from"] = "testing"
            recycled += 1
        ent["finished_at"] = _now()
        writer.upsert_entity(ent)
    return recycled, abandoned


def build_digest(writer, engagement_id: str, *,
                 recover: bool = False) -> FailureDigest:
    """Classify + summarise. ``recover=True`` also runs the recycle pass.

    Read-only by default so tests and inspection cannot mutate the graph; the
    orchestrator opts in to recovery from its health sweep, which owns the
    writer.
    """
    con = _conn_of(writer)
    d = FailureDigest()
    try:
        for f in scan_tool_runs(con, engagement_id):
            d.by_class[f.cls] = d.by_class.get(f.cls, 0) + 1
        for r in con.execute(
                """SELECT tr.tool AS tool, COUNT(*) AS n FROM tool_run tr
                     JOIN entities e ON e.id = tr.hypothesis_id
                    WHERE e.engagement_id=? AND tr.status!='done'
                    GROUP BY tr.tool ORDER BY n DESC LIMIT 5""", (engagement_id,)):
            d.worst_tools.append((r["tool"], r["n"]))
        d.stuck_testing = con.execute(
            "SELECT COUNT(*) n FROM entities WHERE kind='hypothesis' "
            "AND state='testing' AND engagement_id=?", (engagement_id,)).fetchone()["n"]
    except sqlite3.Error:
        d.read_errors += 1
        return d

    if recover:
        reaped = reap_zombie_runs(writer, engagement_id)
        if reaped:
            d.read_errors += 0          # zombies are health, not errors
            d.by_class["tool_timeout"] = d.by_class.get("tool_timeout", 0) + reaped
        if not hasattr(writer, "upsert_entity"):
            # A bare connection cannot recover: state changes must go through
            # the writer so they are event-logged and kind-frozen. Fail loudly
            # rather than silently skipping the recovery the caller asked for.
            raise TypeError(
                "build_digest(recover=True) needs a db.Database writer "
                "(for event-logged upsert_entity); got a raw connection")
        d.recycled, d.abandoned = recycle_stuck_hypotheses(writer, engagement_id)
        d.stuck_testing = con.execute(
            "SELECT COUNT(*) n FROM entities WHERE kind='hypothesis' "
            "AND state='testing' AND engagement_id=?", (engagement_id,)).fetchone()["n"]
    return d


def reap_zombie_runs(writer, engagement_id: str) -> int:
    ''
    import os
    con = _conn_of(writer)
    closed = 0
    try:
        rows = con.execute(
            """SELECT tr.id, tr.pid FROM tool_run tr
                 JOIN entities e ON e.id = tr.hypothesis_id
                WHERE e.engagement_id = ? AND tr.status IN
                      ('running', 'pending', 'queued')""",
            (engagement_id,)).fetchall()
    except sqlite3.Error:
        return 0
    for r in rows:
        pid = r["pid"]
        if not pid:
            continue                    # never registered — not ours to judge
        try:
            alive = os.path.exists(f"/proc/{int(pid)}")
        except (ValueError, OSError):
            alive = True                # unparseable pid: leave it alone
        if alive:
            continue
        try:
            con.execute(
                "UPDATE tool_run SET status='timeout', exit_code=124, "
                "finished_at=? WHERE id=? AND status IN "
                "('running','pending','queued')",
                (_now(), r["id"]))
            con.commit()
            closed += 1
        except sqlite3.Error:
            continue
    return closed
