"Graph health checker — the engine's self-perception of broken links.\n\nLangGraph-class orchestration does not wait for a human audit to notice a\ndead chain: every run ends with a health sweep that flags unconsumed\noutputs, orphan nodes, parser gaps and stuck hypotheses, and the report\nfeeds the wave-loop audit bundle."

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from . import db
from .parsers import _REGISTRY


RUNTIME_ERROR_KINDS: tuple[tuple[str, str, str], ...] = (
    ("rule_attempts_bump_error", "HIGH",
     "the retry guard could not persist; inspect the writer/schema before rerunning"),
    ("hypothesis_retire_error", "HIGH",
     "a completed action may remain in testing; inspect the hypothesis and tool_run rows"),
    ("rule_hit_class_error", "HIGH",
     "a declared finding-class chain failed; inspect the rule-hit event and parser evidence"),
    ("act.executor_error", "MEDIUM",
     "an action executor raised; inspect the hypothesis and its tool-run evidence"),
    ("opsec_cooldown_restore_error", "HIGH",
     "cooldowns may have lifted after restart; verify the persisted cooldown snapshot"),
    ("opsec_cooldown_persist_error", "HIGH",
     "cooldowns may be lost on restart; repair the engagement write path"),
    ("reflector.error", "LOW",
     "the optional reflector failed; the deterministic scheduler remains authoritative"),
)


@dataclass
class HealthIssue:
    severity: str          # HIGH / MEDIUM / LOW
    kind: str              # machine-readable issue class
    message: str
    evidence: str = ""
    suggestion: str = ""

    def to_dict(self) -> dict:
        return {"severity": self.severity, "kind": self.kind,
                "message": self.message, "evidence": self.evidence,
                "suggestion": self.suggestion}


@dataclass
class HealthReport:
    engagement_id: str
    issues: list[HealthIssue] = field(default_factory=list)

    def markdown(self) -> str:
        lines = [f"# Graph health report — {self.engagement_id}",
                 f"issues: {len(self.issues)}"]
        by_sev = {}
        for i in self.issues:
            by_sev.setdefault(i.severity, []).append(i)
        for sev in ("HIGH", "MEDIUM", "LOW"):
            for i in by_sev.get(sev, []):
                lines.append(f"\n## [{sev}] {i.kind}")
                lines.append(f"- {i.message}")
                if i.evidence:
                    lines.append(f"- Evidence: {i.evidence}")
                if i.suggestion:
                    lines.append(f"- Suggestion: {i.suggestion}")
        return "\n".join(lines)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "HIGH")


def check_health(engagement_id: str, *, root: Path | None = None,
                 rules_dir: Path | None = None) -> HealthReport:
    edir = db.engagement_dir(root or db.default_root(), engagement_id)
    g = edir / "graph.db"
    report = HealthReport(engagement_id=engagement_id)
    if not g.exists():
        report.issues.append(HealthIssue(
            "HIGH", "no_graph", f"engagement {engagement_id} has no graph.db",
            suggestion="run `motoko init` first"))
        return report

    if rules_dir is None:
        # The rule-aware checks (on_hit_class orphans, service consumers)
        # return early on a None rules_dir, so a caller that omitted it got a
        # report that silently skipped them — `motoko health` did exactly that
        # from the day the checks landed. Default to the corpus that ships
        # with this engine instead of degrading quietly.
        from . import rulecheck
        rules_dir = rulecheck.rules_dir_default()

    con = sqlite3.connect(g)
    con.row_factory = sqlite3.Row
    try:
        _check_orphan_assets(con, engagement_id, report)
        _check_parser_gaps(con, report)
        _check_dead_letters(con, report)
        _check_stuck_testing(con, engagement_id, report)
        _check_on_hit_class_orphans(rules_dir, con, engagement_id, report)
        _check_service_consumers(rules_dir, con, report)
        _check_scope_blocked(con, report)
        _check_verification_blocked(con, engagement_id, report)
        _check_dangling_edges(con, report)
        _check_uningested_observations(con, engagement_id, report)
        _check_runtime_errors(con, engagement_id, report)
    finally:
        con.close()
    return report


def _check_orphan_assets(con, engagement_id: str, report: HealthReport) -> None:
    """Assets that are neither frontier nor referenced by any hypothesis —
    they can never re-enter the chain."""
    referenced = set()
    for r in con.execute(
            "SELECT data FROM entities WHERE kind='hypothesis' AND engagement_id=?",
            (engagement_id,)):
        try:
            aid = json.loads(r["data"]).get("asset_id")
        except (TypeError, json.JSONDecodeError):
            aid = None
        if aid:
            referenced.add(aid)
    orphans = []
    for r in con.execute(
            "SELECT id, data FROM entities WHERE kind='asset' "
            "AND engagement_id=?", (engagement_id,)):
        try:
            d = json.loads(r["data"])
        except (TypeError, json.JSONDecodeError):
            continue
        if d.get("frontier") or r["id"] in referenced:
            continue
        orphans.append(d.get("value", "?"))
    if orphans:
        report.issues.append(HealthIssue(
            "LOW", "orphan_assets",
            f"{len(orphans)} assets are closed and never referenced — dead ends",
            evidence=", ".join(str(x) for x in orphans[:5]),
            suggestion="check the asset type has a consuming rule"))


def _check_parser_gaps(con, report: HealthReport) -> None:
    """Tools that ran but have no parser — their output went to dead_letter."""
    ran = {r["tool"] for r in con.execute(
        "SELECT DISTINCT tool FROM tool_run")}
    missing = sorted(t for t in ran if t not in _REGISTRY)
    if missing:
        report.issues.append(HealthIssue(
            "HIGH", "tool_without_parser",
            f"tools executed with no parser: {', '.join(missing)}",
            evidence="their stdout is dead-lettered; zero graph yield",
            suggestion="write a parser or demote the rule to registry-only"))


def _check_dead_letters(con, report: HealthReport) -> None:
    n = con.execute(
        "SELECT COUNT(*) n FROM events WHERE kind='observation_dead_letter'"
    ).fetchone()["n"]
    if n:
        report.issues.append(HealthIssue(
            "MEDIUM", "dead_letter_volume",
            f"{n} parser dead-letter events",
            suggestion="review obs/ dead letters; the largest ones hide "
                      "unparsed tool output shapes"))


def _check_stuck_testing(con, engagement_id: str, report: HealthReport) -> None:
    'Hypotheses in ``testing`` with no run in flight have no forward path.\n\n    * ``failure.recycle_stuck_hypotheses`` now closes that gap — it is called\n      per cycle from ``orchestrator._recover_failures``, before ``_prioritize``,\n      so a stranded hypothesis returns to ``proposed`` (or is ``rejected`` once\n      its attempts are exhausted).\n    * The raw count cried wolf: a hypothesis with a ``running``/``pending``\n      tool_run is legitimately testing (a strix deep-dive holds that state for\n      up to 7200s), and one that was never dispatched is not a failure either.\n\n    So only count the genuinely stranded ones — dispatched, nothing in flight,\n    still ``testing``. Anything left here means the recovery pass did not run\n    (or could not act), which is a real defect worth reporting.\n    '
    n = con.execute(
        """SELECT COUNT(*) n FROM entities h
            WHERE h.kind='hypothesis' AND h.state='testing' AND h.engagement_id=?
              AND EXISTS (SELECT 1 FROM tool_run tr WHERE tr.hypothesis_id=h.id)
              AND NOT EXISTS (SELECT 1 FROM tool_run tr
                               WHERE tr.hypothesis_id=h.id
                                 AND tr.status IN ('pending','running','queued'))""",
        (engagement_id,)).fetchone()["n"]
    if n:
        report.issues.append(HealthIssue(
            "MEDIUM", "stuck_testing",
            f"{n} hypotheses sit in state=testing with every tool_run finished "
            "(stranded — no forward path)",
            suggestion="failure.recycle_stuck_hypotheses should have returned "
                       "these to 'proposed' or 'rejected'; the recovery pass in "
                       "orchestrator._recover_failures did not run or raised"))


def _check_on_hit_class_orphans(rules_dir: Path | None, con, engagement_id: str,
                                report: HealthReport) -> None:
    """Rules declaring on_hit_class that no other rule consumes."""
    if rules_dir is None or not Path(rules_dir).exists():
        return
    declared: dict[str, str] = {}
    consumers: set[str] = set()
    for p in Path(rules_dir).rglob("*.json"):
        try:
            rule = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        hit = (rule.get("then") or {}).get("on_hit_class")
        if hit:
            declared[hit] = rule["id"]
        for cond in ((rule.get("when") or {}).get("all") or []) + \
                    ((rule.get("when") or {}).get("any") or []):
            if cond.get("fact") == "class" and isinstance(cond.get("value"), str):
                consumers.add(cond["value"])
    orphaned = [c for c, rid in declared.items()
                if c not in consumers and not any(c in x for x in consumers)]
    if orphaned:
        report.issues.append(HealthIssue(
            "MEDIUM", "on_hit_class_orphan",
            f"on_hit_class declared but consumed by no rule: {', '.join(orphaned)}",
            suggestion="add a bridge rule or drop the declaration"))


def _check_service_consumers(rules_dir: Path | None, con, report: HealthReport) -> None:
    n_services = con.execute("SELECT COUNT(*) n FROM services").fetchone()["n"]
    if not n_services:
        return
    consumes = False
    if rules_dir and Path(rules_dir).exists():
        for p in Path(rules_dir).rglob("*.json"):
            try:
                rule = json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            for cond in ((rule.get("when") or {}).get("all") or []) + \
                        ((rule.get("when") or {}).get("any") or []):
                if cond.get("fact") in ("service", "services"):
                    consumes = True
    if not consumes:
        report.issues.append(HealthIssue(
            "HIGH", "service_no_consumer",
            f"{n_services} services in the graph but no rule consumes them",
            suggestion="service facts are chain input (SMB etc.) — wire a rule"))


def _check_scope_blocked(con, report: HealthReport) -> None:
    n = con.execute(
        "SELECT COUNT(*) n FROM events WHERE kind='scope_blocked'").fetchone()["n"]
    if n > 5:
        report.issues.append(HealthIssue(
            "MEDIUM", "scope_blocked_volume",
            f"{n} scope_blocked events",
            suggestion="high volume = rules firing on out-of-scope assets; "
                      "add ingest-time scope tagging (M-9)"))


def _check_dangling_edges(con, report: HealthReport) -> None:
    n = con.execute(
        "SELECT COUNT(*) n FROM edges e WHERE NOT EXISTS "
        "(SELECT 1 FROM entities WHERE id=e.from_id) OR NOT EXISTS "
        "(SELECT 1 FROM entities WHERE id=e.to_id)").fetchone()["n"]
    if n:
        report.issues.append(HealthIssue(
            "MEDIUM", "dangling_edges",
            f"{n} edges reference missing entities",
            suggestion="ingest-time edge validation is missing"))


def _check_uningested_observations(con, engagement_id: str, report: HealthReport) -> None:
    n = con.execute(
        "SELECT COUNT(*) n FROM observations WHERE engagement_id=? "
        "AND processed_at IS NULL", (engagement_id,)).fetchone()["n"]
    if n:
        report.issues.append(HealthIssue(
            "LOW", "uningested_observations",
            f"{n} observations never ingested (processed_at NULL)",
            suggestion="they were recorded after the last SYNC — one more "
                       "run cycle ingests them"))


def _check_runtime_errors(con, engagement_id: str, report: HealthReport) -> None:
    """Aggregate safety-relevant error events without exposing their payloads.

    Events are stored in the engagement's own database, and their
    ``entity_id`` is sometimes an entity id and sometimes the engagement id
    itself.  One issue per event kind avoids turning a repeated failure into
    an unreadable event dump while retaining the count and a few opaque ids
    for audit lookup.
    """
    specs = {kind: (severity, suggestion)
             for kind, severity, suggestion in RUNTIME_ERROR_KINDS}
    placeholders = ",".join("?" for _ in specs)
    rows = con.execute(
        f"SELECT kind, entity_id, COUNT(*) AS n FROM events "
        f"WHERE kind IN ({placeholders}) "
        "GROUP BY kind, entity_id ORDER BY kind, entity_id",
        sorted(specs)).fetchall()
    grouped: dict[str, list[tuple[str | None, int]]] = {}
    for row in rows:
        grouped.setdefault(row["kind"], []).append((row["entity_id"], row["n"]))
    for kind, entries in grouped.items():
        severity, suggestion = specs[kind]
        count = sum(n for _entity_id, n in entries)
        ids = [str(entity_id) for entity_id, _n in entries if entity_id]
        evidence = ", ".join(ids[:6])
        if len(ids) > 6:
            evidence += ", ..."
        report.issues.append(HealthIssue(
            severity, "runtime_error_event",
            f"{count} {kind} event(s) recorded",
            evidence=evidence,
            suggestion=suggestion))


# What a parked finding is waiting for, per reason code. The point of the
# report is that "we could not verify" is actionable: each row names the
# backend or assertion whose absence caused it.
_BLOCK_SUGGESTIONS: dict[str, str] = {
    "egress_policy":
        "the built-in replay fetcher fails closed (the internal doctrine). Run the engine "
        "inside the verified anonymous lane and assert "
        "MOTOKO_ALLOW_DIRECT_REPLAY=1 there, or inject a fetcher that egresses "
        "through the campaign proxy",
    "missing_backend":
        "wire the backend the validator needs: a headless browser for dom "
        "(playwright + chromium), a canary manager for oob (interactsh / "
        "--oob-domain). `motoko doctor` reports what is missing",
    "io_exhausted":
        "three consecutive transport failures: check egress, proxy and target "
        "reachability, then clear validator_attempts to re-queue",
    "unpinned":
        "the scope guard cleared the url without an A record to pin, so the "
        "replay refuses to connect (DNS rebinding window) — check resolver "
        "config for that host",
    "no_target":
        "the finding carries no url; only an ingest path or a manual verifier "
        "can decide it",
    "no_validator":
        "the finding's class routes to a validator that is not implemented",
}


def _check_verification_blocked(con, engagement_id: str,
                                report: HealthReport) -> None:
    'Findings this deployment could not verify, grouped by reason.'
    by_reason: dict[str, list[tuple]] = {}
    for r in con.execute(
            "SELECT id, data FROM entities WHERE kind='finding' "
            "AND engagement_id=?", (engagement_id,)):
        try:
            d = json.loads(r["data"])
        except (TypeError, json.JSONDecodeError):
            continue
        block = d.get("verification_blocked") or {}
        reason = block.get("reason")
        if not reason:
            continue
        by_reason.setdefault(reason, []).append(
            (r["id"], d.get("class") or "", str(d.get("severity") or "").lower(),
             d.get("state") or "", block.get("validator") or ""))

    # scope_blocked is the guard working as designed, not a capability gap —
    # it is reported, but it never escalates the severity.
    for reason, rows in sorted(by_reason.items()):
        serious = [x for x in rows if x[2] in ("critical", "high")]
        if reason == "scope_blocked":
            sev = "LOW"
        elif serious:
            sev = "HIGH"
        else:
            sev = "MEDIUM"
        ids = ", ".join(f"{c or i}" for i, c, _s, _st, _v in rows[:6])
        report.issues.append(HealthIssue(
            sev, "verification_blocked",
            f"{len(rows)} finding(s) unverified — reason {reason}"
            + (f", {len(serious)} of them critical/high" if serious else "")
            + f": {ids}" + (" ..." if len(rows) > 6 else ""),
            evidence=f"validators: "
                     f"{', '.join(sorted({v for *_, v in rows if v})) or 'n/a'}"
                     f" | states: "
                     f"{', '.join(sorted({st for *_x, st, v in rows if st})) or 'n/a'}",
            suggestion=_BLOCK_SUGGESTIONS.get(
                reason, "inspect the verification_blocked field on the finding")))
