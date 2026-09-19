"""Bounded scan waves with persisted, evidence-driven scheduling feedback.

This is runtime planning, separate from the engineering audit loop. Rules
remain the source of executable actions. Feedback changes their queue order
within a fixed range; it cannot invent commands, widen scope, or confirm a
finding. Events in the engagement database carry the resumable policy.
"""

from __future__ import annotations

import json
import math


class ScanWaves:
    def __init__(self, writer, engagement_id: str):
        self.writer = writer
        self.engagement_id = engagement_id
        self.number = 1
        self.priority_offsets: dict[str, float] = {}
        self.history: list[dict] = []
        self.cycles = 0
        row = writer.conn.execute(
            "SELECT payload FROM events WHERE kind = 'scan.wave.completed' "
            "AND entity_id = ? ORDER BY seq DESC LIMIT 1", (engagement_id,)).fetchone()
        if row:
            try:
                data = json.loads(row["payload"])
                self.number = int(data["wave"]) + 1
                for rid, value in data["priority_offsets"].items():
                    if not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value):
                        self.priority_offsets[rid] = max(-30.0, min(15.0, float(value)))
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise ValueError("invalid scan-wave history; repair it before resuming") from exc
        self.begin()

    def begin(self) -> None:
        self.cycles = 0
        self.cursor = self.writer.conn.execute(
            "SELECT COALESCE(MAX(rowid), 0) FROM tool_run").fetchone()[0]
        self.known_ids = {e["id"] for e in self.writer.query_entities(
            engagement_id=self.engagement_id) if e["kind"] in {"asset", "finding"}}

    def score(self, hyp: dict) -> float:
        base = hyp.get("priority") or 0
        if isinstance(base, bool) or not isinstance(base, (int, float)) or not math.isfinite(base):
            base = 0
        return float(base) + self.priority_offsets.get(hyp.get("rule_id"), 0.0)

    def complete(self, *, stop_reason: str, pending: int) -> dict:
        rows = self.writer.conn.execute(
            "SELECT t.id, t.status, e.data FROM tool_run t "
            "JOIN entities e ON e.id = t.hypothesis_id "
            "WHERE t.rowid > ? AND e.engagement_id = ? ORDER BY t.rowid",
            (self.cursor, self.engagement_id)).fetchall()
        stats: dict[str, dict] = {}
        credited: set[str] = set()
        for row in rows:
            rid = json.loads(row["data"]).get("rule_id") or "unbound"
            stat = stats.setdefault(rid, {"runs": 0, "done": 0, "failed": 0,
                                          "discoveries": 0, "duration_s": 0.0})
            stat["runs"] += 1
            stat["done"] += row["status"] == "done"
            stat["failed"] += row["status"] in {"error", "timeout", "cancelled"}
            observations = self.writer.conn.execute(
                "SELECT new_asset_ids, new_finding_ids, duration_s FROM observations "
                "WHERE action_id = ? AND engagement_id = ?",
                (row["id"], self.engagement_id)).fetchall()
            for obs in observations:
                for col in ("new_asset_ids", "new_finding_ids"):
                    ids = json.loads(obs[col] or "[]")
                    new = set(ids) - self.known_ids - credited
                    stat["discoveries"] += len(new)
                    credited.update(new)
                stat["duration_s"] += max(0.0, float(obs["duration_s"] or 0))
        for rid, stat in stats.items():
            n = stat["runs"]
            # Negative results still earn coverage; exploration loses at most
            # two points per empty wave. Failures cost more than empty success.
            utility = (15.0 * min(1.0, stat["discoveries"] / n)
                       - 30.0 * stat["failed"] / n
                       - (4.0 if not stat["discoveries"] and not stat["failed"] else 0.0))
            old = self.priority_offsets.get(rid, 0.0)
            self.priority_offsets[rid] = round(max(-30.0, min(15.0, (old + utility) / 2)), 2)
            stat["duration_s"] = round(stat["duration_s"], 3)
        result = {"wave": self.number, "cycles": self.cycles,
                  "stop_reason": stop_reason, "pending": pending, "rules": stats,
                  "priority_offsets": dict(self.priority_offsets)}
        self.writer.append_event("scan.wave.completed", self.engagement_id, result)
        self.writer.commit()
        self.history.append(result)
        self.number += 1
        self.begin()
        return result

    def prompt_lines(self) -> list[str]:
        if not self.history:
            return []
        latest = self.history[-1]
        return [f"Completed scan wave: {latest['wave']}",
                "Rule outcomes: " + json.dumps(latest["rules"], sort_keys=True),
                "Bounded priority offsets: " + json.dumps(self.priority_offsets, sort_keys=True)]
