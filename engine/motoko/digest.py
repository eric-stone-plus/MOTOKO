"""Digest generator — the ONLY thing injected into the Hermes context.

Aggregates the graph into a <=2KB markdown summary. Raw tool output, entity
blobs, and credential material NEVER enter the digest; counts and short
pointers only. Regenerated each checkpoint by ``motoko digest``.
"""

from __future__ import annotations

from collections import Counter

MAX_DIGEST_CHARS = 2048


def build_digest(db, engagement_id: str) -> str:
    assets = db.query_entities(kind="asset", engagement_id=engagement_id)
    findings = db.query_entities(kind="finding", engagement_id=engagement_id)
    hypotheses = db.query_entities(kind="hypothesis", engagement_id=engagement_id)
    paths = db.query_entities(kind="path", engagement_id=engagement_id)
    access = db.query_entities(kind="access", engagement_id=engagement_id)

    by_state = Counter(f.get("state") for f in findings)
    frontier = sum(1 for a in assets if a.get("frontier"))
    active_access = [a for a in access if a.get("valid", True)]
    active_paths = [p for p in paths if p.get("state") == "active"]

    top_hyps = sorted(hypotheses, key=lambda h: h.get("priority", 0) or 0, reverse=True)[:3]
    n_events = db.conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]

    lines: list[str] = []
    lines.append(f"## MOTOKO digest ({engagement_id}, events {n_events})")
    lines.append(
        f"- assets {len(assets)} (frontier {frontier}) | findings {len(findings)} "
        f"(cand {by_state.get('candidate', 0)} / triaged {by_state.get('triaged', 0)} / "
        f"repr {by_state.get('reproduced', 0)} / ver {by_state.get('verified', 0)} / "
        f"exp {by_state.get('exploitable', 0)} / impact {by_state.get('confirmed_impact', 0)} / "
        f"fp {by_state.get('false_positive', 0)})"
    )
    if active_access:
        acc = ", ".join(f"{a.get('level', '?')}({a.get('principal', '?')})" for a in active_access[:4])
        lines.append(f"- access: {acc}")
    if top_hyps:
        h = " | ".join(f"[{x['id'][:14]}] {x.get('statement', x.get('text', '?'))[:40]} (pri {x.get('priority')})"
                       for x in top_hyps)
        lines.append(f"- top hypotheses: {h}")
    if active_paths:
        p = " | ".join(f"{x['id'][:14]} {x.get('name', '?')} (conf {x.get('confidence')})"
                       for x in active_paths[:2])
        lines.append(f"- active paths: {p}")
    # recent transitions (last 3 entity transitions)
    recent = db.conn.execute(
        "SELECT entity_id, payload FROM events WHERE kind='entity.transition' "
        "ORDER BY seq DESC LIMIT 3"
    ).fetchall()
    if recent:
        t = " | ".join(f"{r['entity_id'][:12]} -> {_payload_to(r['payload'])}" for r in recent)
        lines.append(f"- recent: {t}")

    out = "\n".join(lines)
    return out[:MAX_DIGEST_CHARS]


def _payload_to(payload: str | None) -> str:
    import json
    try:
        d = json.loads(payload or "{}")
    except json.JSONDecodeError:
        return "?"
    return str(d.get("to", "?"))


def write_digest(db, engagement_id: str, out_path) -> str:
    text = build_digest(db, engagement_id)
    from pathlib import Path
    Path(out_path).write_text(text)
    return text
