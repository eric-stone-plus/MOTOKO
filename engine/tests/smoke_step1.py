"""Step-1 smoke: single-writer schema + entity/edge/event round-trip."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from motoko import db, util  # noqa: E402


def main() -> None:
    root = Path(tempfile.mkdtemp(prefix="motoko-step1-"))
    eng = "eng-test-1"

    edir = db.init_engagement(
        root, eng,
        name="smoke",
        in_scope=["example.com", "10.0.0.0/24"],
        out_of_scope=["partner.example.com"],
        intensity="normal",
        max_depth=3,
        concurrency=4,
    )
    print("engagement dir:", edir)

    writer = db.Database(edir / "graph.db")
    writer.init_schema()

    # entity round-trip
    asset_id = util.new_id("asset")
    writer.upsert_entity({
        "id": asset_id, "kind": "asset", "engagement_id": eng,
        "state": "active", "type": "domain", "value": "example.com",
    })
    got = writer.get_entity(asset_id)
    assert got is not None and got["kind"] == "asset", got
    print("entity upsert+get OK:", got["id"], got["value"])

    # edge
    fnd_id = util.new_id("finding")
    writer.upsert_entity({
        "id": fnd_id, "kind": "finding", "engagement_id": eng,
        "state": "candidate", "confidence": 0.4,
        "class": "xss.reflected", "title": "XSS in /search",
    })
    eid = writer.add_edge(asset_id, fnd_id, "discovered_on", engagement_id=eng)
    edges = writer.get_edges(from_id=asset_id)
    assert len(edges) == 1 and edges[0]["rel"] == "discovered_on", edges
    print("edge add OK:", eid, edges[0]["rel"])

    # state change goes through the single door (state machine + event, F06)
    ok, reason = writer.advance_and_persist(fnd_id, "dedup_pass", actor="validator")
    assert ok, reason
    got = writer.get_entity(fnd_id)
    assert got["state"] == "triaged", got
    print("transition OK:", got["state"])

    # services / scope / cache / tool_run / observation
    writer.add_service({"asset_id": asset_id, "port": 443, "service_name": "https", "product": "nginx"})
    sc = writer.get_scope(eng)
    assert sc is not None and "example.com" in sc["in_scope"], sc
    print("scope OK:", sc["in_scope"])

    run_id = writer.start_tool_run(tool="nuclei", command="nuclei -u x")
    writer.set_tool_run_pid(run_id, 1234)
    writer.finish_tool_run(run_id, status="done", exit_code=0)
    writer.cache_put("k1", asset_id=asset_id, tool="nuclei", result_hash="h1")
    oid = writer.record_observation(
        tool="nuclei", engagement_id=eng, raw_path=None,
        parsed_summary="1 matched", new_finding_ids=[fnd_id], exit_code=0,
    )
    print("tool_run/cache/observation OK:", run_id, oid)

    writer.commit()
    writer.close()

    # read-only reopen
    ro = db.Database(edir / "graph.db", read_only=True)
    n_findings = len(ro.query_entities(kind="finding"))
    print("read-only reopen, findings =", n_findings)
    assert n_findings == 1
    ro.close()

    print("STEP1 SMOKE OK")


if __name__ == "__main__":
    main()
