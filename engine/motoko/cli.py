"""MOTOKO CLI — single-writer process entry point.

Commands:
    init      create an engagement (dir + graph.db + scope row)
    run       run the six-beat main loop with the real tool executor
    digest    print the <=2KB context digest (read-only)
    query     list entities (read-only)
    events    tail the event log (read-only)
    seal      seal a finished engagement (checkpoint + integrity + manifest)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import db, digest, util
from . import asset_link


def _open_ro(args):
    edir = db.engagement_dir(db.default_root(), args.engagement_id)
    return db.Database(edir / "graph.db", read_only=True)


def cmd_init(args) -> int:
    from . import util
    from .scope import ScopeGuard

    # R5 M1: a seed only enters the graph if it passes the same scope guard
    # the ACT beat applies. Checked BEFORE anything is created, so a
    # rejected batch (typo'd or unauthorized seed) leaves no engagement
    # behind. No --force: a bad seed is an error, not a warning.
    guard = ScopeGuard(args.scope or [], args.out_of_scope or [])
    for s in args.seed or []:
        decision = guard.check_url(s)
        if not decision.allowed:
            print(f"seed rejected by scope guard: {s!r}: {decision.reason}",
                  file=sys.stderr)
            return 2

    edir = db.init_engagement(
        db.default_root(),
        args.engagement_id,
        name=args.name or "",
        in_scope=args.scope or [],
        out_of_scope=args.out_of_scope or [],
        intensity=args.intensity,
        max_depth=args.max_depth,
        concurrency=args.concurrency,
        oob_domain=args.oob_domain,
    )
    if args.seed:
        w = db.Database(edir / "graph.db")
        try:
            for s in args.seed:
                w.upsert_entity({
                    "id": util.new_id("asset"),
                    "kind": "asset",
                    "engagement_id": args.engagement_id,
                    "state": "active",
                    "type": "url",
                    "value": s,
                    "frontier": True,
                    "source": "seed",
                })
        finally:
            w.close()
    print(f"engagement initialized: {edir}")
    return 0


def cmd_digest(args) -> int:
    ro = _open_ro(args)
    try:
        print(digest.build_digest(ro, args.engagement_id))
    finally:
        ro.close()
    return 0


def cmd_run(args) -> int:
    """Run the six-beat main loop with the real subprocess executor."""
    import sys as _sys

    from . import orchestrator, reflector as reflector_mod
    from .executor import SubprocessExecutor

    # R5 M2: refuse to start on a missing engagement. sqlite3.connect would
    # otherwise silently create an empty graph.db and the run would report
    # a hollow success against nothing.
    edir = db.engagement_dir(db.default_root(), args.engagement_id)
    if not (edir / "graph.db").exists():
        print(f"engagement {args.engagement_id!r} not found: no graph.db at "
              f"{edir} — run `motoko init {args.engagement_id}` first",
              file=_sys.stderr)
        return 2

    reflector = None
    if args.reflector:
        reflector = reflector_mod.reflector_from_env()
        if reflector is None:
            print("--reflector requested but MOTOKO_REFLECTOR_MODEL, "
                  "MOTOKO_REFLECTOR_BASE_URL or the key env is unset; "
                  "continuing without a reflector",
                  file=_sys.stderr)
    orch = orchestrator.Orchestrator(
        args.engagement_id, rules_dir=args.rules_dir or None,
        reflector=reflector)
    orch.executor = SubprocessExecutor(
        orch.writer, orch.engagement_id, orch.artifacts,
        tool_timeout=args.timeout)
    try:
        summary = orch.run(max_cycles=args.max_cycles)
    finally:
        orch.close()
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_query(args) -> int:
    ro = _open_ro(args)
    try:
        rows = ro.query_entities(kind=args.kind, state=args.state,
                                 engagement_id=args.engagement_id)
        for r in rows:
            title = r.get("title") or r.get("value") or r.get("name") or r.get("statement") or ""
            print(f"{r['id']}\t{r.get('state', '-')}\t{r.get('confidence', '-')}\t{title[:60]}")
        print(f"--- {len(rows)} rows")
    finally:
        ro.close()
    return 0


def cmd_events(args) -> int:
    ro = _open_ro(args)
    try:
        rows = ro.conn.execute(
            "SELECT seq, at, kind, entity_id, payload FROM events ORDER BY seq DESC LIMIT ?",
            (args.limit,),
        ).fetchall()
        for r in reversed(rows):
            print(f"{r['seq']}\t{r['kind']}\t{r['entity_id'] or '-'}\t{r['payload'] or ''}")
    finally:
        ro.close()
    return 0


def cmd_kali(args) -> int:
    """Manage the kali-recon tool container (podman), CLI-only."""
    import shutil
    import subprocess

    podman = shutil.which("podman")
    if podman is None:
        print("podman not found", file=sys.stderr)
        return 1
    name = args.container

    if args.action == "status":
        r = subprocess.run(
            [podman, "ps", "-a", "--filter", f"name={name}",
             "--format", "{{.Names}} {{.Status}}"],
            capture_output=True, text=True, timeout=30)
        print(r.stdout.strip() or f"container {name!r} does not exist")
        return 0

    if args.action == "start":
        r = subprocess.run(
            [podman, "ps", "-a", "--filter", f"name={name}",
             "--format", "{{.Names}}"], capture_output=True, text=True,
            timeout=30)
        if name in r.stdout:
            r = subprocess.run([podman, "start", name],
                               capture_output=True, text=True, timeout=120)
        else:
            # long-lived toolbox container; tools reach it via `podman exec`
            r = subprocess.run(
                [podman, "run", "-d", "--name", name, "--network", "host",
                 args.image, "sleep", "infinity"],
                capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            print(f"{name}: started")
            return 0
        print(f"{name}: start failed (exit {r.returncode}) "
              f"{r.stderr.strip()[:200]}", file=sys.stderr)
        return 1

    if args.action == "stop":
        r = subprocess.run([podman, "stop", name],
                           capture_output=True, text=True, timeout=120)
        print(f"{name}: stopped (exit {r.returncode})")
        return r.returncode
    return 1


def cmd_strix(args) -> int:
    """Launch a strix deep-dive session on one target asset (CLI-only).

    strix is the autonomous LLM agent from the MIMO package — this command is
    the manual/out-of-band deep-dive interface; inside the graph the same
    tool fires via R-CTX-STRIX-001.
    """
    import shutil
    import subprocess
    from pathlib import Path

    from . import util

    strix = shutil.which("strix") or str(Path.home() / ".local" / "bin" / "strix")
    if not Path(strix).exists():
        print("strix binary not found", file=sys.stderr)
        return 1
    edir = db.engagement_dir(db.default_root(), args.engagement_id)
    out = Path(args.output) if args.output else edir / f"strix-{util.now_iso()}.md"
    prompt = (f"Deep-dive authorized penetration test on {args.target}: "
              "enumerate the hidden API surface, auth flows, and client-side "
              "secrets. Report every URL, parameter and CVE found.")
    print(f"launching strix deep-dive on {args.target} -> {out}", file=sys.stderr)
    r = subprocess.run([strix, "-p", prompt, "--permission-mode",
                        "bypassPermissions"],
                       capture_output=True, text=True, timeout=3600)
    out.write_text(r.stdout or r.stderr or "(empty strix session)")
    print(f"report: {out} (exit {r.returncode})")
    return 0 if r.returncode == 0 else 1


# -- loop driver (cli) --------------------------------------------------

REQUIRED_LOOP_KEYS = {
    "auditors": ("name", "protocol"),
    "adjudicator": ("name", "protocol"),
}


def validate_loop_config(cfg: dict) -> list[str]:
    """Return a list of human-readable config problems (empty = valid)."""
    problems: list[str] = []
    auditors = cfg.get("auditors")
    if not auditors:
        problems.append("missing 'auditors' (need at least one audit leg)")
    elif not isinstance(auditors, list):
        problems.append("'auditors' must be a list of endpoint maps")
    else:
        for i, a in enumerate(auditors):
            if not isinstance(a, dict):
                problems.append(f"auditors[{i}] is not a map")
                continue
            for key in REQUIRED_LOOP_KEYS["auditors"]:
                if not a.get(key):
                    problems.append(f"auditors[{i}]: missing '{key}'")
            if a.get("protocol") == "anthropic" and not a.get("base_url"):
                problems.append(f"auditors[{i}]: anthropic protocol needs "
                                f"'base_url'")
            if a.get("protocol") == "cli" and not a.get("command"):
                problems.append(f"auditors[{i}]: cli protocol needs "
                                f"'command'")
    adj = cfg.get("adjudicator")
    if not adj:
        problems.append("missing 'adjudicator' (the converge beat needs one)")
    elif isinstance(adj, dict):
        for key in REQUIRED_LOOP_KEYS["adjudicator"]:
            if not adj.get(key):
                problems.append(f"adjudicator: missing '{key}'")
        if adj.get("protocol") == "anthropic" and not adj.get("base_url"):
            problems.append("adjudicator: anthropic protocol needs "
                            "'base_url'")
        if adj.get("protocol") == "cli" and not adj.get("command"):
            problems.append("adjudicator: cli protocol needs 'command'")
    return problems


def _sha256sums(round_dir: Path) -> Path:
    """Write SHA256SUMS for every artifact in round_dir (its own hash
    excluded). Returns the sums file path."""
    import hashlib

    lines: list[str] = []
    for p in sorted(round_dir.rglob("*")):
        if not p.is_file() or p.name == "SHA256SUMS":
            continue
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{h}  {p.relative_to(round_dir)}")
    sums = round_dir / "SHA256SUMS"
    sums.write_text("\n".join(lines) + ("\n" if lines else ""))
    return sums


def _append_pitfall(repo_root: Path, round_name: str, text: str) -> None:
    """Append a numbered entry to plans/waves/pitfall-log.md (append-only
    per runbook §五-6). Only called when the round actually produced one."""
    log = repo_root / "plans" / "waves" / "pitfall-log.md"
    n = 0
    if log.exists():
        for line in log.read_text().splitlines():
            m = re.match(r"^## P-(\d+)", line)
            if m:
                n = max(n, int(m.group(1)))
    entry = (f"\n## P-{n + 1:03d} loop round {round_name} — open "
             f"(auto-appended by motoko loop)\n\n- {text}\n")
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a") as f:
        f.write(entry)


def cmd_loop(args) -> int:
    """Drive the wave-loop: N rounds of audit -> adjudicate -> evaluate,
    executing ROLLBACK/STOP verdicts until the loop stops itself."""
    import time
    from pathlib import Path

    from . import loop, util

    cfg_path = Path(args.config) if args.config else loop.default_config_path()
    if not cfg_path.exists():
        print(f"loop config not found: {cfg_path} "
              f"(pass --config, set MOTOKO_CONFIG, or create "
              f"motoko/config/loop.yaml)", file=sys.stderr)
        return 2
    cfg = loop.load_loop_config(cfg_path)
    problems = validate_loop_config(cfg)
    if problems:
        print("loop config invalid:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2

    runner = loop.LoopRunner(args.engagement_id, config=cfg)
    rounds = min(args.rounds, 5)          # HARD_MAX_ROUNDS fuse
    repo_root = runner.engine_root.parent

    # round dirs follow the plans/waves/<wave>/round-N convention
    if args.out:
        wave = Path(args.out)
    else:
        wave = repo_root / "plans" / "waves" / f"loop-{util.now_iso()[:10]}"
    wave.mkdir(parents=True, exist_ok=True)

    extra = Path(args.extra).read_text() if args.extra else ""
    summaries = []
    stopped = False
    # Round numbering RESUMES from the wave dir (round-2 audit finding: a
    # fresh `--rounds 1` launch used to stamp "round-1" again and reuse an
    # existing round's directory).
    existing = sorted(int(m.group(1)) for d in wave.iterdir()
                      if (m := re.fullmatch(r"round-(\d+)", d.name)))
    start = (existing[-1] + 1) if existing else 1
    for n in range(start, start + rounds):
        round_dir = wave / f"round-{n}"
        t0 = time.monotonic()
        try:
            result = runner.run_round(round_dir, extra=extra)
        except loop.LoopEvaluationError as e:
            print(f"round {n}: evaluation failed: {e}", file=sys.stderr)
            return 3
        vj = result["verdict_json"]
        action = vj.get("action", "CONTINUE")

        entry = {"round": n, "dir": str(round_dir), "action": action,
                 "reason": vj.get("reason"),
                 "elapsed_s": round(time.monotonic() - t0, 1)}
        print(json.dumps(entry, ensure_ascii=False))

        # -- verdict execution ------------------------------------------
        if action == "ROLLBACK":
            try:
                rb = runner.apply_verdict(vj, round_dir=round_dir)
            except loop.LoopRollbackError as e:
                # P0-4: apply_verdict archives the refusal itself; this is
                # belt and braces so the driver never dies mid-wave.
                rb = {"action": "ROLLBACK", "executed": False,
                      "degraded_to": "STOP", "reason": str(e)}
            entry["rollback"] = rb
            # after a rollback the round is spent; next round re-audits
        elif action == "STOP":
            sp = runner.apply_verdict(vj, round_dir=round_dir)
            entry["stop"] = sp
            stopped = True

        # archive: SHA256 manifest of everything this round produced
        _sha256sums(round_dir)
        summaries.append(entry)

        if stopped:
            break

    result_payload = {
        "rounds_run": len(summaries), "stopped": stopped,
        "wave_dir": str(wave), "rounds": summaries,
    }
    print(json.dumps(result_payload, ensure_ascii=False, indent=2))
    return 0


def cmd_ingest_strix(args) -> int:
    """Feed a strix session report back into the attack graph.

    The strix parser extracts URLs and CVEs from the report; URLs pass the
    engagement scope guard (out-of-scope/hallucinated hosts stay out), then
    land as frontier assets so the next run wave auto-pulls the full chain
    (bootstrap httpx → scan → crawl → param/injection).
    """
    from pathlib import Path

    from . import db as _db, util
    from .parsers import get_parser
    from .scope import ScopeGuard

    report = Path(args.report)
    if not report.exists():
        print(f"report not found: {report}", file=sys.stderr)
        return 1
    edir = _db.engagement_dir(_db.default_root(), args.engagement_id)
    g = edir / "graph.db"
    if not g.exists():
        print(f"engagement {args.engagement_id} not found", file=sys.stderr)
        return 1
    scope = _db.Database(g, read_only=True).get_scope(args.engagement_id)
    if scope is None:
        print("engagement has no scope row", file=sys.stderr)
        return 1
    guard = ScopeGuard(scope["in_scope"], scope["out_of_scope"])

    parser = get_parser("strix")
    if parser is None:
        print("strix parser not registered", file=sys.stderr)
        return 1
    parsed = parser.parse(report.read_text(), action={})
    if not parsed.assets and not parsed.findings:
        print("strix parser extracted nothing from the report")
        return 0

    w = _db.Database(g)
    kept_urls = []
    # P-030-R (grok H4): asset-side seen-set. The first pass left assets on
    # a bare upsert — 87 rows / 43 distinct values (one host x4)
    # in a production graph. A (type, value) already present is skipped
    # instead of re-inserted, so re-ingesting a strix report is idempotent.
    seen_assets: set[tuple[str, str]] = {
        (str(e.get("type", "")), str(e.get("value", "")))
        for e in w.query_entities(kind="asset", engagement_id=args.engagement_id)
    }
    for a in parsed.assets:
        url = str(a.get("value", ""))
        decision = guard.check_url(url)
        if not decision.allowed:
            print(f"scope-blocked: {url} ({decision.reason})")
            continue
        if (str(a.get("type", "")), url) in seen_assets:
            continue
        a.setdefault("id", util.new_id("asset"))
        a.setdefault("engagement_id", args.engagement_id)
        a.setdefault("kind", "asset")
        a.setdefault("state", "active")
        a.setdefault("frontier", True)
        w.upsert_entity(a)
        seen_assets.add((str(a.get("type", "")), url))
        kept_urls.append(url)
    kept, dups = ingest_strix_findings(w, parsed.findings, args.engagement_id)
    w.close()
    print(f"ingested {len(kept_urls)} urls, {kept} findings "
          f"({dups} duplicates merged) into {args.engagement_id}")
    return 0


def ingest_strix_findings(w, findings: list[dict],
                          engagement_id: str) -> tuple[int, int]:
    """Shared strix-findings ingest path (P-030-R grok H2/H5).

    Production and the tests call THIS function, so a test
    can no longer pass by re-implementing the gate (the first P-030
    tests duplicated the logic and stayed green against any production
    drift). Gate semantics mirror orchestrator._ingest_finding's F15
    shape: dedup_key lookup -> duplicate bumps the primary + duplicate_of
    edge; new row -> upsert + advance_and_persist("dedup_pass") so the
    finding enters the validator queue at 'triaged' instead of stalling
    at 'candidate' (one production graph: 25/25 candidate, entity.transition = 0).

    P-030-R2 (grok M1) deltas vs the orchestrator path, as of P1
    batch 1: (1) FIXED — M1-asset-link: the shared
    asset_link.asset_id_for_url (the orchestrator's _asset_id_for_url
    logic, lifted into one module) resolves the asset behind
    finding.url before the row lands, so the stored asset_id plus a
    discovered_on edge make strix class facts reach _fact_view;
    (2) the advance_and_persist return value is unchecked (single-writer
    CLI, defensive only — P2).
    """
    from .dedup import compute_dedup_key
    kept = 0
    dups = 0
    for f in findings:
        f.setdefault("engagement_id", engagement_id)
        f.setdefault("kind", "finding")
        f.setdefault("state", "candidate")
        f["dedup_key"] = compute_dedup_key(f)
        existing = [e for e in w.query_entities(
            kind="finding", engagement_id=engagement_id)
            if e.get("dedup_key") == f["dedup_key"]]
        if existing:
            # P-030-R2 (grok M1): duplicate_of is an EDGE (F15), not an
            # event — the duplicate entity is never upserted; the edge's
            # from_id is the dup's minted id, to_id the surviving primary.
            f.setdefault("id", util.new_id("finding"))
            w.add_edge(f["id"], existing[0]["id"], "duplicate_of",
                       engagement_id=engagement_id,
                       data={"dedup_key": f["dedup_key"]})
            w.bump_duplicate_count(existing[0]["id"])
            dups += 1
            continue
        f.setdefault("id", util.new_id("finding"))
        # M1-asset-link: resolve the asset this finding's URL belongs to
        # BEFORE the row lands, so the stored asset_id (and the
        # discovered_on edge) exist the moment _fact_view scans findings —
        # strix class facts become visible to the per-asset class rules.
        aid = asset_link.asset_id_for_url(w, str(f.get("url") or ""),
                                          engagement_id=engagement_id)
        if aid:
            f["asset_id"] = aid
        w.upsert_entity(f)
        if aid:
            w.add_edge(f["id"], aid, "discovered_on",
                       engagement_id=engagement_id,
                       data={"source": "strix_ingest"})
        # P-030-R (grok H5): the state machine gate the docstring always
        # promised — without this advance, strix findings never reach
        # 'triaged' and the validator queue never sees them.
        w.advance_and_persist(f["id"], "dedup_pass", actor="validator")
        kept += 1
    return kept, dups


def cmd_health(args) -> int:
    """Run the graph health sweep and print the report."""
    from .graph_health import check_health

    report = check_health(args.engagement_id)
    print(report.markdown())
    return 0


def cmd_seal(args) -> int:
    from .seal import cmd_seal as _cmd_seal

    return _cmd_seal(args)


def cmd_doctor(args) -> int:
    from .doctor import cmd_doctor as _cmd_doctor

    return _cmd_doctor(args)


def cmd_recover(args) -> int:
    """One-shot recovery sweep: stranded 'testing' hypotheses get their
    forward path back — recycled to 'proposed' (plannable again) or
    'rejected' (attempts exhausted). Never touches in-flight runs.

    Reopening a sealed engagement is expected here: the write drifts the
    artifact from its manifest, so the printed note says to re-seal.
    """
    import json as _json

    from . import failure

    edir = db.engagement_dir(db.default_root(), args.engagement_id)
    graph = edir / "graph.db"
    if not graph.exists():
        print(f"engagement {args.engagement_id!r} not found: no graph.db at "
              f"{edir}", file=sys.stderr)
        return 2
    sealed = (edir / "engagement.manifest.json").exists()
    w = db.Database(graph)
    try:
        recycled, abandoned = failure.recycle_stuck_hypotheses(
            w, args.engagement_id)
        stuck_after = sum(
            1 for h in w.query_entities(kind="hypothesis",
                                        state="testing",
                                        engagement_id=args.engagement_id))
    finally:
        w.close()
    print(_json.dumps({
        "engagement": args.engagement_id,
        "recycled": recycled,
        "abandoned": abandoned,
        "testing_remaining": stuck_after,
        "sealed_reopened": sealed,
        "re_seal": sealed,
    }, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="motoko", description="MOTOKO attack-graph orchestrator")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", help="initialize an engagement")
    pi.add_argument("engagement_id")
    pi.add_argument("--name")
    pi.add_argument("--scope", action="append", help="in-scope domain/CIDR (repeatable)")
    pi.add_argument("--out-of-scope", action="append", help="out-of-scope domain/CIDR")
    pi.add_argument("--seed", action="append", help="seed asset URL (repeatable)")
    pi.add_argument("--intensity", default="normal", choices=["normal", "aggressive", "stealth"])
    pi.add_argument("--max-depth", type=int, default=3)
    pi.add_argument("--concurrency", type=int, default=4)
    pi.add_argument("--oob-domain")
    pi.set_defaults(func=cmd_init)

    pd = sub.add_parser("digest", help="print the context digest")
    pd.add_argument("engagement_id")
    pd.set_defaults(func=cmd_digest)

    pr = sub.add_parser("run", help="run the six-beat main loop")
    pr.add_argument("engagement_id")
    pr.add_argument("--max-cycles", type=int, default=20,
                    help="hard cap on cycles (fuse, not a target)")
    pr.add_argument("--timeout", type=float, default=300,
                    help="per-tool timeout in seconds")
    pr.add_argument("--rules-dir", default=None,
                    help="override the rules directory")
    pr.add_argument("--reflector", action="store_true",
                    help="enable the LLM reflector (MOTOKO_REFLECTOR_* env)")
    pr.set_defaults(func=cmd_run)

    pq = sub.add_parser("query", help="list entities")
    pq.add_argument("engagement_id")
    pq.add_argument("--kind", choices=["asset", "finding", "hypothesis", "evidence", "access", "path"])
    pq.add_argument("--state")
    pq.set_defaults(func=cmd_query)

    pe = sub.add_parser("events", help="tail the event log")
    pe.add_argument("engagement_id")
    pe.add_argument("--limit", type=int, default=20)
    pe.set_defaults(func=cmd_events)

    pk = sub.add_parser("kali", help="manage the kali-recon tool container")
    pk.add_argument("action", choices=["status", "start", "stop"])
    pk.add_argument("--container", default="kali-recon")
    pk.add_argument("--image", default="localhost/kali-recon:20260908")
    pk.set_defaults(func=cmd_kali)

    ps = sub.add_parser("strix", help="launch a strix deep-dive on a target")
    ps.add_argument("engagement_id")
    ps.add_argument("--target", required=True,
                    help="target URL/host for the strix session")
    ps.add_argument("--output", default=None,
                    help="report path (default: engagement dir/strix-<ts>.md)")
    ps.set_defaults(func=cmd_strix)

    pl = sub.add_parser("loop", help="drive the wave-loop (audit -> adjudicate -> evaluate)")
    pl.add_argument("engagement_id")
    pl.add_argument("--config", default=None,
                    help="loop config path (default ~/.motoko/loop.yaml)")
    pl.add_argument("--rounds", type=int, default=1,
                    help="max rounds to drive (default 1, hard cap 5)")
    pl.add_argument("--out", default=None,
                    help="wave dir (default plans/waves/loop-<date>, "
                         "rounds land in round-N subdirs)")
    pl.add_argument("--extra", default=None,
                    help="extra material file to append to the bundle")
    pl.set_defaults(func=cmd_loop)

    pi = sub.add_parser("ingest-strix", help="feed a strix report into the graph")
    pi.add_argument("engagement_id")
    pi.add_argument("report", help="path to the strix session report (.md/.log)")
    pi.set_defaults(func=cmd_ingest_strix)

    ph = sub.add_parser("health", help="graph health sweep (broken links etc.)")
    ph.add_argument("engagement_id")
    ph.set_defaults(func=cmd_health)

    pseal = sub.add_parser(
        "seal", help="seal a finished engagement: WAL checkpoint, integrity "
                     "gates, census, engagement.manifest.json")
    pseal.add_argument("engagement_id")
    pseal.add_argument("--root", default=None,
                       help="engagements root override "
                            "(default MOTOKO_HOME or package-relative)")
    pseal.add_argument("--verify", action="store_true",
                       help="check graph.db against the existing manifest "
                            "instead of sealing")
    pseal.set_defaults(func=cmd_seal)

    pdoc = sub.add_parser(
        "doctor", help="read-only environment self-check "
                       "(python, root, tools, config, key envs)")
    pdoc.set_defaults(func=cmd_doctor)

    prev = sub.add_parser(
        "recover", help="one-shot sweep: give stranded 'testing' hypotheses "
                        "a forward path (recycle or reject; never touches "
                        "in-flight runs)")
    prev.add_argument("engagement_id")
    prev.set_defaults(func=cmd_recover)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
