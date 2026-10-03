"""MOTOKO CLI — single-writer process entry point.

Commands:
    interface open the terminal interface (also the default without a command)
    status    print a read-only interface snapshot
    watch     watch read-only interface snapshots; --once runs the findings
              watchdog sweep (new findings + strix completions since the
              cursor) and exits — the host-consumable delta mode
    init      create an engagement (dir + graph.db + scope row)
    run       run the six-beat main loop with the real tool executor
    adapter   dispatch one host-neutral, bounded JSON request
    digest    print the <=2KB context digest (read-only)
    query     list entities (read-only)
    events    tail the event log (read-only)
    seal      seal a finished engagement (checkpoint + integrity + manifest)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from . import db, digest, schema, util
from . import asset_link


def _open_ro(args):
    'Open the engagement graph read-only; None (stderr printed) if missing.'
    edir = db.engagement_dir(db.default_root(), args.engagement_id)
    if not (edir / "graph.db").exists():
        print(f"engagement {args.engagement_id!r} not found: no graph.db at "
              f"{edir} — run `motoko init {args.engagement_id}` first",
              file=sys.stderr)
        return None
    return db.Database(edir / "graph.db", read_only=True)


def cmd_init(args) -> int:
    from . import util
    from .scope import ScopeGuard

    guard = ScopeGuard(args.scope or [], args.out_of_scope or [])
    # A scope entry the guard cannot honor (URL scheme, bad port, empty
    # host) would sit in the list matching nothing — the operator's scoping
    # silently doing nothing. Same posture as a bad seed: an error, not a
    # warning.
    if guard.unhonored:
        print(f"scope entries the guard cannot honor: "
              f"{', '.join(guard.unhonored)}", file=sys.stderr)
        return 2
    for s in args.seed or []:
        decision = guard.check_url(s)
        if not decision.allowed:
            print(f"seed rejected by scope guard: {s!r}: {decision.reason}",
                  file=sys.stderr)
            return 2

    # A pip-installed engine with MOTOKO_HOME unset derives its tasks root
    # from the package location: <prefix>/lib/pythonX.Y/tasks (ABOVE
    # site-packages), inside the interpreter's install tree — the next
    # `pip install --upgrade` or uninstall wipes every engagement created
    # there. Refused here, at the only command that creates the tree;
    # util.under_interpreter_prefix documents why the site-packages
    # membership test would miss it.
    root = db.default_root()
    if root == util.motoko_root() / "tasks" and \
            util.under_interpreter_prefix(root):
        print(f"refusing to initialize: the default tasks root {root} "
              "sits inside the Python installation tree "
              f"(sys.prefix={sys.prefix}) — an upgrade or uninstall of "
              "the package wipes it. Set MOTOKO_HOME (or pass the global "
              "--root) to a writable location outside the interpreter "
              "tree", file=sys.stderr)
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
    if ro is None:
        return 2
    try:
        print(digest.build_digest(ro, args.engagement_id))
    finally:
        ro.close()
    return 0


def cmd_run(args) -> int:
    """Run the six-beat main loop with the real subprocess executor."""
    import sys as _sys

    from . import orchestrator, reflector as reflector_mod

    edir = db.engagement_dir(db.default_root(), args.engagement_id)
    if not (edir / "graph.db").exists():
        print(f"engagement {args.engagement_id!r} not found: no graph.db at "
              f"{edir} — run `motoko init {args.engagement_id}` first",
              file=_sys.stderr)
        return 2

    reflector = None
    if args.reflector:
        try:
            reflector = reflector_mod.reflector_from_env()
        except ValueError as exc:
            print(f"--reflector configuration error: {exc}",
                  file=_sys.stderr)
            return 2
        if reflector is None:
            print("--reflector requested but MOTOKO_REFLECTOR_MODEL, "
                  "MOTOKO_REFLECTOR_BASE_URL or the key env is unset; "
                  "continuing without a reflector",
                  file=_sys.stderr)
    canary = orchestrator.default_canary(args.engagement_id)
    try:
        summary = orchestrator.run_engagement(
            args.engagement_id, rules_dir=args.rules_dir or None,
            reflector=reflector, timeout=args.timeout,
            max_cycles=args.max_cycles,
            wave_cycles=getattr(args, "wave_cycles", 5),
            max_waves=getattr(args, "max_waves", None),
            canary=canary)
    except RuntimeError as exc:
        print(exc, file=_sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_query(args) -> int:
    ro = _open_ro(args)
    if ro is None:
        return 2
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
    """Tail the event log, or gate it.

    Three modes over the same read-only connection:
      * default — the tail, parsed strictly: a payload that does not decode is
        printed with its raw text and a marker rather than killing the listing.
      * ``--verify`` — the event-sourcing gate (``core.events.verify``): the
        log is the source of truth, so this proves it still is. Exit 1 on any
        violation.
      * ``--rebuild DIR`` — materialize a NEW graph.db from the log alone and
        verify the result: crash recovery as an executable claim rather than a
        docstring. Exit 1 unless the rebuilt database verifies clean.
    """
    from . import events as events_mod

    ro = _open_ro(args)
    if ro is None:
        return 2
    try:
        if args.verify:
            rep = events_mod.verify(
                ro.conn, graph=str(ro.path), engagement_id=args.engagement_id)
            if args.json:
                print(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2))
            else:
                _print_verification(rep)
            return 0 if rep.ok else 1

        if args.rebuild:
            dest = Path(args.rebuild)
            try:
                result = events_mod.rebuild(
                    dest, ro.conn, engagement_id=args.engagement_id)
            except events_mod.RebuildRefused as exc:
                print(f"rebuild refused: {exc}", file=sys.stderr)
                return 2
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"rebuilt {result['path']} from {result['events']} events")
                for table, count in sorted(result["written"].items()):
                    print(f"  {table}: {count} rows")
                if result["unsourced_tables"]:
                    print("  not rebuilt (not event-sourced, by design): "
                          + ", ".join(result["unsourced_tables"]))
                for violation in result["violations"]:
                    print(f"  VIOLATION [{violation['check']}] "
                          f"seq={violation['seq']} {violation['detail']}")
                print(f"  warnings: {result['warnings']}")
                print("verify: " + ("clean" if result["ok"] else "FAILED"))
            return 0 if result["ok"] else 1

        kinds = set(args.kind or [])
        unknown = sorted(kinds - schema.EVENT_KINDS)
        if unknown:
            print(f"unknown event kind(s): {', '.join(unknown)} — the declared "
                  f"vocabulary is schema.EVENT_ENTITY_DOMAINS", file=sys.stderr)
            return 2
        rows = events_mod.read_events(
            ro.conn, since_seq=args.since_seq, kinds=kinds or None,
            entity_id=args.entity, limit=args.limit, descending=True)
        if args.json:
            print(json.dumps([
                {"seq": e.seq, "at": e.at, "kind": e.kind,
                 "entity_id": e.entity_id, "payload": e.payload,
                 **({"corrupt": e.corrupt, "raw": e.raw} if e.corrupt else {})}
                for e in reversed(rows)], ensure_ascii=False, indent=2))
            return 0
        for e in reversed(rows):
            if e.corrupt is not None:
                print(f"{e.seq}\t{e.kind}\t{e.entity_id or '-'}\t"
                      f"<undecodable: {e.corrupt}> {e.raw}")
            else:
                print(f"{e.seq}\t{e.kind}\t{e.entity_id or '-'}\t{e.raw or ''}")
    finally:
        ro.close()
    return 0


def _print_verification(rep) -> None:
    """Human form of a verification report: the counts, then every issue."""
    print(f"graph: {rep.graph}")
    if rep.engagement_id:
        print(f"engagement: {rep.engagement_id}")
    print(f"events: {rep.events}"
          + (f" (seq {rep.first_seq}..{rep.last_seq})" if rep.events else ""))
    for table in sorted(rep.materialized):
        print(f"  {table}: log={rep.folded.get(table, 0)} "
              f"table={rep.materialized[table]}")
    for kind, count in sorted(rep.kinds.items()):
        print(f"  kind {kind}: {count}")
    for issue in rep.violations:
        print(f"VIOLATION [{issue.check}] seq={issue.seq} {issue.detail}")
    for issue in rep.warnings:
        print(f"warning [{issue.check}] seq={issue.seq} {issue.detail}")
    print("verify: " + ("clean" if rep.ok else
                        f"FAILED ({len(rep.violations)} violations, "
                        f"{len(rep.warnings)} warnings)"))


def cmd_kali(args) -> int:
    """Manage the kali-recon tool container (podman), CLI-only."""
    import shutil
    import subprocess

    name = args.container
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        print("invalid container name", file=sys.stderr)
        return 2
    if not isinstance(args.image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*", args.image):
        print("invalid container image reference", file=sys.stderr)
        return 2
    podman = shutil.which("podman")
    if podman is None:
        print("podman not found", file=sys.stderr)
        return 1

    if args.action == "status":
        r = subprocess.run(
            [podman, "ps", "-a", "--filter", f"name={name}",
             "--format", "{{.Names}} {{.Status}}"],
            capture_output=True, text=True, timeout=30)
        print(r.stdout.strip() or f"container {name!r} does not exist")
        return 0

    if args.action == "start":
        listed = subprocess.run(
            [podman, "ps", "-a", "--filter", f"name={name}",
             "--format", "{{.Names}}"], capture_output=True, text=True,
            timeout=30)
        exists = name in {line.strip() for line in listed.stdout.splitlines()}
        current = ""
        if exists:
            insp = subprocess.run(
                [podman, "inspect", "--format", "{{.Config.Image}}", name],
                capture_output=True, text=True, timeout=30)
            if insp.returncode == 0:
                current = insp.stdout.strip()

        if exists and current and current != args.image and not args.recreate:
            # The defect this branch exists for: rebuilding the image and
            # re-running `kali start` used to print "started" while the
            # container kept running the OLD toolset, because the existence
            # check matched on the name and `--image` was never consulted.
            # Rules with `runtime: container` exec INTO this container, so the
            # mismatch surfaces later as a rule failure charged to the
            # (rule, asset) pair — a host defect billed as a corpus defect.
            print(f"{name}: image mismatch — the existing container runs "
                  f"{current}, you asked for {args.image}. Rules declaring "
                  f"runtime: container exec INTO this container, so starting "
                  f"it keeps the old toolset and those rules run against tools "
                  f"that may not exist there. Refusing to report that as "
                  f"'started'.\n"
                  f"  remedy: motoko kali start --recreate   "
                  f"(stop + rm + recreate from {args.image})\n"
                  f"  or keep the running one: motoko kali start "
                  f"--image {current}", file=sys.stderr)
            return 1

        if exists and args.recreate:
            subprocess.run([podman, "stop", name], capture_output=True,
                           text=True, timeout=120)
            rm = subprocess.run([podman, "rm", name], capture_output=True,
                                text=True, timeout=120)
            if rm.returncode != 0:
                print(f"{name}: could not remove the old container "
                      f"(exit {rm.returncode}) {rm.stderr.strip()[:200]}",
                      file=sys.stderr)
                return 1
            exists = False

        if exists:
            r = subprocess.run([podman, "start", name],
                               capture_output=True, text=True, timeout=120)
        else:
            # long-lived toolbox container; tools reach it via `podman exec`
            r = subprocess.run(
                [podman, "run", "-d", "--name", name, "--network", "host",
                 args.image, "sleep", "infinity"],
                capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            print(f"{name}: started ({args.image})")
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


_WAVE_ROOT = "wave-runs"

_STRIX_LAUNCHER_REL = "engine/launch-strix.sh"

_STRIX_INSTRUCTION = (
    "Deep-dive authorized penetration test on {target}: enumerate the hidden "
    "API surface, auth flows, and client-side secrets. Report every URL, "
    "parameter and CVE found. Single-host discipline: {target} only — do not "
    "follow siblings, parent domains or third-party hosts out of scope."
)


def _strix_wrapper_path() -> Path:
    'The six-gate strix launch wrapper (deploy-site tree only).'
    return util.motoko_root() / _STRIX_LAUNCHER_REL


def _strix_records(edir: Path) -> list[Path]:
    """Launch records the wrapper has written under this engagement."""
    runs = edir / "strix_runs"
    return sorted(runs.glob("launch-*.record")) if runs.is_dir() else []


#: Every flag the wrapper's launch CMD uses (launch-strix.sh:
#: ``strix -n -t <target> --instruction-file <file> -m <mode>``). Keep in
#: sync with the wrapper-side preflight probe (its gate 5.9).
_STRIX_REQUIRED_FLAGS = ("-n", "-t", "--instruction-file", "-m")

_STRIX_MODES = ("deep", "standard", "quick")


def _strix_help_flags_ok() -> tuple[bool, str]:
    """Probe ``strix --help`` for the launch flags the wrapper needs.

    Fail closed if the installed strix does not advertise them —
    a strix that prints usage and exits 0 is NOT a launch, and without this
    probe the discovery costs the full gate-6 readiness window (60 s of a
    session that never existed) or, on the old bare path, a green exit code.
    Offline and local: --help spawns no agent and touches no network.
    """
    import subprocess

    try:
        r = subprocess.run(["strix", "--help"], capture_output=True,
                           text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"strix --help probe failed: {exc}"
    if r.returncode != 0:
        return False, f"strix --help exited {r.returncode}"
    help_text = f"{r.stdout or ''}\n{r.stderr or ''}"
    # Token-boundary match: argparse help shows flags as "[-t TARGET]",
    # "-t, --target" or "[-n]" — the flag must stand alone against
    # non-word/non-hyphen edges, so "-t" never matches inside "--target"
    # and "-m" never inside "--max-budget".
    missing = [flag for flag in _STRIX_REQUIRED_FLAGS
               if not re.search(rf"(?<![\w-]){re.escape(flag)}(?![\w-])",
                                help_text)]
    if missing:
        return False, ("installed strix --help lacks required launch flags: "
                       + ", ".join(missing))
    return True, ""


def cmd_strix(args) -> int:
    'Launch a strix deep-dive through the six-gate wrapper (operator-driven).'
    import subprocess

    wrapper = _strix_wrapper_path()
    if not wrapper.is_file():
        print(f"launch wrapper not found: {wrapper}\n"
              "refusing to start strix without the six anonymity gates (the internal doctrine). "
              "launch-strix.sh ships in the deploy-site tree only, not in the "
              "exported wheel — run this from the engine checkout.",
              file=sys.stderr)
        return 2

    ok, why = _strix_help_flags_ok()
    if not ok:
        print(f"strix preflight failed: {why}\n"
              "refusing to launch: a strix that prints usage and exits 0 is "
              "NOT a launch. Repair the install "
              "(tools_anchor/provision.sh strix-upgrade) and retry.",
              file=sys.stderr)
        return 2

    mode = getattr(args, "mode", None)
    if mode is not None and mode not in _STRIX_MODES:
        print(f"invalid --mode {mode!r} — expected one of "
              f"{'/'.join(_STRIX_MODES)}", file=sys.stderr)
        return 2
    timeout = getattr(args, "timeout", None)
    if timeout is not None and (isinstance(timeout, bool)
                                or not isinstance(timeout, int)
                                or timeout <= 0):
        print(f"invalid --timeout {timeout!r} — expected a positive integer "
              "(seconds)", file=sys.stderr)
        return 2
    egress_class = getattr(args, "egress_class", None)
    if egress_class is not None and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9-]*", egress_class):
        print(f"invalid --egress-class {egress_class!r} — expected a name "
              "like 'browser' or 'campaign-<x>' (the deploy substrate "
              "file's egress.classes is the source of truth)",
              file=sys.stderr)
        return 2
    target_local = args.target.startswith(("/", "file://"))
    no_rotate = bool(getattr(args, "no_rotate", False))
    if no_rotate and not target_local:
        print("--no-rotate is limited to local self-test targets (a path or "
              "file:// URL) — remote hosts must pass gate 5 rotation + "
              "IP-echo (the internal doctrine standing egress rule)", file=sys.stderr)
        return 2

    edir = db.engagement_dir(db.default_root(), args.engagement_id)
    edir.mkdir(parents=True, exist_ok=True)
    stamp = re.sub(r"[^0-9A-Za-z]", "", util.now_iso()[:19])
    op_ifile = getattr(args, "instruction_file", None)
    if op_ifile:
        ifile = Path(op_ifile)
        if not ifile.is_file() or ifile.stat().st_size == 0:
            print(f"--instruction-file not found or empty: {ifile}",
                  file=sys.stderr)
            return 2
    else:
        ifile = edir / f"strix-instruction-{stamp}.md"
        ifile.write_text(_STRIX_INSTRUCTION.format(target=args.target))
    out = Path(args.output) if args.output \
        else edir / f"strix-launch-{stamp}.md"

    argv = [str(wrapper), "--target", args.target,
            "--instruction-file", str(ifile), "--workdir", str(edir)]
    if mode is not None:
        argv += ["--mode", mode]
    if timeout is not None:
        argv += ["--timeout", str(timeout)]
    if egress_class is not None:
        argv += ["--egress-class", egress_class]
    if no_rotate:
        argv.append("--no-rotate")
    if getattr(args, "dry_run", False):
        argv.append("--dry-run")
    print(f"launching strix through the six-gate wrapper: {args.target}",
          file=sys.stderr)
    # stdout and stderr stay attached: an operator-driven launch must be
    # visible, and a fail-closed gate death has to surface the moment it
    # happens rather than after a captured buffer is flushed.
    before = set(_strix_records(edir))
    wenv = os.environ.copy()
    wenv.setdefault("MOTOKO_HOME", str(db.default_root()))
    r = subprocess.run(argv, env=wenv)
    fresh = [p for p in _strix_records(edir) if p not in before]
    record = max(fresh, key=lambda p: p.stat().st_mtime) if fresh else None

    lines = [f"# strix launch — {args.target}", "",
             f"- launched_at: {util.now_iso()}",
             f"- engagement: {args.engagement_id}",
             f"- wrapper: {wrapper}",
             f"- instruction_file: {ifile}",
             f"- exit: {r.returncode}",
             f"- launch_record: {record if record else 'NONE'}", ""]
    if record is not None:
        lines += ["```", record.read_text(errors="replace").strip(), "```", "",
                  "The session runs in the background under the wrapper's own "
                  "pid/pgid; the record above carries the pid, the launch log "
                  "and the egress exit that was actually used. Point mission "
                  "evidence at it (the internal doctrine), and stop it with `kill -- -<pgid>`."]
    else:
        lines += ["No launch record was produced by this run: the wrapper died "
                  "inside its gates (or this was --dry-run). Treat the launch "
                  "as NOT proven anonymized — no session may be assumed to "
                  "exist, and none may be pointed at as evidence."]
    out.write_text("\n".join(lines) + "\n")
    print(f"report: {out} (exit {r.returncode})")
    return r.returncode


# -- deploy substrate reader (cli) --------------------------------------

def cmd_deploy(args) -> int:
    'FIX-7: offline reader for the deploy substrate file.'
    from . import deploy_config

    argv = [args.action]
    if args.action == "gateway":
        if not args.egress_class:
            print("deploy gateway requires a class name "
                  "(motoko deploy gateway <class>)", file=sys.stderr)
            return 2
        argv.append(args.egress_class)
    return deploy_config.main(argv)


# -- loop driver (cli) --------------------------------------------------

REQUIRED_LOOP_KEYS = {
    "auditors": ("name", "protocol"),
    "adjudicator": ("name", "protocol"),
}


def _base_url_dialect_problem(label: str, ep: dict) -> str | None:
    ''
    protocol = ep.get("protocol")
    if protocol not in ("anthropic", "openai"):
        return None
    base = str(ep.get("base_url") or "").rstrip("/")
    if protocol == "anthropic":
        if base.endswith("/v1"):
            return (f"{label}: anthropic base_url must not end in /v1 — every "
                    f"adapter appends /v1/messages (drop the suffix)")
        if base.endswith("/v1/messages"):
            return (f"{label}: anthropic base_url must not carry the full "
                    f"endpoint path — every adapter appends /v1/messages, so "
                    f"the paste would double the segment and 404 at launch "
                    f"(drop the path)")
    if protocol == "openai" and base.endswith("/chat/completions"):
        return (f"{label}: openai base_url must not carry the full endpoint "
                f"path — every adapter appends /chat/completions, so the "
                f"paste would double the segment and 404 at launch (drop "
                f"the path)")
    return None


def validate_loop_config(cfg: dict) -> list[str]:
    """Return a list of human-readable config problems (empty = valid)."""
    from .loop import LENS_NAMES, validate_endpoint_shape  # lazy: same import shape as doctor's

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
            lens = str(a.get("lens") or "")
            if lens and lens not in LENS_NAMES:
                problems.append(f"auditors[{i}]: unknown lens '{lens}' "
                                f"(known: {', '.join(LENS_NAMES)})")
            if a.get("protocol") in {"anthropic", "openai"} and not str(a.get("base_url") or "").strip():
                problems.append(f"auditors[{i}]: {a['protocol']} protocol needs "
                                f"'base_url'")
            dialect = _base_url_dialect_problem(f"auditors[{i}]", a)
            if dialect:
                problems.append(dialect)
            try:
                validate_endpoint_shape(a, f"auditors[{i}]")
            except ValueError as e:
                problems.append(str(e))
            if a.get("protocol") == "cli" and not a.get("command"):
                problems.append(f"auditors[{i}]: cli protocol needs "
                                f"'command'")
        if len(auditors) > 1:
            lenses = [str(x.get("lens") or "") for x in auditors
                      if isinstance(x, dict)]
            if len(set(lenses)) != len(lenses):
                problems.append(
                    f"auditor lenses collide ({', '.join(lenses)}) — under "
                    "one substrate the legs differentiate BY lens; two legs "
                    "on the same lens are the same prompt twice")
    adj = cfg.get("adjudicator")
    if not adj:
        problems.append("missing 'adjudicator' (the converge beat needs one)")
    elif isinstance(adj, dict):
        for key in REQUIRED_LOOP_KEYS["adjudicator"]:
            if not adj.get(key):
                problems.append(f"adjudicator: missing '{key}'")
        if adj.get("protocol") in {"anthropic", "openai"} and not str(adj.get("base_url") or "").strip():
            problems.append(f"adjudicator: {adj['protocol']} protocol needs "
                            "'base_url'")
        dialect = _base_url_dialect_problem("adjudicator", adj)
        if dialect:
            problems.append(dialect)
        try:
            validate_endpoint_shape(adj, "adjudicator")
        except ValueError as e:
            problems.append(str(e))
        if adj.get("protocol") == "cli" and not adj.get("command"):
            problems.append("adjudicator: cli protocol needs 'command'")
    else:
        problems.append("'adjudicator' must be an endpoint map")
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
    ''
    log = repo_root / _WAVE_ROOT / "pitfall-log.md"
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
              f"engine/loop/loop.yaml)", file=sys.stderr)
        return 2
    try:
        cfg = loop.load_loop_config(cfg_path)
    except (OSError, ValueError) as exc:
        print(f"loop config unreadable: {exc}", file=sys.stderr)
        return 2
    problems = validate_loop_config(cfg)
    if problems:
        print("loop config invalid:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2

    runner = loop.LoopRunner(args.engagement_id, config=cfg)
    rounds = min(args.rounds, 5)          # HARD_MAX_ROUNDS fuse

    if args.out:
        wave = Path(args.out)
    else:
        engagement_dir = db.engagement_dir(runner.root, args.engagement_id)
        wave = engagement_dir / _WAVE_ROOT / f"loop-{util.now_iso()[:10]}"
    wave.mkdir(parents=True, exist_ok=True)

    extra = Path(args.extra).read_text() if args.extra else ""
    summaries = []
    stopped = False
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
    kept, dups = ingest_strix_findings(w, parsed.findings,
                                       args.engagement_id, guard=guard)
    w.close()
    print(f"ingested {len(kept_urls)} urls, {kept} findings "
          f"({dups} duplicates merged) into {args.engagement_id}")
    return 0


def ingest_strix_findings(w, findings: list[dict],
                          engagement_id: str,
                          guard=None) -> tuple[int, int]:
    ''
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
            f.setdefault("id", util.new_id("finding"))
            w.add_edge(f["id"], existing[0]["id"], "duplicate_of",
                       engagement_id=engagement_id,
                       data={"dedup_key": f["dedup_key"]})
            w.bump_duplicate_count(existing[0]["id"])
            dups += 1
            continue
        f.setdefault("id", util.new_id("finding"))
        if not f.get("url"):
            from .verification import NO_TARGET
            f["dedup_key"] = f.get("dedup_key") or compute_dedup_key(f)
            # Same doctrine as `Orchestrator._ingest_finding`: terminal because
            # a missing url is not a condition that can appear, recorded with
            # its reason and its real actor. Two doors, one record — otherwise
            # the same finding is reported differently depending on which one
            # it came through.
            f["verification_blocked"] = {
                "reason": NO_TARGET, "validator": "ingest",
                "detail": "finding carries no url, so no validator can target "
                          "it and nothing ever attaches one later",
                "at": util.now_iso(),
            }
            w.upsert_entity(f)
            w.advance_and_persist(f["id"], "wont_test", actor="ingest",
                                  payload={"reason": NO_TARGET})
            w.append_event("verification_blocked", f["id"], {
                "reason": NO_TARGET, "validator": "ingest",
                "detail": f["verification_blocked"]["detail"],
                "state": "wont_test", "class": f.get("class"),
                "severity": f.get("severity"),
            })
            kept += 1
            continue
        aid = asset_link.asset_id_for_url(w, str(f.get("url") or ""),
                                          engagement_id=engagement_id)
        if not aid:
            if guard is None:
                decision = None
            else:
                decision = guard.check_url(str(f["url"]))
            if decision is None or decision.allowed:
                aid = w.upsert_entity({
                    "id": util.new_id("asset"), "kind": "asset",
                    "engagement_id": engagement_id, "state": "active",
                    "type": "url", "value": str(f["url"]),
                    "frontier": True,
                    "source": f.get("detector") or "strix_ingest",
                })
        if aid:
            f["asset_id"] = aid
        w.upsert_entity(f)
        if aid:
            w.add_edge(f["id"], aid, "discovered_on",
                       engagement_id=engagement_id,
                       data={"source": "strix_ingest"})
        w.advance_and_persist(f["id"], "dedup_pass", actor="validator")
        kept += 1
    return kept, dups


def cmd_health(args) -> int:
    """Run the graph health sweep and print the report.

    The report is the output; the exit code is the verdict: any [HIGH]
    finding returns 1, so a script gating on `motoko health` cannot read
    a broken graph as healthy. MEDIUM/LOW stay informational (exit 0).
    """
    from .graph_health import check_health

    report = check_health(args.engagement_id)
    print(report.markdown())
    return 1 if report.high_count else 0


def cmd_seal(args) -> int:
    from .seal import cmd_seal as _cmd_seal

    return _cmd_seal(args)


def cmd_doctor(args) -> int:
    from .doctor import cmd_doctor as _cmd_doctor

    return _cmd_doctor(args)


def cmd_rules(args) -> int:
    """Static rule-corpus check: which rules can never fire, and why."""
    from .rulecheck import cmd_rules as _cmd_rules

    return _cmd_rules(args)


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


def cmd_adapter(args) -> int:
    """Serve the local host protocol, or one legacy request envelope."""
    from .adapter import handle_frame, serve_lines

    if getattr(args, "stdio", False):
        return serve_lines(disconnect_cancels=args.disconnect_cancels)

    if args.disconnect_cancels:
        raise ValueError("--disconnect-cancels requires --stdio")

    result = handle_frame(args.request)
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return int(result.get("exit_code") or 0)


def cmd_interface(args) -> int:
    """Launch the optional UI against the same runtime as the engine."""
    from interface.cli import run

    args.root = (args.root or db.default_root()).expanduser().resolve()
    return run(args)


def cmd_watch(args) -> int:
    """Watch dispatch: interface snapshot watcher, or the watchdog sweep.

    Bare ``watch`` stays the interface's live snapshot mode. ``--once`` is
    the engine primitive (core/watch.py, successor of the retired shell
    watchdog looper): print the deltas since the cursor and advance it,
    with the host owning scheduling. The interface is never imported on
    the ``--once`` path, so the sweep works without the display
    dependencies.
    """
    if getattr(args, "once", False):
        from . import watch as watch_mod

        return watch_mod.cmd_watch(args)
    if getattr(args, "json", False) or getattr(args, "strix_root", None):
        print("--json/--strix-root apply only to `watch --once` (the findings "
              "watchdog sweep); bare `watch` is the interface snapshot mode",
              file=sys.stderr)
        return 2
    return cmd_interface(args)


def _interface_options(parser: argparse.ArgumentParser) -> None:
    # Suppressed defaults preserve top-level options before a subcommand.
    parser.add_argument("--demo", action="store_true", default=argparse.SUPPRESS,
                        help="show synthetic MOTOKO data")
    parser.add_argument("--root", type=Path, default=argparse.SUPPRESS, metavar="PATH",
                        help="engagement runtime directory (default: MOTOKO_HOME "
                             "or the engine tasks/ directory)")
    parser.add_argument("--theme", default=argparse.SUPPRESS, metavar="NAME",
                        help="MOTOKO theme name or theme file")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="motoko", description="MOTOKO attack-graph orchestrator",
        epilog="Without a command, open MOTOKO (print status when output is redirected).")
    p.set_defaults(func=cmd_interface, mode="tui", root=None, demo=False,
                   theme="motoko-dark")
    _interface_options(p)
    sub = p.add_subparsers(dest="command")

    interface = sub.add_parser("interface", help="open MOTOKO in the terminal")
    _interface_options(interface)
    interface.set_defaults(func=cmd_interface, mode="tui")
    interface_modes = interface.add_subparsers(dest="interface_mode")
    for name, description in (("status", "print a read-only snapshot"),
                              ("watch", "watch read-only snapshots")):
        view = interface_modes.add_parser(name, help=description)
        _interface_options(view)
        view.set_defaults(func=cmd_interface, mode=name)
    status = sub.add_parser("status", help="print a read-only snapshot")
    _interface_options(status)
    status.set_defaults(func=cmd_interface, mode="status")

    watch = sub.add_parser(
        "watch", help="watch read-only snapshots; --once prints the findings "
                      "watchdog deltas since the cursor and exits")
    _interface_options(watch)
    watch.add_argument("--once", action="store_true",
                       help="single findings-watchdog sweep (engine primitive, "
                            "no display dependencies): new findings and strix "
                            "completions since the cursor, then advance it. "
                            "Hosts own scheduling — run this from cron, a "
                            "timer, or the seat loop")
    watch.add_argument("--json", action="store_true",
                       help="machine-readable deltas (with --once)")
    watch.add_argument("--strix-root", action="append", default=None,
                       metavar="DIR",
                       help="extra strix run root outside the tasks tree "
                            "(repeatable; engagement strix_runs/ dirs are "
                            "always scanned)")
    watch.set_defaults(func=cmd_watch, mode="watch")

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
    pr.add_argument("--wave-cycles", type=int, default=5,
                    help="cycles per scan wave; outcomes adjust the next wave's priorities")
    pr.add_argument("--max-waves", type=int, default=None,
                    help="additional hard cap on scan waves in this invocation")
    pr.add_argument("--rules-dir", default=None,
                    help="override the rules directory (default: the bundled "
                         "engine/rules checkout, else the installed core/rules "
                         "package data — see util.default_rules_dir)")
    pr.add_argument("--reflector", action="store_true",
                    help="enable the LLM reflector (MOTOKO_REFLECTOR_* env)")
    pr.set_defaults(func=cmd_run)

    pq = sub.add_parser("query", help="list entities")
    pq.add_argument("engagement_id")
    pq.add_argument("--kind", choices=["asset", "finding", "hypothesis", "evidence", "access", "path"])
    pq.add_argument("--state")
    pq.set_defaults(func=cmd_query)

    pe = sub.add_parser("events", help="tail, verify or rebuild from the event log")
    pe.add_argument("engagement_id")
    pe.add_argument("--limit", type=int, default=20)
    pe.add_argument("--since-seq", type=int, default=0,
                    help="only rows after this seq (0 = from the beginning)")
    pe.add_argument("--kind", action="append",
                    help="restrict to a declared kind; repeatable")
    pe.add_argument("--entity", help="restrict to one subject id")
    pe.add_argument("--json", action="store_true", help="machine-readable output")
    pe.add_argument("--verify", action="store_true",
                    help="gate the log: sequence, vocabulary, references, "
                         "payloads, state machine, fold == materialized "
                         "(exit 1 on any violation)")
    pe.add_argument("--rebuild", metavar="DIR",
                    help="materialize a NEW graph.db in DIR from the log "
                         "alone, then verify it; refuses a non-empty DIR")
    pe.set_defaults(func=cmd_events)

    pk = sub.add_parser("kali", help="manage the kali-recon tool container")
    pk.add_argument("action", choices=["status", "start", "stop"])
    pk.add_argument("--container", default=util.KALI_CONTAINER)
    pk.add_argument("--image", default=util.KALI_IMAGE)
    pk.add_argument("--recreate", action="store_true",
                    help="stop + rm + recreate the container from --image "
                         "(required when the existing one was built from a "
                         "different image; `start` refuses to swap silently)")
    pk.set_defaults(func=cmd_kali)

    ps = sub.add_parser("strix", help="launch a strix deep-dive through the "
                                      "six-gate wrapper (launch-strix.sh)")
    ps.add_argument("engagement_id")
    ps.add_argument("--target", required=True,
                    help="target URL/host for the strix session")
    ps.add_argument("--output", default=None,
                    help="launch report path (default: engagement "
                         "dir/strix-launch-<ts>.md) — it points at the "
                         "wrapper's strix_runs/launch-*.record")
    ps.add_argument("--dry-run", action="store_true",
                    help="passed through to the wrapper: run every gate, "
                         "launch nothing (no egress, no tokens)")
    ps.add_argument("--mode", default=None, choices=_STRIX_MODES,
                    help="strix scan mode (wrapper default: deep)")
    ps.add_argument("--timeout", type=int, default=None,
                    help="session timeout in seconds (wrapper default: 7200)")
    ps.add_argument("--egress-class", default=None,
                    help="gate-5 egress class (wrapper default: "
                         "$MOTOKO_EGRESS_CLASS or 'browser'); classes and "
                         "gateways resolve from egress.classes in "
                         "$MOTOKO_HOME/deploy.json — an unknown class "
                         "dies in the wrapper naming that key")
    ps.add_argument("--no-rotate", action="store_true",
                    help="local self-test targets only (path or file://): "
                         "skip gate-5 rotation; refused for remote hosts")
    ps.add_argument("--instruction-file", default=None,
                    help="operator instruction file (replaces the generated "
                         "one; wrapper gate 3 still requires the target host "
                         "inside)")
    ps.set_defaults(func=cmd_strix)

    pdep = sub.add_parser(
        "deploy", help="read the deploy substrate config "
                       "($MOTOKO_HOME/deploy.json)")
    pdep.add_argument("action", choices=["gateway", "env", "validate"],
                      help="gateway <class>: resolve an egress class to "
                           "its gateway; env: print EnvironmentFile lines "
                           "(KEY=value, applied only where unset); "
                           "validate: print defect lines")
    pdep.add_argument("egress_class", nargs="?", default=None,
                      help="egress class name (the gateway action)")
    pdep.set_defaults(func=cmd_deploy)

    pl = sub.add_parser("loop", help="drive the wave-loop (audit -> adjudicate -> evaluate)")
    pl.add_argument("engagement_id")
    pl.add_argument("--config", default=None,
                    help="loop config path (default ~/.motoko/loop.yaml)")
    pl.add_argument("--rounds", type=int, default=1,
                    help="max rounds to drive (default 1, hard cap 5)")
    pl.add_argument("--out", default=None,
                    help="wave dir (default the private wave archive, "
                         "under the selected engagement; rounds land in round-N subdirs)")
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
    pseal.add_argument("--root", default=argparse.SUPPRESS,
                       help="engagements root override "
                            "(default MOTOKO_HOME or package-relative)")
    pseal.add_argument("--verify", action="store_true",
                       help="check graph.db against the existing manifest "
                            "instead of sealing")
    pseal.set_defaults(func=cmd_seal)

    pdoc = sub.add_parser(
        "doctor", help="read-only environment self-check "
                       "(python, root, tools, config, key envs)")
    pdoc.add_argument("--scope", choices=["full", "scan"], default="full",
                      help="full includes audit-loop dependencies; scan checks scan-wave dependencies")
    pdoc.add_argument("--require-ready", action="store_true",
                      help="exit non-zero unless the engine is ready to run: "
                           "no FAIL findings, a writable tasks root outside "
                           "the interpreter's install tree, and a rule "
                           "corpus that loads with at least one rule. "
                           "Operator-only substrate (credentials, echo URL, "
                           "toolbox, container) stays WARN and never gates "
                           "readiness — a fresh install in a scrubbed "
                           "environment can still be ready")
    pdoc.set_defaults(func=cmd_doctor)

    prules = sub.add_parser(
        "rules", help="static rule-corpus check: never-firing rules, "
                      "unresolvable tools, unrenderable placeholders, "
                      "unconsumed chain fields (no traffic, no LLM)")
    prules.add_argument("--report", action="store_true",
                        help="full markdown report instead of the summary")
    prules.add_argument("--json", action="store_true",
                        help="machine-readable output")
    prules.add_argument("--strict", action="store_true",
                        help="exit 1 when any HIGH issue is present (CI gate)")
    prules.add_argument("--docs", action="store_true",
                        help="also check that rule ids referenced by the docs "
                             "exist in the corpus")
    prules.add_argument("--no-resolve", action="store_true",
                        help="skip binary resolution (toolbox not mounted)")
    prules.add_argument("--rules-dir", default=None,
                        help="corpus to check (default: the bundled engine/rules "
                             "checkout, else the installed core/rules package "
                             "data when running from a wheel — see "
                             "util.default_rules_dir)")
    prules.set_defaults(func=cmd_rules)

    prev = sub.add_parser(
        "recover", help="one-shot sweep: give stranded 'testing' hypotheses "
                        "a forward path (recycle or reject; never touches "
                        "in-flight runs)")
    prev.add_argument("engagement_id")
    prev.set_defaults(func=cmd_recover)

    pa = sub.add_parser(
        "adapter", help="dispatch one bounded JSON request for a host adapter")
    adapter_transport = pa.add_mutually_exclusive_group(required=True)
    adapter_transport.add_argument(
        "--request",
        help="one JSON object: operation, optional engagement_id, and options")
    adapter_transport.add_argument(
        "--stdio", action="store_true",
        help="serve newline-delimited JSON requests on stdin (local host protocol)")
    pa.add_argument("--disconnect-cancels", action="store_true",
                    help="cancel active work when stdin closes; host must keep stdin open until each response")
    pa.set_defaults(func=cmd_adapter)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.func not in (cmd_interface, cmd_watch) and \
            (args.demo or args.theme != "motoko-dark"):
        parser.error("--demo and --theme apply only to interface, status, and watch")
    # Resolve owner-local defaults once for the complete CLI lifetime.  A
    # gateway deliberately supplies a small environment, so tool discovery
    # and the default tasks root must be identical for direct commands,
    # adapter children, and the interface.  The helper is reversible because
    # tests and embedding hosts call ``main`` in their own Python process.
    previous_local = util.adapt_local_environment()
    previous_root = None
    if args.root is not None:
        # A global runtime override must select the same data for every
        # command and any adapter child, then leave an embedding caller's env
        # unchanged.  Apply it after local defaults so an explicit root wins.
        previous_root = os.environ.get("MOTOKO_HOME", util._MISSING)
        os.environ["MOTOKO_HOME"] = str(Path(args.root).expanduser().resolve())
    try:
        return args.func(args)
    finally:
        if previous_root is not None:
            if previous_root is util._MISSING:
                os.environ.pop("MOTOKO_HOME", None)
            else:
                os.environ["MOTOKO_HOME"] = str(previous_root)
        util.restore_local_environment(previous_local)


if __name__ == "__main__":
    sys.exit(main())
