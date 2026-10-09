"""Findings watchdog — the host-consumable delta sweep.

The engine primitive that succeeds the retired shell watchdog looper.
One ``motoko watch --once`` invocation scans every engagement under the
tasks root for:

* new finding ids — the union of ``observations.new_finding_ids`` in the
  engagement's ``graph.db`` (severity read off the finding entity, exactly
  the watchdog's two queries), and
* strix run completions — ``<engagement>/strix_runs/<run>/run.json``
  reaching a terminal status (``completed``/``failed``; ``running`` and
  ``interrupted`` are not completions). Extra run roots outside the tasks
  tree (a shepherd burn dir on tmpfs, say) are added with ``--strix-root``.

The sweep prints the deltas since the last run and advances a cursor file,
``<tasks root>/watch-cursor.json``, so the next run reports only what is
new. Scheduling belongs to the host (cron, systemd timer, seat loop) — the
engine owns the scan and the cursor, never the loop. There is deliberately
no loop mode; run ``--once`` from whatever scheduler the host already has.

Cursor semantics:

* First run (no cursor file) ESTABLISHES the cursor and reports an empty
  delta by design: installing the watcher on a tree with history means
  "from now on", not a replay of the past.
* The cursor records seen finding IDS per engagement (not counts — the
  ``--json`` delta lists the ids, and an id set cannot drift into a
  re-report the way a count can when observations are rewritten) plus the
  seen terminal strix runs (``<engagement>/<run>``; an absolute run-dir
  path for extra roots).
* Entries whose engagement or run directory no longer exists are pruned:
  a tmpfs-swept run dir recreated under the same slug is a NEW run and
  must report again.
* An engagement whose graph.db cannot be scanned keeps its old cursor
  entry (nothing is silently lost) and the run exits 1 after reporting
  every healthy delta.

Exit contract (read-only ops): 0 even with no deltas, 2 for refusal-class
misuse (a tasks root that does not exist), 1 on errors (corrupt cursor,
unwritable cursor, an unscannable engagement).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import db, util

CURSOR_NAME = "watch-cursor.json"
CURSOR_VERSION = 1

#: run.json statuses the sweep treats as completions (watchdog.sh parity:
#: a session still going, or interrupted, is not a completion).
TERMINAL_STRIX_STATES = ("completed", "failed")


class WatchError(RuntimeError):
    """A sweep that cannot start or finish honestly (cursor, tasks root)."""


def cursor_path(root: Path) -> Path:
    return Path(root) / CURSOR_NAME


def _fresh_cursor() -> dict:
    return {"version": CURSOR_VERSION, "engagements": {}, "strix_runs": []}


def _load_cursor(path: Path) -> tuple[dict, bool]:
    """Read the cursor; a missing file means first run, not an error."""
    if not path.exists():
        return _fresh_cursor(), True
    try:
        data = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise WatchError(
            f"cursor {path} is unreadable ({exc}); refusing to guess — "
            f"remove it to re-baseline (the next run then reports an empty "
            f"delta by design)") from None
    if not isinstance(data, dict) or not isinstance(
            data.get("engagements"), dict) or not isinstance(
            data.get("strix_runs"), list):
        raise WatchError(
            f"cursor {path} has an unexpected shape; refusing to guess — "
            f"remove it to re-baseline")
    return data, False


def _save_cursor(path: Path, cursor: dict) -> None:
    """Atomic install: temp file in the same directory + rename, so a
    crashed sweep never leaves a half-written cursor that the next run
    would read as a baseline."""
    cursor["version"] = CURSOR_VERSION
    cursor["updated_at"] = util.now_iso()
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(cursor, ensure_ascii=False, indent=2,
                                  sort_keys=True) + "\n")
        os.replace(tmp, path)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise WatchError(f"could not write cursor {path}: {exc}") from None


def _scan_findings(graph: Path, engagement_id: str) -> dict[str, str]:
    """finding id -> severity for every id any observation ever reported.

    Read-only connection, per-row guarded JSON (watchdog.sh parity): a
    corrupt cell degrades to no ids instead of killing the sweep.
    """
    found: dict[str, str] = {}
    ro = db.Database(graph, read_only=True)
    try:
        rows = ro.conn.execute(
            "SELECT new_finding_ids FROM observations WHERE engagement_id = ?",
            (engagement_id,))
        ids: set[str] = set()
        for (raw,) in rows:
            try:
                for fid in json.loads(raw or "[]"):
                    ids.add(str(fid))
            except (TypeError, ValueError):
                continue
        for fid in sorted(ids):
            row = ro.conn.execute(
                "SELECT data FROM entities WHERE id = ?", (fid,)).fetchone()
            severity = "?"
            if row:
                try:
                    severity = str(json.loads(row[0] or "{}").get(
                        "severity", "?"))
                except (TypeError, ValueError):
                    pass
            found[fid] = severity
    finally:
        ro.close()
    return found


def _scan_strix_runs(runs_dir: Path) -> dict[str, dict]:
    """run name -> {status, findings} for terminal runs under one root.

    An unreadable or missing run.json is skipped silently: the run is
    most likely still starting up, and the next sweep re-reads it.
    """
    runs: dict[str, dict] = {}
    if not runs_dir.is_dir():
        return runs
    for child in sorted(runs_dir.iterdir()):
        run_json = child / "run.json"
        if not child.is_dir() or not run_json.is_file():
            continue
        try:
            data = json.loads(run_json.read_text())
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        status = data.get("status")
        if status not in TERMINAL_STRIX_STATES:
            continue
        findings = data.get("findings") or []
        runs[child.name] = {
            "status": str(status),
            "findings": len(findings) if isinstance(findings, list) else 0,
        }
    return runs


def sweep(root: Path, extra_roots: list[Path] | None = None,
          cursor_file: Path | None = None) -> dict:
    """Scan the tasks root and return deltas + the advanced cursor.

    Pure with respect to the on-disk cursor: the caller decides when (and
    whether) to persist ``result["cursor"]``, so a failed save never eats
    the printed deltas.

    ``cursor_file`` overrides the default ``<root>/watch-cursor.json``. A host UI
    that must not write inside the tasks tree (the native panel's read-only
    contract) passes its own cursor path outside the tree; the default
    keeps every existing caller unchanged.
    """
    root = Path(root)
    if not root.is_dir():
        raise WatchError(f"tasks root not found: {root}")
    path = (Path(cursor_file).expanduser() if cursor_file is not None
            else cursor_path(root))
    cursor, first_run = _load_cursor(path)
    seen_engagements: dict[str, list[str]] = {
        str(eng): sorted(str(fid) for fid in ids)
        for eng, ids in cursor["engagements"].items()
        if isinstance(ids, list)
    }
    seen_runs: set[str] = {str(k) for k in cursor["strix_runs"]}

    deltas: list[dict] = []
    errors: list[str] = []
    new_engagements: dict[str, list[str]] = {}
    new_runs: set[str] = set()

    engagements = sorted(
        (d for d in root.iterdir()
         if d.is_dir() and (d / "graph.db").is_file()),
        key=lambda d: d.name)
    for edir in engagements:
        eng = edir.name
        try:
            findings = _scan_findings(edir / "graph.db", eng)
        except Exception as exc:  # unreadable db: keep its old cursor entry
            errors.append(f"{eng}: could not scan graph.db ({exc})")
            if eng in seen_engagements:
                new_engagements[eng] = seen_engagements[eng]
            continue
        known = set(seen_engagements.get(eng, []))
        new_engagements[eng] = sorted(findings)
        new_ids = [fid for fid in sorted(findings) if fid not in known]

        completions = []
        for run_name, info in _scan_strix_runs(edir / "strix_runs").items():
            key = f"{eng}/{run_name}"
            new_runs.add(key)
            if key not in seen_runs:
                completions.append({"run": key, **info})
        if new_ids or completions:
            deltas.append({
                "engagement": eng,
                "new_finding_ids": new_ids,
                # severity is display metadata, never cursor state
                "finding_severities": {fid: findings[fid] for fid in new_ids},
                "strix_completions": completions,
            })

    for extra in extra_roots or []:
        extra = Path(extra)
        if not extra.is_dir():
            errors.append(f"strix root not found: {extra}")
            continue
        completions = []
        for run_name, info in _scan_strix_runs(extra).items():
            key = str(extra / run_name)
            new_runs.add(key)
            if key not in seen_runs:
                completions.append({"run": key, **info})
        if completions:
            deltas.append({"engagement": None,
                           "new_finding_ids": [],
                           "finding_severities": {},
                           "strix_completions": completions})

    # Runs whose directories vanished fall out of the cursor here: a run
    # dir recreated under the same slug (tmpfs sweep + shepherd restart)
    # is a NEW run and must report again. Vanished engagements likewise
    # (they are simply absent from new_engagements).
    new_cursor = {"version": CURSOR_VERSION,
                  "engagements": new_engagements,
                  "strix_runs": sorted(new_runs)}
    if first_run:
        # Establishing the baseline reports nothing: "from now on", not a
        # replay of the tree's whole history.
        deltas = []
    return {"deltas": deltas, "errors": errors, "first_run": first_run,
            "cursor": new_cursor, "cursor_path": path,
            "stats": {"engagements": len(new_engagements),
                      "strix_runs_seen": len(new_runs)}}


def _print_human(result: dict) -> None:
    for delta in result["deltas"]:
        severities = delta.get("finding_severities") or {}
        for fid in delta["new_finding_ids"]:
            print(f"NEW FINDING {delta['engagement']} {fid} "
                  f"severity={severities.get(fid, '?')}")
        for comp in delta["strix_completions"]:
            print(f"STRIX {comp['run']} status={comp['status']} "
                  f"findings={comp['findings']}")


def cmd_watch(args) -> int:
    """``motoko watch --once``: print the deltas since the cursor, advance it."""
    root = db.default_root()
    if not root.is_dir():
        print(f"watch: tasks root not found: {root} — run `motoko init` "
              f"first, or point MOTOKO_HOME/--root at the live tasks root",
              file=sys.stderr)
        return 2
    extra = [Path(p).expanduser()
             for p in (getattr(args, "strix_root", None) or [])]
    cursor = getattr(args, "cursor", None)
    # `is not None`: an explicitly passed empty value must not silently fall
    # back to the default in-tree cursor (the write this option exists to
    # avoid); it fails loudly on save instead.
    cursor = Path(cursor).expanduser() if cursor is not None else None
    try:
        result = sweep(root, extra_roots=extra, cursor_file=cursor)
    except WatchError as exc:
        print(f"watch: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(json.dumps({
            "cursor": str(result["cursor_path"]),
            "first_run": result["first_run"],
            "deltas": result["deltas"],
            "errors": result["errors"],
        }, ensure_ascii=False, indent=2))
    else:
        _print_human(result)

    try:
        _save_cursor(result["cursor_path"], result["cursor"])
    except WatchError as exc:
        print(f"watch: {exc}", file=sys.stderr)
        return 1

    if not getattr(args, "json", False) and result["first_run"]:
        # Only claim the cursor is established once it is on disk: with a
        # missing parent directory the save above fails first.
        stats = result["stats"]
        print(f"watch cursor established: {result['cursor_path']} "
              f"({stats['engagements']} engagements, "
              f"{stats['strix_runs_seen']} terminal strix runs already "
              f"seen — reporting from now on)", file=sys.stderr)

    for err in result["errors"]:
        print(f"watch: {err}", file=sys.stderr)
    return 1 if result["errors"] else 0
