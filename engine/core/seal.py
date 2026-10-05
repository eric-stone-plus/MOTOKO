"""Engagement sealing — turn a finished campaign's runtime state into a
verifiable artifact.

A sealed engagement is the product unit (ARCHITECTURE.md): engine commit +
checkpointed graph.db + engagement.manifest.json. Contract:

* Refuses a live engagement: seal takes the engagement's writer lock
  (``graph.db.writer.lock`` flock, the same gate ``db.Database`` writers
  take) for its whole critical section, and the TRUNCATE checkpoint
  reports busy if a non-flock writer holds the DB — either way seal
  aborts without writing a manifest. Sealing must never race the
  single-writer orchestrator.
* Structural integrity is a hard gate (integrity_check, foreign_key_check,
  WAL removal). Operational findings (stranded hypotheses, unprocessed
  observations) are recorded in the manifest census but never block a
  seal — a campaign cut short is still a legal artifact.
* The seal event is appended to the event log BEFORE the hash is taken,
  so the manifest's graph_db.sha256 covers its own provenance record.
* Idempotent: re-sealing a sealed engagement re-checkpoints, re-verifies
  and rewrites the manifest (previous seal time kept under
  previously_sealed_at).
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import db, events, state_machine


class SealError(Exception):
    """Seal refused — the engagement is not in a sealable state."""


def _engine_commit(engine_root: Path) -> str:
    """git rev-parse HEAD of the engine repo, or 'unknown' outside a repo."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=engine_root,
            capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _census(conn: sqlite3.Connection, engagement_id: str) -> dict:
    """Read-only census of the sealed state. Operational anomalies land
    here as counts — they inform the operator, they do not block."""
    cur = conn.cursor()
    census: dict = {}

    rows = cur.execute(
        "SELECT kind, state, COUNT(*) FROM entities WHERE engagement_id = ? "
        "GROUP BY kind, state ORDER BY kind, state",
        (engagement_id,)).fetchall()
    by_kind_state = {f"{k}/{s}": n for k, s, n in rows}
    census["entities_by_kind_state"] = by_kind_state

    # terminal vs open findings per the finding state machine
    terminal = state_machine.TERMINAL_STATES
    findings_total = sum(n for k, s, n in rows if k == "finding")
    findings_terminal = sum(n for k, s, n in rows
                            if k == "finding" and s in terminal)
    census["findings_total"] = findings_total
    census["findings_terminal"] = findings_terminal
    census["findings_open"] = findings_total - findings_terminal

    testing = sum(n for k, s, n in rows if k == "hypothesis" and s == "testing")
    census["hypotheses_testing"] = testing

    # Append-only log (core never DELETEs from events), so the live cursor
    # is the count — and it is O(1) instead of a multi-million-row scan.
    census["events"] = cur.execute(
        "SELECT COALESCE(MAX(seq), 0) FROM events").fetchone()[0]
    census["edges"] = cur.execute(
        "SELECT COUNT(*) FROM edges").fetchone()[0]
    census["observations_total"] = cur.execute(
        "SELECT COUNT(*) FROM observations").fetchone()[0]
    census["observations_unprocessed"] = cur.execute(
        "SELECT COUNT(*) FROM observations WHERE processed_at IS NULL"
    ).fetchone()[0]
    census["tool_runs"] = dict(cur.execute(
        "SELECT status, COUNT(*) FROM tool_run GROUP BY status").fetchall())
    return census


def seal_engagement(engagement_id: str, root: Path | None = None) -> dict:
    """Seal one engagement. Returns the manifest dict; raises SealError on
    refusal (missing engagement, live writer, failed integrity)."""
    root = root or db.default_root()
    edir = db.engagement_dir(root, engagement_id)
    graph = edir / "graph.db"
    if not graph.exists():
        raise SealError(f"engagement {engagement_id!r} not found: no graph.db "
                        f"at {edir}")
    wal = Path(str(graph) + "-wal")
    manifest_path = edir / "engagement.manifest.json"
    previously_sealed_at = None
    if manifest_path.exists():
        try:
            previously_sealed_at = json.loads(
                manifest_path.read_text()).get("sealed_at")
        except (OSError, ValueError):
            previously_sealed_at = None

    # -- single-writer assertion ------------------------------------------
    # The engine's writer gate is the flock on graph.db.writer.lock (every
    # db.Database writer takes it LOCK_EX on open). Hold it for the whole
    # critical section: the checkpoint-busy and leftover-sidecar checks
    # below only catch a writer that ALREADY wrote — the flock is what
    # keeps an engine writer out between the checkpoint, the hash, and the
    # manifest write.
    lock_fd = None
    try:
        lock_fd = os.open(str(graph) + ".writer.lock", os.O_CREAT | os.O_RDWR, 0o600)
    except PermissionError as e:
        # The lock is 0600 beside a 0700 engagement dir, so a sealer running
        # as another account cannot even open it. Say that, rather than
        # letting a bare PermissionError escape: the operator would read a
        # uid boundary as a broken artifact.
        raise SealError(
            f"{engagement_id}: cannot open the writer lock ({e}). The "
            f"engagement store is owned by another account — seal as that "
            f"account") from None
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        raise SealError(
            f"{engagement_id}: another writer owns the graph.db writer lock "
            f"— refusing to seal a live engagement") from None
    try:
        # -- WAL checkpoint ---------------------------------------------
        # A short busy timeout makes a concurrent writer fail fast instead
        # of silently sealing a snapshot mid-write.
        conn = sqlite3.connect(str(graph), timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
            if str(journal).lower() == "wal":
                busy, wal_pages, ckpt_pages = conn.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if busy:
                    raise SealError(
                        f"{engagement_id}: graph.db is busy (another writer "
                        f"holds it) — refusing to seal a live engagement")
                if wal_pages and ckpt_pages < wal_pages:
                    raise SealError(
                        f"{engagement_id}: checkpoint incomplete "
                        f"({ckpt_pages}/{wal_pages} pages) — refusing to seal")
            conn.execute("PRAGMA busy_timeout = 5000")

            # -- hard gates -----------------------------------------------
            integrity = conn.execute("PRAGMA integrity_check").fetchall()
            bad = [r[0] for r in integrity if r[0] != "ok"]
            if bad:
                raise SealError(f"{engagement_id}: integrity_check failed: "
                                f"{bad[:3]}")
            fk = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk:
                raise SealError(f"{engagement_id}: foreign_key_check reported "
                                f"{len(fk)} violations")

            replay = events.verify(conn, graph=str(graph),
                                   engagement_id=engagement_id)
            if not replay.ok:
                first = replay.violations[0]
                raise SealError(
                    f"{engagement_id}: the event log does not replay "
                    f"({len(replay.violations)} violation(s); first: "
                    f"{first.check} seq={first.seq} {first.detail[:160]}) — "
                    f"refusing to seal a product unit whose log cannot be "
                    f"rebuilt from itself. Inspect with "
                    f"`motoko events {engagement_id} --verify`")

            # -- record the seal inside the event log (pre-hash) ----------
            # Through events.insert_row, the same funnel every other writer
            # uses, so the kind vocabulary is checked here too and the seal
            # cannot become a row no reader recognizes.
            events.insert_row(conn, "engagement_sealed", None, {
                "engine": "seal", "previously_sealed_at": previously_sealed_at})
            conn.commit()
            census = _census(conn, engagement_id)
            schema_version = None
            try:
                row = conn.execute(
                    "SELECT value FROM schema_meta WHERE key = 'schema_version'"
                ).fetchone()
                schema_version = row[0] if row else None
            except sqlite3.Error:
                pass
        finally:
            conn.close()

        # A clean close of the last connection removes -wal/-shm. Their
        # survival means the checkpoint did not take (or a reader still
        # holds them) — the artifact would not be self-contained.
        leftovers = [p.name for p in (wal, Path(str(graph) + "-shm")) if p.exists()]
        if leftovers:
            raise SealError(f"{engagement_id}: WAL sidecars survived checkpoint "
                            f"close: {leftovers} — a reader still holds the db")

        engine_root = Path(__file__).resolve().parent.parent
        manifest = {
            "motoko": "engagement-seal/1",
            "engagement_id": engagement_id,
            "sealed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "previously_sealed_at": previously_sealed_at,
            "engine_commit": _engine_commit(engine_root),
            "schema_version": schema_version,
            "graph_db": {"sha256": _sha256_file(graph), "bytes": graph.stat().st_size},
            "integrity": {"integrity_check": "ok", "foreign_key_check": "ok",
                          "wal_removed": True},
            # The replay gate's own verdict, carried by the artifact. A
            # consumer reading a manifest can now tell "the log was checked
            # and replayed" from "nothing looked" — the sha proves the bytes,
            # this proves they mean something.
            "events_verified": {"ok": True, "events": replay.events,
                                "warnings": len(replay.warnings)},
            "census": census,
        }

        # atomic manifest write: temp file in the same dir, then rename
        fd, tmp = tempfile.mkstemp(dir=str(edir), prefix=".manifest-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(tmp, manifest_path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return manifest
    finally:
        os.close(lock_fd)


def verify_seal(engagement_id: str, root: Path | None = None) -> tuple[bool, str]:
    """Re-derive the artifact and check it against its manifest.

    Verifies: manifest exists, graph.db sha256 matches, byte size matches,
    schema version unchanged. This is the consumption side of the product
    unit — anyone with the engagement dir can confirm the artifact is the
    one the seal signed, without trusting the disk's history.
    """
    root = root or db.default_root()
    edir = db.engagement_dir(root, engagement_id)
    graph = edir / "graph.db"
    manifest_path = edir / "engagement.manifest.json"
    if not graph.exists():
        return False, f"no graph.db at {edir}"
    if not manifest_path.exists():
        return False, "never sealed (no engagement.manifest.json)"
    try:
        m = json.loads(manifest_path.read_text())
    except ValueError as e:
        return False, f"manifest unreadable: {e}"
    actual = _sha256_file(graph)
    if actual != m.get("graph_db", {}).get("sha256"):
        return False, ("sha256 MISMATCH — graph.db changed after sealing "
                       "(run `motoko seal` again to re-sign)")
    size = graph.stat().st_size
    if size != m.get("graph_db", {}).get("bytes"):
        return False, "byte size mismatch vs manifest"
    wal = Path(str(graph) + "-wal")
    if wal.exists() and wal.stat().st_size > 0:
        return False, ("WAL FRAMES present next to the sealed graph.db — the "
                       "database drifted after sealing (re-seal to re-sign)")
    ver = None
    try:
        con = sqlite3.connect(f"{graph.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
        try:
            row = con.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            ver = row[0] if row else None
        finally:
            con.close()
    except sqlite3.Error as e:
        return False, f"db unreadable: {e}"
    if ver != m.get("schema_version"):
        return False, (f"schema version drifted: manifest {m.get('schema_version')}"
                       f" vs db {ver}")
    sealed_at = m.get("sealed_at", "?")
    commit = (m.get("engine_commit") or "?")[:9]
    return True, f"manifest match (sealed {sealed_at} @ engine {commit})"


def cmd_seal(args) -> int:
    root = Path(args.root) if getattr(args, "root", None) else None
    if getattr(args, "verify", False):
        ok, detail = verify_seal(args.engagement_id, root=root)
        mark = "verify OK  " if ok else "verify FAIL"
        print(f"{mark} {args.engagement_id}: {detail}")
        return 0 if ok else 1
    try:
        manifest = seal_engagement(args.engagement_id, root=root)
    except SealError as e:
        print(f"seal refused: {e}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    return 0
