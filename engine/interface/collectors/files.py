'FileCollector — engagement discovery and runtime-file parsing.\n\nPure stdlib, zero SQLite (design/DESIGN.md section 8, collector 1). All data\ncomes from the filesystem under the MOTOKO home root:\n\nLive-vs-sealed heuristics (best effort by design; this is a read-only\nobserver, never the authority):\n\n1. ``engagement.manifest.json`` present -> sealed. Sealed wins, full stop.\n2. Else the engagement is LIVE when any of:\n   - the writer lock is HELD: we open ``graph.db.writer.lock`` O_RDONLY (no\n     O_CREAT — we never create engine files) and try ``flock(LOCK_EX|NB)``;\n     ``BlockingIOError`` means a writer owns it. The fd is closed at once.\n   - the heartbeat file is fresh (age below ``LIVE_WINDOW_S``).\n   - ``graph.db-wal`` has a fresh mtime — a WAL with frames implies recent\n     writes. This is the stand-in for "fresh events.at" without SQLite; the\n     0-byte cosmetic WAL that read-only connections leave next to sealed\n     databases is irrelevant here because sealed wins in rule 1.\n\nNothing that carries a target identifier may leave this module unredacted:\ncooldown origins pass through ``redact.origin_label``, and TSV rows (which\ncontain raw target URLs) are counted, never returned.\n'

from __future__ import annotations

import fcntl
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from interface.render.redact import origin_label, redact_text
from interface.snapshot import Cooldown, LegStatus

LIVE_WINDOW_S = 120.0
"""Heartbeat/WAL age below which an unsealed engagement counts as live."""

_STALE_HEARTBEAT_S = 600.0
"""Heartbeat age above which the engagement data is flagged stale."""

RUNNER_STATE_FALLBACK = Path("engine/scripts/backfill-state")
"""Fallback location of the (single, engine-owned) runner state directory."""

_WAVE_ROOT = Path("wave-runs")

_PROGRESS_RE = re.compile(r"^progress:(?P<tool>[^:]+):(?P<done>\d+)/(?P<total>\d+)$")
_ROUND_RE = re.compile(r"^round-(\d+)$")
_LEG_META_RE = re.compile(r"^leg-(\d+)-(.+)-meta\.json$")

_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d_%H:%M:%S")

VALID_VERDICTS = frozenset({"CONTINUE", "ROLLBACK", "STOP"})


@dataclass(frozen=True)
class Heartbeat:
    """Parsed heartbeat file: age of the last beat plus its message."""

    age_s: float | None
    msg: str | None
    progress_done: int | None = None
    progress_total: int | None = None
    progress_tool: str | None = None


@dataclass(frozen=True)
class RunnerState:
    """Backfill-runner liveness as read from pid/ALL_DONE files."""

    pid: int | None
    alive: bool
    finished: bool  # ALL_DONE marker present


@dataclass(frozen=True)
class TsvStats:
    """Counts for the BACKFILL LINEAGE panel. Rows are never returned."""

    queue_rows: int
    queue_targets: int  # sum of the ``total`` column in queue.tsv
    done_rows: int
    failed_rows: int


@dataclass(frozen=True)
class EngagementFiles:
    """All filesystem facts about one engagement (no SQLite, no adapter)."""

    id: str
    path: Path
    sealed: bool
    live: bool
    writer_lock_held: bool
    heartbeat_age_s: float | None
    heartbeat_msg: str | None
    runner_alive: bool
    runner_finished: bool
    stale: bool
    cooldowns: tuple[Cooldown, ...] = ()
    legs: tuple[LegStatus, ...] = ()
    tsv: TsvStats = field(default_factory=lambda: TsvStats(0, 0, 0, 0))
    wave_count: int = 0
    progress_done: int | None = None
    progress_total: int | None = None


def _parse_beat_ts(ts_raw: str) -> float | None:
    """Parse a heartbeat timestamp into an epoch value.

    The backfill runner writes local wall time via ``time.strftime`` with no
    offset (research/04), so a naive timestamp is interpreted in the local
    zone — matching the producer. An offset-aware value (if a future writer
    upgrades the format) is honoured as-is.
    """
    candidate = ts_raw.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate).timestamp()
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            # Naive by design: the runner writes local wall time (no offset),
            # .timestamp() applies the local zone, matching the producer.
            return datetime.strptime(ts_raw.strip(), fmt).timestamp()  # noqa: DTZ007
        except ValueError:
            continue
    return None


def parse_heartbeat(text: str, *, now: float | None = None) -> Heartbeat:
    """Parse one heartbeat line ``<ISO-ts><TAB><msg>``.

    The file is overwritten (never appended), so the line is the latest beat.
    Age is computed from the embedded timestamp; ``None`` when unparseable.
    """
    now = time_now() if now is None else now
    line = text.strip().splitlines()[0] if text.strip() else ""
    ts_raw, _, msg = line.partition("\t")
    age: float | None = None
    beat = _parse_beat_ts(ts_raw) if ts_raw.strip() else None
    if beat is not None:
        age = max(0.0, now - beat)
    progress_done = progress_total = None
    progress_tool = None
    match = _PROGRESS_RE.match(msg.strip()) if msg else None
    if match:
        progress_tool = match.group("tool")
        progress_done = int(match.group("done"))
        progress_total = int(match.group("total"))
    clean_msg = msg.strip() or None
    return Heartbeat(age, clean_msg, progress_done, progress_total, progress_tool)


def parse_runner_pid(text: str) -> int | None:
    """Extract the runner pid from its single-line pid file."""
    for token in text.split():
        if token.isdigit():
            return int(token)
    return None


def pid_alive(pid: int | None) -> bool:
    """Liveness via /proc only (research/04: read, never signal).

    Falls back to ``os.kill(pid, 0)`` — which sends no signal — only on
    systems where /proc is not mounted.
    """
    if pid is None or pid <= 0:
        return False
    if Path("/proc").is_dir():
        return Path(f"/proc/{pid}").exists()
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def writer_lock_held(path: Path) -> bool:
    """True when some process currently holds the graph.db writer flock.

    Opens the lock file read-only (never O_CREAT) and probes it with a
    non-blocking exclusive flock; the probe fd is closed immediately and
    nothing is written. Missing file -> no writer.
    """
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True  # another process owns the writer lease
    except OSError:
        return False
    finally:
        # Closing our probe fd releases the (rarely acquired) probe lock;
        # a held lock belongs to another open file description and survives.
        os.close(fd)
    return False


def parse_cooldowns(text: str, *, now: float | None = None) -> tuple[Cooldown, ...]:
    """Parse ``opsec-cooldowns.json`` into redacted Cooldown records.

    Two formats are accepted (research/04):

    - current engine format (``CooldownBoard.snapshot()``):
      ``{"saved_at": <epoch>, "entries": [{"origin", "reason", "remaining_s"}]}``;
      ``remaining_s`` was captured at save time, so wall-clock elapsed since
      ``saved_at`` is subtracted.
    - legacy flat mapping ``{origin: until_epoch}``.

    Origins are masked with ``redact.origin_label``; reasons are engine
    enums ("429", "detected", ...) but still passed through ``redact_text``
    as belt-and-braces. Malformed JSON yields an empty tuple, never an error.
    """
    now = time_now() if now is None else now
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return ()
    if not isinstance(payload, dict):
        return ()
    out: list[Cooldown] = []
    entries = payload.get("entries")
    if isinstance(entries, list):
        saved_at = payload.get("saved_at")
        elapsed = max(0.0, now - float(saved_at)) if isinstance(saved_at, (int, float)) else 0.0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            remaining = entry.get("remaining_s")
            if not isinstance(remaining, (int, float)):
                continue
            origin = entry.get("origin")
            if not isinstance(origin, str) or not origin:
                continue
            remaining_s = max(0, round(float(remaining) - elapsed))
            reason = redact_text(str(entry.get("reason") or "unknown"))
            out.append(Cooldown(origin_label(origin), remaining_s, reason))
        return tuple(sorted(out, key=lambda c: c.origin))
    # Legacy flat shape: origin -> until-epoch seconds.
    for origin, until in payload.items():
        if not isinstance(origin, str) or not isinstance(until, (int, float)):
            continue
        remaining_s = max(0, round(float(until) - now))
        if remaining_s <= 0:
            continue
        out.append(Cooldown(origin_label(origin), remaining_s, "unknown"))
    return tuple(sorted(out, key=lambda c: c.origin))


def count_queue_rows(lines: list[str]) -> tuple[int, int]:
    """Count ``queue.tsv`` rows -> (rows, summed targets).

    Row format: ``tool<TAB>total<TAB>ts`` where ``total`` is the target
    count for one tool pass. Target counts are aggregate-only.
    """
    rows = targets = 0
    for line in lines:
        cols = line.rstrip("\n").split("\t")
        if len(cols) >= 2 and cols[0] and cols[1].isdigit():
            rows += 1
            targets += int(cols[1])
    return rows, targets


def count_done_rows(lines: list[str]) -> int:
    """Count ``done.tsv`` rows (``tool<TAB>url<TAB>ts``); URLs discarded."""
    return _count_ts_rows(lines, 3)


def count_failed_rows(lines: list[str]) -> int:
    """Count ``failed.tsv`` rows (``tool<TAB>url<TAB>status<TAB>ts``)."""
    return _count_ts_rows(lines, 4)


def _count_ts_rows(lines: list[str], min_cols: int) -> int:
    """Rows whose last column looks like the trailing timestamp."""
    count = 0
    for line in lines:
        cols = line.rstrip("\n").split("\t")
        if len(cols) >= min_cols and _looks_like_ts(cols[-1]):
            count += 1
    return count


def _looks_like_ts(value: str) -> bool:
    """Cheap timestamp-column check for TSV tail columns."""
    return len(value) >= 19 and value[4] == "-" and "T" in value


def parse_leg_meta(path: Path) -> LegStatus | None:
    """Parse one ``leg-<i>-<name>-meta.json`` into a LegStatus.

    The engine writes ``{"name", "exit_code", "stderr", ...}`` per audit leg
    (core/loop.py). A leg with a zero exit code is ok, anything else error;
    busy/idle states only exist while a round is running, which a file
    observer cannot see.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    name = payload.get("name")
    if not isinstance(name, str) or not name:
        match = _LEG_META_RE.match(path.name)
        name = match.group(2) if match else path.name
    exit_code = payload.get("exit_code")
    state = "ok" if exit_code == 0 else "error"
    return LegStatus(name=name, state=state, last_round=None, verdict=None)


def parse_verdict(path: Path) -> tuple[int | None, str | None, str]:
    """Parse ``verdict.json`` -> (round, action, reason).

    ``action`` is CONTINUE | ROLLBACK | STOP per the loop evaluator; the
    engine also writes ``{"action": "ERROR"}`` when evaluation itself blew
    up, which surfaces here as ``(None, None, reason)`` plus the raw action
    in ``reason``. Returns (None, None, "") for unreadable files.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None, None, ""
    if not isinstance(payload, dict):
        return None, None, ""
    round_num = payload.get("round")
    round_num = round_num if isinstance(round_num, int) else None
    action = payload.get("action")
    action = action if action in VALID_VERDICTS else None
    reason = str(payload.get("reason") or payload.get("error") or "")
    return round_num, action, reason


def _read_text(path: Path) -> str:
    """Read a small UTF-8 file, treating any I/O/decode problem as empty."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def time_now() -> float:
    """Wall clock; isolated for tests."""
    return datetime.now(UTC).timestamp()


class FileCollector:
    """Filesystem-only facts for every engagement under ``<root>/tasks``."""

    def __init__(self, root: Path, *, now: float | None = None,
                 runtime_root: Path | None = None,
                 live_window_s: float = LIVE_WINDOW_S,
                 stale_after_s: float = _STALE_HEARTBEAT_S) -> None:
        self.root = Path(root)
        self.runtime_root = Path(runtime_root) if runtime_root is not None else self.root / "tasks"
        self._now = now  # None -> live clock on every call
        self._live_window_s = live_window_s
        self._stale_after_s = stale_after_s

    # -- discovery ------------------------------------------------------
    def engagement_ids(self) -> list[str]:
        """Engagement ids = child directories under ``<root>/tasks``.

        Dot-prefixed entries are engine-internal (e.g. ``.host-processes``)
        and never engagements; engine ids must start with ``[A-Za-z0-9]``.
        """
        runtime = self.runtime_root
        try:
            return sorted(p.name for p in runtime.iterdir()
                          if p.is_dir() and not p.name.startswith("."))
        except OSError:
            return []

    # -- per-engagement collection --------------------------------------
    def collect(self, eng_id: str) -> EngagementFiles:
        """Read every file-level fact for one engagement. Never raises."""
        now = self._now if self._now is not None else time_now()
        edir = self.runtime_root / eng_id
        sealed = (edir / "engagement.manifest.json").is_file()
        lock_held = writer_lock_held(edir / "graph.db.writer.lock")
        heartbeat = self._read_heartbeat(eng_id, sealed=sealed)
        wal_fresh = self._wal_fresh(edir / "graph.db-wal", now)
        live = (not sealed) and (lock_held or self._heartbeat_fresh(heartbeat)
                                 or wal_fresh)
        runner = self._runner_state(eng_id, sealed=sealed)
        heartbeat_age = heartbeat.age_s
        if heartbeat_age is None:
            heartbeat_age = self._heartbeat_mtime_age(eng_id, now, sealed=sealed)
        stale = heartbeat_age is not None and heartbeat_age > self._stale_after_s
        return EngagementFiles(
            id=eng_id,
            path=edir,
            sealed=sealed,
            live=live,
            writer_lock_held=lock_held,
            heartbeat_age_s=heartbeat_age,
            heartbeat_msg=redact_text(heartbeat.msg),
            runner_alive=runner.alive,
            runner_finished=runner.finished,
            stale=stale,
            cooldowns=self._cooldowns(edir, now),
            legs=self._legs(edir),
            tsv=self._tsv(eng_id, sealed=sealed),
            wave_count=self._wave_count(edir),
            progress_done=heartbeat.progress_done,
            progress_total=heartbeat.progress_total,
        )

    # -- heartbeat / runner ---------------------------------------------
    def _runner_dirs(self, eng_id: str, *, sealed: bool) -> list[Path]:
        """Runner-state search path for one engagement.

        Per-engagement artifacts (``tasks/<eng>/heartbeat``, ``runner.pid``,
        ``ALL_DONE``, TSVs) always win. The engine-owned global directory
        (``RUNNER_STATE_FALLBACK`` — org-level backfill lineage, research/04)
        is consulted only for UNSEALED engagements without their own files:
        binding a shared runner's age to a finished sealed engagement would
        wrongly flag it stale.
        """
        dirs = [self.runtime_root / eng_id]
        if not sealed and self.runtime_root == self.root / "tasks":
            dirs.append(self.root / RUNNER_STATE_FALLBACK)
        return dirs

    def _heartbeat_path(self, eng_id: str, *, sealed: bool) -> Path | None:
        """Per-engagement heartbeat first, runner-state dir as fallback."""
        for directory in self._runner_dirs(eng_id, sealed=sealed):
            path = directory / "heartbeat"
            if path.is_file():
                return path
        return None

    def _read_heartbeat(self, eng_id: str, *, sealed: bool) -> Heartbeat:
        path = self._heartbeat_path(eng_id, sealed=sealed)
        if path is None:
            return Heartbeat(None, None)
        return parse_heartbeat(_read_text(path), now=self._now)

    def _heartbeat_fresh(self, heartbeat: Heartbeat) -> bool:
        return heartbeat.age_s is not None and heartbeat.age_s <= self._live_window_s

    def _heartbeat_mtime_age(self, eng_id: str, now: float, *,
                             sealed: bool) -> float | None:
        path = self._heartbeat_path(eng_id, sealed=sealed)
        if path is None:
            return None
        try:
            return max(0.0, now - path.stat().st_mtime)
        except OSError:
            return None

    def _wal_fresh(self, wal: Path, now: float) -> bool:
        """Fresh WAL mtime as the no-SQLite proxy for fresh events.at."""
        try:
            stat = wal.stat()
        except OSError:
            return False
        return stat.st_size > 0 and (now - stat.st_mtime) <= self._live_window_s

    def _runner_state(self, eng_id: str, *, sealed: bool) -> RunnerState:
        for directory in self._runner_dirs(eng_id, sealed=sealed):
            if (directory / "ALL_DONE").is_file():
                return RunnerState(None, False, True)
        for directory in self._runner_dirs(eng_id, sealed=sealed):
            pid_path = directory / "runner.pid"
            if pid_path.is_file():
                pid = parse_runner_pid(_read_text(pid_path))
                return RunnerState(pid, pid_alive(pid), False)
        return RunnerState(None, False, False)

    # -- cooldowns / legs / tsv / waves ----------------------------------
    def _cooldowns(self, edir: Path, now: float) -> tuple[Cooldown, ...]:
        return parse_cooldowns(_read_text(edir / "opsec-cooldowns.json"), now=now)

    def _legs(self, edir: Path) -> tuple[LegStatus, ...]:
        'LegStatus rows from the newest round that carries leg artifacts.'
        waves = edir / _WAVE_ROOT
        for round_dir in self._round_dirs(waves):  # newest first
            metas = sorted(round_dir.glob("leg-*-meta.json"))
            verdict_path = round_dir / "verdict.json"
            if not metas and not verdict_path.is_file():
                continue
            round_num, action, _ = parse_verdict(verdict_path)
            legs: list[LegStatus] = []
            for meta in metas:
                leg = parse_leg_meta(meta)
                if leg is None:
                    continue
                legs.append(LegStatus(name=leg.name, state=leg.state,
                                      last_round=round_num, verdict=action))
            if legs:
                return tuple(legs)
        return ()

    def _round_dirs(self, waves: Path) -> list[Path]:
        """All round-N directories across waves, newest round first."""
        rounds: list[tuple[int, Path]] = []
        try:
            wave_dirs = [p for p in waves.iterdir() if p.is_dir()]
        except OSError:
            return []
        for wave in wave_dirs:
            try:
                candidates = list(wave.iterdir())
            except OSError:
                continue
            for candidate in candidates:
                match = _ROUND_RE.match(candidate.name)
                if candidate.is_dir() and match:
                    rounds.append((int(match.group(1)), candidate))
        return [path for _, path in sorted(rounds, reverse=True)]

    def _wave_count(self, edir: Path) -> int:
        waves = edir / _WAVE_ROOT
        try:
            return sum(1 for p in waves.iterdir() if p.is_dir())
        except OSError:
            return 0

    def _tsv(self, eng_id: str, *, sealed: bool) -> TsvStats:
        """Count runner TSV rows (contents are never returned)."""
        directory = None
        for candidate in self._runner_dirs(eng_id, sealed=sealed):
            if (candidate / "queue.tsv").is_file():
                directory = candidate
                break
        if directory is None:
            return TsvStats(0, 0, 0, 0)
        queue_rows, queue_targets = count_queue_rows(
            _read_text(directory / "queue.tsv").splitlines())
        done_rows = count_done_rows(_read_text(directory / "done.tsv").splitlines())
        failed_rows = count_failed_rows(
            _read_text(directory / "failed.tsv").splitlines())
        return TsvStats(queue_rows, queue_targets, done_rows, failed_rows)
