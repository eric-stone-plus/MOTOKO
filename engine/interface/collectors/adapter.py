'AdapterClient — defensive client for the engine\'s ``motoko/1`` stdio adapter.\n\nThe protocol is implemented strictly from the engine source\n(``engine/core/adapter.py``, read-only): newline-delimited JSON frames, each\nrequest ``{"protocol": "motoko/1", "request_id": <int>, "operation": str,\n"engagement_id": str|null, "options": object|null}`` and each response\n``{"protocol": "motoko/1", "request_id": int, "ok": bool, "exit_code": int,\n"result"|"error": ...}``.\n\nSafety envelope (the internal design notes sections 1, 2 and 9):\n\n- ONLY read operations are ever sent: capabilities, doctor, rules, status,\n  digest, health (plus query/events, which this prototype does not need\n  because the activity feed reads ro-SQLite directly). The mutating ``run``\n  operation is\n  NEVER sent; it is only detected in the capabilities response so the UI can\n  honestly report the engine\'s advertised capability set.\n- The adapter subprocess uses this installation\'s Python and ``-m core``;\n  if the binary is absent or the handshake fails, the client degrades to\n  unavailable (every call returns ``None``) and the UI renders\n  "adapter unavailable". Nothing raises into the UI.\n- The engine serves at most 32 requests per process (``MAX_REQUESTS``); the\n  client counts every sent request and transparently restarts the subprocess\n  once the budget is exhausted.\n- A child we spawned ourselves is stopped with ``terminate()``/``kill()`` by\n  PID handle — never by process name.'

from __future__ import annotations

import atexit
import json
import os
import select
import shutil
import subprocess
import sys
import threading
import time
import weakref
from pathlib import Path
from typing import Any, Self

PROTOCOL = "motoko/1"
PROTOCOL_COMMAND = (sys.executable, "-m", "core", "adapter", "--stdio")
MAX_FRAME_BYTES = 64 * 1024  # engine-side limit, mirrored defensively
DEFAULT_REQUEST_BUDGET = 32  # engine MAX_REQUESTS; re-learned at handshake
REQUEST_TIMEOUT_S = 15.0

WATCHDOG_POLL_S = 5.0
"""Watchdog cadence: how often orphaned spawns are looked for."""

REAP_WAIT_S = 2.0
"""Bounded per-child wait on emergency reaps so exits never hang."""

READ_OPERATIONS = frozenset(
    {"capabilities", "doctor", "rules", "status", "digest", "query", "events",
     "health"})
MUTATING_OPERATIONS = frozenset({"run"})  # detected only, never sent


# --------------------------------------------------------------------------
# Child registry: track every spawn so no exit path leaks a subprocess.
# --------------------------------------------------------------------------

#: pid -> (weak owner reference, live child handle). Strong Popen references
#: on purpose: the child must stay reapable after its client is gone.
_children: dict[int, tuple[weakref.ref[AdapterClient], subprocess.Popen[bytes]]] = {}
_children_lock = threading.Lock()
_watchdog_thread: threading.Thread | None = None


def _stop_child(proc: subprocess.Popen[bytes], *, wait_s: float = 5.0) -> None:
    """Close our pipe ends, then stop the child by handle; never raises.

    The pipes close BEFORE signalling (the child can exit on stdin EOF by
    itself, and the descriptors stop outliving the handle — Popen closes
    neither for us). Every stage is best-effort with a bounded wait so a
    wedged adapter cannot hang the caller.
    """
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except OSError:
            pass
    try:
        proc.terminate()
        proc.wait(timeout=wait_s)
    except (OSError, subprocess.TimeoutExpired):
        try:
            proc.kill()
            proc.wait(timeout=wait_s)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _register_child(owner: AdapterClient,
                    proc: subprocess.Popen[bytes]) -> None:
    """Track a fresh spawn; lazily (re)start the daemon watchdog."""
    global _watchdog_thread
    with _children_lock:
        _children[proc.pid] = (weakref.ref(owner), proc)
        if _watchdog_thread is None or not _watchdog_thread.is_alive():
            _watchdog_thread = threading.Thread(
                target=_watchdog_loop, name="motoko-adapter-watchdog", daemon=True)
            _watchdog_thread.start()


def _forget_child(proc: subprocess.Popen[bytes]) -> None:
    """Drop a child from the registry (it was stopped or exited already)."""
    with _children_lock:
        _children.pop(proc.pid, None)


def _watchdog_loop() -> None:
    """Reap spawns whose owning client vanished without ``close()``.

    Daemon thread: dies with the process, restarts on the next spawn. For
    each tracked child: already-exited entries are dropped; a child whose
    ``AdapterClient`` was garbage-collected is stopped by handle. Children
    with a live owner are untouched — their teardown path owns them.
    """
    while True:
        time.sleep(WATCHDOG_POLL_S)
        with _children_lock:
            entries = list(_children.items())
        for _pid, (owner_ref, proc) in entries:
            if proc.poll() is not None:
                _forget_child(proc)
                continue
            if owner_ref() is None:
                _forget_child(proc)
                _stop_child(proc, wait_s=REAP_WAIT_S)


def _reap_all() -> None:
    """atexit hook: stop every adapter child this process still owns.

    Bounded per child (``REAP_WAIT_S``) and exception-free — an atexit
    handler must never hang or print over the UI on interpreter exit.
    ``close_sessions()`` already covers CLI exits; this catches direct
    users of :class:`AdapterClient` that never reached a ``finally``.
    """
    with _children_lock:
        entries = list(_children.values())
        _children.clear()
    for _owner_ref, proc in entries:
        _stop_child(proc, wait_s=REAP_WAIT_S)


atexit.register(_reap_all)


class AdapterClient:
    """Spawn-lazy, budget-aware JSONL client for the read-only adapter ops."""

    def __init__(self, *, command: list[str] | None = None,
                 runtime_root: Path | None = None,
                 request_timeout_s: float = REQUEST_TIMEOUT_S) -> None:
        self._command = command if command is not None else list(PROTOCOL_COMMAND)
        self._runtime_root = runtime_root
        self._request_timeout_s = request_timeout_s
        self._proc: subprocess.Popen[bytes] | None = None
        self._read_buffer = b""
        self._sent = 0
        self._next_request_id = 0
        self._spawn_failed = False
        self.available = False
        self.operations: tuple[str, ...] = ()
        self.max_requests = DEFAULT_REQUEST_BUDGET

    # -- lifecycle -------------------------------------------------------
    def _spawn(self) -> bool:
        "Start the configured interpreter's adapter, then handshake.\n\n        - **binary missing / Popen OSError** latches ``_spawn_failed``: later\n          requests fail fast for this client's lifetime. Recovery requires a\n          new client; the early return in ``_request`` prevents a latched\n          client from reaching the request-budget restart path.\n        - **a bad handshake** (capabilities absent/not ok, or an immediate\n          exit surfacing as a closed pipe) does NOT latch — it tears down and\n          returns False, so the next request can retry spawn+handshake. The\n          collector schedules its probes on the 15 s TTL; this client has no\n          retry timer of its own.\n        "
        binary = shutil.which(self._command[0])
        if binary is None:
            self._spawn_failed = True
            return False
        try:
            child_env = dict(os.environ)
            if self._runtime_root is not None:
                child_env["MOTOKO_HOME"] = str(self._runtime_root)
            self._proc = subprocess.Popen(
                [binary, *self._command[1:]],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=child_env,
            )
        except OSError:
            self._proc = None
            self._spawn_failed = True
            return False
        _register_child(self, self._proc)
        self._sent = 0
        self._read_buffer = b""
        capabilities = self._exchange("capabilities")
        if capabilities is None or not capabilities.get("ok"):
            self._teardown()
            return False
        result = capabilities.get("result")
        if not isinstance(result, dict) or "capabilities" not in result.get(
                "operations", []):
            self._teardown()
            return False
        self.operations = tuple(result.get("operations") or ())
        budget = result.get("max_requests_per_process")
        if isinstance(budget, int) and not isinstance(budget, bool) and budget > 0:
            self.max_requests = budget
        self.available = True
        return True

    def _teardown(self) -> None:
        """Stop our own child by handle; never by name."""
        proc, self._proc = self._proc, None
        self.available = False
        # A partial frame from the dying process must never pollute the next
        # spawn's stream.
        self._read_buffer = b""
        if proc is None:
            return
        # Off the registry first: the watchdog must not race this teardown.
        _forget_child(proc)
        # Close our end of the pipes BEFORE signalling: the child sees EOF on
        # stdin and can exit on its own, and the descriptors stop outliving
        # the handle. Popen closes neither for us — leaving that to the collector
        # leaked one reader and one writer per spawn (ResourceWarning at
        # interpreter exit; in a long-lived interface that respawns on every
        # failed handshake, an fd ceiling).
        _stop_child(proc)

    def close(self) -> None:
        """Public shutdown (context-manager compatible)."""
        self._teardown()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- framing ---------------------------------------------------------
    def _readline(self, timeout_s: float) -> bytes | None:
        """One response line with a wall-clock timeout, or None.

        The timeout bounds the WHOLE line, not just time-to-first-byte: a
        peer that writes a partial frame and then goes quiet would
        otherwise wedge the caller's single provider thread forever (a
        one-worker caller never re-fires; ``motoko status`` hangs
        instead of degrading after its documented timeout). Reads bypass
        the buffered reader via ``os.read`` so the wait stays interruptible;
        bytes over-read past the newline stay in ``self._read_buffer`` for
        the next call, so framing is preserved exactly.
        """
        proc = self._proc
        if proc is None or proc.stdout is None:
            return None
        deadline = time.monotonic() + timeout_s
        while True:
            newline_at = self._read_buffer.find(b"\n")
            if newline_at >= 0:
                line = self._read_buffer[:newline_at + 1]
                self._read_buffer = self._read_buffer[newline_at + 1:]
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                ready, _, _ = select.select([proc.stdout.fileno()], [], [],
                                            remaining)
                if not ready:
                    return None
                chunk = os.read(proc.stdout.fileno(), MAX_FRAME_BYTES)
            except (OSError, ValueError):
                return None
            if not chunk:
                return None  # EOF before the line completed
            self._read_buffer += chunk

    def _exchange(self, operation: str, engagement_id: str | None = None,
                  options: dict[str, Any] | None = None) -> dict | None:
        """Send one request frame, return the parsed response (or None)."""
        proc = self._proc
        if proc is None or proc.stdin is None or proc.poll() is not None:
            return None
        if operation not in READ_OPERATIONS:
            # Hard client-side guard: the mutating `run` op is never sent,
            # regardless of what capabilities advertise.
            return None
        request_id = self._next_request_id
        self._next_request_id += 1
        frame = json.dumps(
            {"protocol": PROTOCOL, "request_id": request_id,
             "operation": operation, "engagement_id": engagement_id,
             "options": options},
            ensure_ascii=True, allow_nan=False)
        if len(frame.encode()) > MAX_FRAME_BYTES:
            return None
        try:
            proc.stdin.write(frame.encode() + b"\n")
            proc.stdin.flush()
        except (OSError, ValueError):
            return None
        self._sent += 1
        raw = self._readline(self._request_timeout_s)
        if not raw:
            return None
        try:
            response = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(response, dict):
            return None
        if response.get("protocol") != PROTOCOL:
            return None
        if response.get("request_id") != request_id:
            return None
        return response

    def _request(self, operation: str, engagement_id: str | None = None,
                 options: dict[str, Any] | None = None) -> dict | None:
        """Request with budget accounting and transparent process restart."""
        if self._spawn_failed and self._proc is None:
            return None
        if self._proc is None and not self._spawn():
            return None
        if self._sent >= self.max_requests:
            # Engine budget exhausted for this process: restart, then retry.
            self._teardown()
            if not self._spawn():
                return None
        response = self._exchange(operation, engagement_id, options)
        if response is None:
            # Any protocol/transport failure degrades to unavailable; the
            # next call gets a fresh spawn attempt.
            self._teardown()
            self._spawn_failed = False  # binary may reappear / recover
            return None
        return response

    # -- read-only operations --------------------------------------------
    def capabilities(self) -> dict | None:
        """Engine capability announcement (handshake payload)."""
        response = self._request("capabilities")
        return response.get("result") if response and response.get("ok") else None

    def doctor(self) -> dict | None:
        """Doctor report: ``{"checks": [{"category", "counts"}], "failures"}``."""
        response = self._request("doctor")
        # A failed doctor is a report, not a failed transport.
        return response.get("result") if response else None

    def rules(self) -> dict | None:
        """Static rules report: totals, fireable, severity counts, by_code."""
        response = self._request("rules", options={"json": True})
        return response.get("result") if response and response.get("ok") else None

    def digest(self, engagement_id: str) -> dict | None:
        """Per-engagement kind/state counts + latest wave projection."""
        if not _valid_engagement_id(engagement_id):
            return None
        response = self._request("digest", engagement_id=engagement_id)
        return response.get("result") if response and response.get("ok") else None

    def health(self, engagement_id: str) -> dict | None:
        """Per-engagement graph-health issues (severity/kind only)."""
        if not _valid_engagement_id(engagement_id):
            return None
        response = self._request("health", engagement_id=engagement_id)
        return response.get("result") if response and response.get("ok") else None

    # -- deliberately NOT implemented -------------------------------------
    def run(self, *_args: object, **_kwargs: object) -> None:
        """The mutating ``run`` op is intentionally not implemented.

        The interface never drives the engine loop from the data layer; run
        capability is only surfaced via ``mutating_operations`` in the
        capabilities payload (the internal design notes: control flows through the
        UI's structured confirm paths, not the collector).
        """
        raise NotImplementedError("the interface never sends mutating ops")


def _valid_engagement_id(engagement_id: str) -> bool:
    """Mirror the engine's id shape check ([A-Za-z0-9][A-Za-z0-9_.-]{0,127})."""
    if not isinstance(engagement_id, str) or not engagement_id:
        return False
    if len(engagement_id) > 128 or not engagement_id[0].isalnum():
        return False
    return all(ch.isalnum() or ch in "_.-" for ch in engagement_id)
