"""AdapterClient — defensive client for the engine's ``motoko/1`` stdio adapter.

The protocol is implemented strictly from the engine source
(``engine/core/adapter.py``, read-only): newline-delimited JSON frames, each
request ``{"protocol": "motoko/1", "request_id": <int>, "operation": str,
"engagement_id": str|null, "options": object|null}`` and each response
``{"protocol": "motoko/1", "request_id": int, "ok": bool, "exit_code": int,
"result"|"error": ...}``.

Safety envelope (design/DESIGN.md sections 1, 2 and 9):

- ONLY read operations are ever sent: capabilities, doctor, rules, digest,
  health (plus query/events, which this prototype does not need because the
  activity feed reads ro-SQLite directly). The mutating ``run`` operation is
  NEVER sent; it is only detected in the capabilities response so the UI can
  honestly report the engine's advertised capability set.
- The adapter subprocess uses this installation's Python and ``-m core``;
  if the binary is absent or the handshake fails, the client degrades to
  unavailable (every call returns ``None``) and panels render
  "adapter unavailable". Nothing raises into the UI.
- The engine serves at most 32 requests per process (``MAX_REQUESTS``); the
  client counts every sent request and transparently restarts the subprocess
  once the budget is exhausted.
- A child we spawned ourselves is stopped with ``terminate()``/``kill()`` by
  PID handle — never by process name.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Self

PROTOCOL = "motoko/1"
PROTOCOL_COMMAND = (sys.executable, "-m", "core", "adapter", "--stdio")
MAX_FRAME_BYTES = 64 * 1024  # engine-side limit, mirrored defensively
DEFAULT_REQUEST_BUDGET = 32  # engine MAX_REQUESTS; re-learned at handshake
REQUEST_TIMEOUT_S = 15.0

READ_OPERATIONS = frozenset(
    {"capabilities", "doctor", "rules", "digest", "query", "events", "health"})
MUTATING_OPERATIONS = frozenset({"run"})  # detected only, never sent


class AdapterClient:
    """Spawn-lazy, budget-aware JSONL client for the read-only adapter ops."""

    def __init__(self, *, command: list[str] | None = None,
                 runtime_root: Path | None = None,
                 request_timeout_s: float = REQUEST_TIMEOUT_S) -> None:
        self._command = command if command is not None else list(PROTOCOL_COMMAND)
        self._runtime_root = runtime_root
        self._request_timeout_s = request_timeout_s
        self._proc: subprocess.Popen[bytes] | None = None
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
        self._sent = 0
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
        if proc is None:
            return
        # Close our end of the pipes BEFORE signalling: the child sees EOF on
        # stdin and can exit on its own, and the descriptors stop outliving the
        # handle. Popen closes neither for us — leaving that to the collector
        # leaked one reader and one writer per spawn (ResourceWarning at
        # interpreter exit; in a long-lived interface that respawns on every
        # failed handshake, an fd ceiling).
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is None:
                continue
            try:
                stream.close()
            except OSError:
                pass
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass

    def close(self) -> None:
        """Public shutdown (context-manager compatible)."""
        self._teardown()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- framing ---------------------------------------------------------
    def _readline(self, timeout_s: float) -> bytes | None:
        """One response line with a wall-clock timeout, or None."""
        proc = self._proc
        if proc is None or proc.stdout is None:
            return None
        try:
            ready, _, _ = select.select([proc.stdout.fileno()], [], [], timeout_s)
            if not ready:
                return None
            return proc.stdout.readline()
        except (OSError, ValueError):
            return None

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
        return response.get("result") if response and response.get("ok") else None

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
        capabilities payload (design section 5.3: control flows through the
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
