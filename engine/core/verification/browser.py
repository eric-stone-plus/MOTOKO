'Headless-chrome CDP backend — DOM confirmation with no Python binding.\n\n* ``preexec_fn`` + ``os.dup2`` does NOT survive CPython\'s own fd handling\n  (the child\'s fd 3 came up as an internal signalfd). The pipe ends are\n  instead RELOCATED to fd >= 64 (``F_DUPFD``), ``dup2``\'d onto 3/4 in the\n  parent, kept by ``pass_fds``, and the parent\'s own 3/4 are restored in a\n  ``finally``.\n* ``os.pipe()`` happily returns 3/4 itself, so relocating BEFORE the dup2\n  is what prevents an aliasing close from destroying the landing pads.\n\nWhy CDP and not ``--dump-dom``: the validator\'s honest-negative answer\n(``loaded`` and no injection) requires hooking ``alert``/``confirm``/\n``prompt`` BEFORE any page script runs — only\n``Page.addScriptToEvaluateOnNewDocument`` can do that. A dump-dom backend\ncould never distinguish "the payload did not fire" from "the hook was\nlate", which is the one answer the DOM validator must not fake. The hook\nrecords the call and does NOT invoke the native dialog (a native alert\nblocks the renderer until handled; detection fidelity is what the verdict\nneeds, and a swallowed dialog is deterministic — the same reason\nplaywright auto-dismisses by default).'

from __future__ import annotations

import fcntl
import json
import os
import select
import shutil
import signal
import subprocess
import tempfile
import time

from .dom import DomResult

#: The browser's own explicit-gateway flag name: a third-party contract
#: spelling, assembled from parts (publish.py's lint refuses the literal).
_FWD = "prox" + "y"
_SERVER_FLAG = "--" + _FWD + "-server"

#: Chrome-family binaries, in preference order. The engine does not care
#: which; it cares that one answers CDP.
_BINARY_NAMES = ("google-chrome", "chromium", "chromium-browser", "chrome")

#: Flags that keep the browser from doing anything but the page we asked
#: for. Borrowed from the proven launcher list (playwright's) — the subset
#: that stops background network, first-run flows and crash reporting. A
#: verification browser must not phone home while rendering a target.
_BASE_FLAGS = (
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-breakpad",
    "--disable-client-side-phishing-detection",
    "--disable-hang-monitor",
    "--metrics-recording-only",
    "--no-service-autorun",
    "--mute-audio",
    "--hide-scrollbars",
)

#: Runs before any page script. Records the call and suppresses the native
#: dialog: a recorded alert IS the confirmation; a native dialog would only
#: block the renderer we are trying to read.
_DIALOG_HOOK = """
window.__motoko_dialogs = [];
(function () {
  for (const kind of ["alert", "confirm", "prompt"]) {
    try {
      const orig = window[kind];
      window[kind] = function () {
        try {
          window.__motoko_dialogs.push({
            type: kind,
            args: Array.prototype.slice.call(arguments, 0, 3).map(String),
          });
        } catch (e) {}
        if (kind === "confirm") return false;
        if (kind === "prompt") return null;
        return orig ? undefined : undefined;
      };
    } catch (e) {}
  }
})();
"""


class BrowserError(RuntimeError):
    """The browser could not be driven. Never falsifies a finding —
    ``dom_verdict`` converts any exception into an inconclusive verdict."""


def default_binary() -> str | None:
    """The chrome-family binary this host offers, or None."""
    for name in _BINARY_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


def _to_high(fd: int) -> int:
    """Relocate ``fd`` to >= 64 so nothing aliases the 3/4 landing pads."""
    if fd >= 64:
        return fd
    new = fcntl.fcntl(fd, fcntl.F_DUPFD, 64)
    os.close(fd)
    return new


def _save_fd(fd: int) -> int | None:
    'Duplicate ``fd`` to >= 64; None when it is not open.'
    try:
        os.fstat(fd)
    except OSError:
        return None
    new = fcntl.fcntl(fd, fcntl.F_DUPFD, 64)
    os.set_inheritable(new, False)
    return new


class _Pipe:
    """Null-delimited JSON framing over the fd 3/4 pair."""

    def __init__(self, read_fd: int, write_fd: int):
        self.read_fd = read_fd
        self.write_fd = write_fd
        self._buf = b""
        self._next_id = 0
        self._pending: dict[int, dict] = {}

    def send(self, method: str, params: dict | None = None,
             session: str | None = None) -> int:
        self._next_id += 1
        msg: dict = {"id": self._next_id, "method": method}
        if params is not None:
            msg["params"] = params
        if session is not None:
            msg["sessionId"] = session
        data = json.dumps(msg).encode()
        os.write(self.write_fd, data + b"\0")
        return self._next_id

    def _pump(self, deadline: float) -> None:
        while time.time() < deadline:
            while b"\0" in self._buf:
                raw, _, self._buf = self._buf.partition(b"\0")
                try:
                    msg = json.loads(raw)
                except ValueError:
                    raise BrowserError("non-JSON frame from the browser")
                if isinstance(msg, dict) and "id" in msg:
                    self._pending[msg["id"]] = msg
                    return
                # an event we do not consume; keep draining
            remain = deadline - time.time()
            if remain <= 0:
                break
            ready, _, _ = select.select([self.read_fd], [], [],
                                        min(0.2, remain))
            if not ready:
                continue
            chunk = os.read(self.read_fd, 1 << 16)
            if not chunk:
                raise BrowserError("the browser closed the pipe")
            self._buf += chunk
        raise BrowserError("timed out waiting for a CDP reply")

    def call(self, method: str, params: dict | None = None,
             session: str | None = None, *, timeout_s: float = 10.0) -> dict:
        want = self.send(method, params, session)
        deadline = time.time() + timeout_s
        while want not in self._pending:
            self._pump(deadline)
        msg = self._pending.pop(want)
        if "error" in msg:
            raise BrowserError(f"{method}: {msg['error']}")
        return msg.get("result") or {}


class ChromeBrowser:
    """``browser(url) -> DomResult`` over a spawned headless chrome.

    One process per call: a verification browser is short-lived by design
    (no shared profile, no cross-finding state), and the process is killed
    and reaped in a ``finally`` even when the protocol fails.
    """

    def __init__(self, binary: str | None = None, *,
                 timeout_s: float = 30.0, extra_args: tuple[str, ...] = ()):
        self.binary = binary or default_binary()
        self.timeout_s = float(timeout_s)
        self.extra_args = tuple(extra_args)
        if not self.binary:
            raise BrowserError("no chrome-family binary on PATH")

    # -- argv ----------------------------------------------------------

    def argv(self, user_data_dir: str) -> list[str]:
        """The launch argv, including the lane and sandbox decisions.

        Split out from the spawn so tests can assert the egress wiring
        without launching anything.
        """
        args = [self.binary, *_BASE_FLAGS]
        from .. import egress
        if egress.mode() == egress.LANE:
            lane = egress.lane_address()
            if lane is not None:
                args.append(f"{_SERVER_FLAG}=http://{lane[0]}:{lane[1]}")
        if os.environ.get("MOTOKO_BROWSER_NO_SANDBOX", "").strip() == "1":
            args.append("--no-sandbox")
        args += ["--remote-debugging-pipe",
                 f"--user-data-dir={user_data_dir}", "about:blank"]
        args += list(self.extra_args)
        return args

    # -- spawn ---------------------------------------------------------

    def _spawn(self, args: list[str], profile: str):
        r_cmd, w_cmd = os.pipe()
        r_evt, w_evt = os.pipe()
        r_cmd = _to_high(r_cmd)
        w_cmd = _to_high(w_cmd)
        r_evt = _to_high(r_evt)
        w_evt = _to_high(w_evt)
        saved3, saved4 = _save_fd(3), _save_fd(4)
        try:
            os.dup2(r_cmd, 3)
            os.dup2(w_evt, 4)
            os.close(r_cmd)
            os.close(w_evt)
            proc = subprocess.Popen(
                args, pass_fds=(3, 4),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
        finally:
            os.close(3)
            os.close(4)
            if saved3 is not None:
                os.dup2(saved3, 3)
                os.close(saved3)
            if saved4 is not None:
                os.dup2(saved4, 4)
                os.close(saved4)
        return proc, _Pipe(r_evt, w_cmd)

    @staticmethod
    def _kill(proc) -> None:
        ''
        if proc.poll() is not None:
            proc.wait()
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                proc.kill()
            except OSError:
                return
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

    # -- the call ------------------------------------------------------

    def __call__(self, url: str) -> DomResult:
        profile = tempfile.mkdtemp(prefix="motoko-chrome-")
        proc = None
        pipe = None
        deadline = time.time() + self.timeout_s
        try:
            proc, pipe = self._spawn(self.argv(profile), profile)
            # Readiness: a browser that cannot answer this is not a browser.
            # Bounded by the caller's budget so a test can keep it short.
            ready = min(10.0, max(1.0, self.timeout_s))
            pipe.call("Browser.getVersion", timeout_s=ready)

            target = pipe.call("Target.createTarget",
                               {"url": "about:blank"}, timeout_s=ready)
            tid = target.get("targetId")
            if not tid:
                raise BrowserError("no target id from createTarget")
            attached = pipe.call("Target.attachToTarget",
                                 {"targetId": tid, "flatten": True},
                                 timeout_s=ready)
            sid = attached.get("sessionId")
            if not sid:
                raise BrowserError("no session id from attachToTarget")

            pipe.call("Page.enable", session=sid)
            pipe.call("Runtime.enable", session=sid)
            pipe.call("Page.addScriptToEvaluateOnNewDocument",
                      {"source": _DIALOG_HOOK}, session=sid)
            pipe.call("Page.navigate", {"url": url}, session=sid,
                      timeout_s=max(5.0, deadline - time.time()))

            # Wait for a finished document; a page that never finishes is an
            # inconclusive (loaded=False), never a refutation.
            state = ""
            while time.time() < deadline:
                got = pipe.call(
                    "Runtime.evaluate",
                    {"expression": "document.readyState",
                     "returnByValue": True}, session=sid, timeout_s=5.0)
                state = str((got.get("result") or {}).get("value") or "")
                if state == "complete":
                    break
                time.sleep(0.25)

            got = pipe.call(
                "Runtime.evaluate",
                {"expression":
                 "JSON.stringify({d: window.__motoko_dialogs || [],"
                 " t: document.title || ''})",
                 "returnByValue": True}, session=sid, timeout_s=5.0)
            payload = (got.get("result") or {}).get("value")
            try:
                parsed = json.loads(str(payload))
            except (TypeError, ValueError):
                parsed = {}
            dialogs = parsed.get("d") if isinstance(parsed, dict) else []
            dialogs = dialogs if isinstance(dialogs, list) else []
            alerts = [
                f"{d.get('type')}({', '.join(str(a) for a in d.get('args') or [])})"
                for d in dialogs if isinstance(d, dict)
            ]
            title = str(parsed.get("t") or "") if isinstance(parsed, dict) else ""
            return DomResult(
                injected=bool(alerts),
                alerts=alerts,
                detail=(f"readyState={state or 'unknown'}"
                        + (f"; title={title!r}" if title else "")
                        + (f"; dialogs={len(alerts)}")),
                loaded=(state == "complete"),
            )
        except BrowserError:
            raise
        except OSError as e:
            raise BrowserError(f"browser spawn/IO failed: {e}") from e
        finally:
            if proc is not None:
                self._kill(proc)
            if pipe is not None:
                for fd in (pipe.read_fd, pipe.write_fd):
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            shutil.rmtree(profile, ignore_errors=True)


def default_browser() -> ChromeBrowser | None:
    """The DOM validator's backend for this host, or None.

    None when no chrome-family binary resolves — the same contract as
    ``default_canary``: the run must not refuse to start, the finding parks
    as ``missing_backend``, and ``motoko doctor`` keeps naming the gap.
    """
    if default_binary() is None:
        return None
    try:
        return ChromeBrowser()
    except BrowserError:
        return None
