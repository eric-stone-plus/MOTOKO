'Real tool executor — subprocess argv execution with stdout/stderr capture.\n\nThis replaces the skeleton executor in the ACT beat. Contract:'

from __future__ import annotations

import os
import math
import re
import selectors
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path

from . import egress, util, secret_transport
from .cmd import ENV_PREFIX
from .parsers import Parser, get_parser

_TOOLS = util.motoko_root() / "tools"


_BROKEN_EXEC_RE = re.compile(
    r"(No such file or directory|bad interpreter|not found)", re.IGNORECASE)


def _wrapper_death(exit_code: int, err_path: Path) -> str | None:
    'Why the tool died before it could exec, or None if it really ran.'
    if exit_code not in (126, 127):
        return None
    try:
        head = err_path.read_text(errors="ignore")[:600]
    except OSError:
        return None
    for line in head.splitlines():
        if _BROKEN_EXEC_RE.search(line):
            return f"wrapper died before exec: {line.strip()[:200]}"
    return None


def _known_tool_dirs() -> tuple[Path, ...]:
    'Deploy-host pin dirs, in precedence order.'
    env = os.environ.get("MOTOKO_TOOLS")
    tools_root = Path(env).expanduser() if env else _TOOLS
    return (
        Path.home() / ".local" / "bin",
        tools_root / "bin",
        tools_root / "nuclei",
    )

_KILL_GRACE_S = 5

_DEFAULT_PROXY_TOOLS = egress.DEFAULT_PROXY_TOOLS
_PROXY_TOOLS_ENV = egress.PROXY_TOOLS_ENV
_EGRESS_MODE_ENV = egress.MODE_ENV
_proxy_tools = egress.proxy_tools
_inherits_proxy = egress.tool_inherits_proxy


def resolve_tool(tool: str, extra_dirs: tuple[Path, ...] = ()) -> str | None:
    'Absolute path to a tool binary, or None if it cannot be found.'
    if not isinstance(tool, str) or not tool:
        return None
    if "/" in tool or "\\" in tool or ".." in tool:
        return None
    for d in (*extra_dirs, *_known_tool_dirs()):
        p = Path(d) / tool
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    found = shutil.which(tool)
    return found or None


# Bound on the artifact a parser's success contract may read. A contract is an
# output-shape assertion ("the four generated tokens are all here"), not a
# reason to load a 16 MiB capture into memory twice; truncation fails CLOSED,
# because a half-read contract cannot prove the run finished.
_SUCCESS_CONTRACT_BYTES = 1 << 20


def _obs_opener(path, flags: int) -> int:
    'Create obs capture files owner-only (0600).'
    return os.open(path, flags, 0o600)


class SubprocessExecutor:
    """Executes rendered actions as real tool processes."""

    def __init__(self, writer, engagement_id: str, artifacts_dir: Path, *,
                 tool_timeout: float = 300, kill_grace: float = _KILL_GRACE_S,
                 tool_dirs: tuple[Path, ...] = ()):
        self.writer = writer
        self.engagement_id = engagement_id
        self.artifacts = Path(artifacts_dir)
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.tool_timeout = tool_timeout
        self.kill_grace = kill_grace
        self.tool_dirs = tool_dirs
        self.max_output_bytes = 16 * 1024 * 1024
        self._live: dict[int, str] = {}
        # Tools this host cannot run at all (resolved but unexec'able, or not
        # found). The orchestrator's mint door reads this set so the rest of
        # the engagement stops proposing them: one wasted ACT slot per tool per
        # process instead of three strikes per (rule, asset) pair.
        self.broken_tools: set[str] = set()

    def __call__(self, hyp: dict, action: dict) -> None:
        """Run one rendered action and record its raw output (never raises)."""
        tool = action.get("tool", "")
        run_id = f"{util_stamp()}"
        out_path = self.artifacts / f"{run_id}.out"
        err_path = self.artifacts / f"{run_id}.err"
        url = action.get("url") or hyp.get("url")
        host = action.get("host") or hyp.get("host")
        bind_ip = action.get("bind_ip")

        argv = action.get("argv")
        if not argv or not isinstance(argv, list) or not argv:
            self._record_observation(
                tool=tool, engagement_id=self.engagement_id,
                raw_path=None, parsed_summary=f"no argv to execute for {tool}",
                exit_code=-1, action_id=action.get("_tool_run_id"),
                url=url, host=host,
            )
            self._finish_tool_run(action, status="error", exit_code=-1)
            return

        if not all(isinstance(a, str) for a in argv):
            self._record_observation(
                tool=tool, engagement_id=self.engagement_id, raw_path=None,
                parsed_summary=(f"refusing to execute {tool}: argv contains "
                                f"non-string elements"),
                exit_code=-2, action_id=action.get("_tool_run_id"),
                url=url, host=host,
            )
            self._finish_tool_run(action, status="error", exit_code=-2)
            return

        # strix deep-dive rule sets action["timeout"] (1800s) — long-running
        # agent sessions outlive the default tool timeout.
        effective_timeout = self.tool_timeout
        action_timeout = action.get("timeout")
        if isinstance(action_timeout, (int, float)) and action_timeout > 0:
            effective_timeout = float(action_timeout)
        if (isinstance(effective_timeout, bool) or not isinstance(effective_timeout, (int, float))
                or not math.isfinite(effective_timeout) or effective_timeout <= 0):
            self._record_observation(tool=tool, engagement_id=self.engagement_id,
                raw_path=None, parsed_summary="invalid tool timeout", exit_code=-2,
                action_id=action.get("_tool_run_id"), url=url, host=host)
            self._finish_tool_run(action, status="error", exit_code=-2)
            return

        exe = resolve_tool(tool, self.tool_dirs)
        runtime = action.get("runtime") or "host"
        if runtime == "container":
            # Kali container route: the binary lives INSIDE the kali-recon
            # container (msf/responder/netexec/impacket/…). Execute as
            # `podman exec <container> timeout -k … <tool> <args>` — still an
            # argv array, still no shell. Host resolve_tool is skipped (the
            # tool does not exist on the host).
            container = action.get("container") or util.KALI_CONTAINER
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", container):
                self._record_observation(
                    tool=tool, engagement_id=self.engagement_id, raw_path=None,
                    parsed_summary=f"refusing container name: {container!r}",
                    exit_code=-2, action_id=action.get("_tool_run_id"),
                    url=url, host=host)
                self._finish_tool_run(action, status="error", exit_code=-2)
                return
            podman = resolve_tool("podman", self.tool_dirs) or shutil.which("podman")
            if podman is None:
                self._record_observation(
                    tool=tool, engagement_id=self.engagement_id, raw_path=None,
                    parsed_summary="podman not found for container action",
                    exit_code=127, action_id=action.get("_tool_run_id"),
                    url=url, host=host)
                self._finish_tool_run(action, status="error", exit_code=127)
                return
            try:
                exists = subprocess.run(
                    [podman, "container", "exists", container],
                    capture_output=True, text=True, timeout=30)
                missing = exists.returncode != 0
            except Exception:      # noqa: BLE001 - probe must not break exec
                missing = False
            if missing:
                self._record_observation(
                    tool=tool, engagement_id=self.engagement_id, raw_path=None,
                    parsed_summary=f"container {container!r} not running "
                                   "for container action",
                    exit_code=127, action_id=action.get("_tool_run_id"),
                    url=url, host=host)
                self._finish_tool_run(action, status="error", exit_code=127)
                return
            env_clears = egress.container_env_clears(tool)
            argv = [podman, "exec", *env_clears, container,
                    "timeout", "-k", "5",
                    str(max(0.1, effective_timeout - min(5, effective_timeout / 2))), *argv]
        elif exe is None:
            self._record_observation(
                tool=tool, engagement_id=self.engagement_id,
                raw_path=None, parsed_summary=f"tool binary not found: {tool}",
                exit_code=127, action_id=action.get("_tool_run_id"),
                url=url, host=host,
            )
            self._mark_broken(tool, f"tool binary not found: {tool}")
            self._finish_tool_run(action, status="error", exit_code=127)
            return
        else:
            argv = [exe, *argv[1:]] if argv else [exe]

        env_action = action.get("env")
        if env_action is not None and not isinstance(env_action, Mapping):
            self._record_observation(
                tool=tool, engagement_id=self.engagement_id, raw_path=None,
                parsed_summary=(f"refusing to execute {tool}: env is not a "
                                f"mapping ({type(env_action).__name__})"),
                exit_code=-2, action_id=action.get("_tool_run_id"),
                url=url, host=host,
            )
            self._finish_tool_run(action, status="error", exit_code=-2)
            return
        env = dict(os.environ)
        stripped_host_secrets = egress.strip_host_secrets(env, strip_engine_secrets=True)
        if not _inherits_proxy(tool):
            egress.strip_host_proxy(env)
        dropped_env: list[str] = []
        for k, v in (env_action or {}).items():
            if not isinstance(k, str) or not k.startswith(ENV_PREFIX):
                dropped_env.append(str(k))
                continue
            env[k] = str(v)

        # Credentials need renderer-owned bindings and a tool-specific
        # transport. Never expand legacy markers directly into OS argv.
        bindings = action.get("secret_bindings") or {}
        proc = None
        started_at = time.monotonic()
        reason = None
        try:
            if not bindings and any(value.startswith("@env:") for value in argv):
                raise ValueError("credential reference has no renderer binding")
            if runtime == "container" and bindings:
                raise ValueError("container credential transport is not configured")
            with open(out_path, "wb", opener=_obs_opener) as out_f, \
                    open(err_path, "wb", opener=_obs_opener) as err_f, \
                    secret_transport.prepare(tool, argv, env, bindings,
                        tools_root=Path(os.environ.get("MOTOKO_TOOLS") or _TOOLS)) as (private_argv, fds):
                proc = subprocess.Popen(
                    private_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                    pass_fds=fds,
                    stdin=subprocess.DEVNULL, start_new_session=True,
                )
                self._register(str(action.get("_tool_run_id") or run_id),
                               proc.pid)
                reason = self._capture(proc, out_f, err_f, effective_timeout)
            exit_code = proc.returncode
            status = "timeout" if reason == "timeout" or exit_code == 124 else \
                ("done" if self._run_succeeded(tool, exit_code, action,
                                               out_path, err_path) else "error")
            if reason == "output_limit":
                status, exit_code = "error", 125
        except (OSError, TypeError, ValueError) as e:
            exit_code, status = 126, "error"
            try:
                with open(err_path, "wb", opener=_obs_opener) as err_f:
                    err_f.write(f"tool setup failed: {type(e).__name__}".encode())
            except OSError:
                pass
        except BaseException as stopped:
            # Cancellation must close the durable run before unwinding. The
            # finally block removes its process from the live registry, so a
            # later reap cannot repair an otherwise stranded running row.
            code = 124 if getattr(stopped, "code", None) == 124 else 130
            self._record_observation(tool=tool, engagement_id=self.engagement_id,
                raw_path=str(out_path) if out_path.exists() else None,
                parsed_summary="tool interrupted", exit_code=code,
                duration_s=round(time.monotonic() - started_at, 3),
                action_id=action.get("_tool_run_id"), url=url, host=host)
            self._finish_tool_run(action, status="timeout" if code == 124 else "error",
                                  exit_code=code, out_path=out_path, err_path=err_path)
            raise
        finally:
            if proc is not None:
                # The leader may exit while a descendant keeps scanning.
                # The saved process group belongs to this invocation only.
                self._stop_group(proc)
                self._unregister(proc.pid)

        summary = f"{tool} exit {exit_code} ({status})"
        if status == "done" and exit_code != 0:
            # An exit code the parser's output contract overruled is the one
            # thing a post-mortem cannot reconstruct from the row alone.
            summary += " via parser output contract"
        if reason:
            summary += f" reason={reason}"
        broken = _wrapper_death(exit_code, err_path)
        if broken:
            # Deployment, not target and not rule: say so on the observation
            # that reports and post-mortems read, and stop proposing the tool.
            summary += f" — {broken}"
            self._mark_broken(tool, broken)
        if bind_ip:
            summary += f" bind_ip={bind_ip}"
        if dropped_env:
            summary += f" dropped_env_keys={','.join(dropped_env)}"
        if stripped_host_secrets:
            # Count, not names: the summary lands in the db and reports, and
            # the stripped set is host configuration, not observation data.
            summary += f" host_secret_vars_stripped={len(stripped_host_secrets)}"
        self._record_observation(
            tool=tool, engagement_id=self.engagement_id,
            raw_path=str(out_path) if out_path.exists() else None,
            parsed_summary=summary,
            exit_code=exit_code,
            duration_s=round(time.monotonic() - started_at, 3),
            action_id=action.get("_tool_run_id"),
            url=url, host=host,
        )
        self._finish_tool_run(action, status=status, exit_code=exit_code,
                              out_path=out_path, err_path=err_path)

    def _run_succeeded(self, tool: str, exit_code: int, action: dict,
                       out_path: Path, err_path: Path) -> bool:
        """Is a non-zero exit nonetheless a finished, successful run?

        For most tools ``exit 0`` is the whole answer, and this returns it
        without touching the artifacts. A parser that OVERRIDES the contract
        is the only thing that can relax it: jwt_tool's offline generation
        modes exit 1 after writing valid tokens, and a run recorded as
        ``error`` is not ``done``, so the dependency bridge withholds every
        value the run produced and the chain behind it never arms — the exit
        code alone made a working generation indistinguishable from a crash.

        Only the parser that declared the contract may accept it, only for the
        exact invocation it recognizes (``action`` carries the rendered
        command), and only when the tool's own output proves it. Failures stay
        failures: a missing artifact, an unreadable one, or a parser raising
        all fall back to the exit code, since withholding a success is
        recoverable on the next run and claiming one is not.
        """
        if exit_code == 0:
            return True
        parser = get_parser(tool)
        if parser is None or \
                type(parser).execution_succeeded is Parser.execution_succeeded:
            return False
        try:
            stdout = out_path.read_text(errors="replace")[:_SUCCESS_CONTRACT_BYTES]
            stderr = err_path.read_text(errors="replace")[:_SUCCESS_CONTRACT_BYTES]
        except OSError:
            return False
        try:
            return bool(parser.execution_succeeded(exit_code, stdout, stderr, action))
        except Exception:
            return False

    def _stop_group(self, proc) -> None:
        if proc.pid <= 0:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            proc.wait()
            return
        except PermissionError:
            return
        try:
            proc.wait(timeout=max(0.01, self.kill_grace))
        except subprocess.TimeoutExpired:
            pass
        # Always finish the group, even if its leader handled TERM and exited.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()

    def _capture(self, proc, out_f, err_f, timeout: float) -> str | None:
        """Drain bounded pipes without holding arbitrary tool output in RAM."""
        deadline = time.monotonic() + timeout
        limit = getattr(self, "max_output_bytes", 16 * 1024 * 1024)
        sizes = {out_f: 0, err_f: 0}
        # Lightweight mocked processes used by the container argv contract do
        # not expose PIPEs. Preserve that seam while real processes always use
        # bounded nonblocking drains below.
        if not hasattr(proc, "stdout") or not hasattr(proc, "stderr"):
            proc.communicate(timeout=timeout)
            return None
        with selectors.DefaultSelector() as sel:
            for stream, destination in ((proc.stdout, out_f), (proc.stderr, err_f)):
                os.set_blocking(stream.fileno(), False)
                sel.register(stream, selectors.EVENT_READ, destination)
            try:
                while sel.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return "timeout"
                    if proc.poll() is not None:
                        # A descendant can hold pipes open after leader exit.
                        self._stop_group(proc)
                    for key, _ in sel.select(min(0.05, remaining)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            sel.unregister(key.fileobj)
                            continue
                        dest = key.data
                        room = max(0, limit - sizes[dest])
                        dest.write(chunk[:room])
                        sizes[dest] += min(room, len(chunk))
                        if len(chunk) > room:
                            return "output_limit"
                try:
                    proc.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    return "timeout"
            finally:
                if proc.poll() is None:
                    self._stop_group(proc)
                proc.stdout.close()
                proc.stderr.close()
        return None

    def _mark_broken(self, tool: str, reason: str) -> None:
        """Record a tool this host cannot run. Never raises.

        Lazy-initialized because legacy tests construct executors without
        ``__init__`` (the same reason ``_register`` guards ``_live``).
        """
        if getattr(self, "broken_tools", None) is None:
            self.broken_tools = set()
        self.broken_tools.add(tool)
        append = getattr(self.writer, "append_event", None)
        if callable(append):
            try:
                append("tool_run.broken_wrapper", None,
                       {"tool": tool, "reason": reason,
                        "engagement_id": self.engagement_id})
            except Exception:      # noqa: BLE001 - diagnostics never break exec
                pass

    def _register(self, run_id: str, pid: int) -> None:
        "        ``run_id`` here is the tool_run ROW id (``action['_tool_run_id']``) —\n        the internal observation stamp is a different namespace. Legacy tests\n        construct executors without ``__init__``, so the registry lazily\n        initializes.\n        "
        if pid <= 0:
            return
        if getattr(self, "_live", None) is None:
            self._live = {}
        self._live[pid] = run_id
        try:
            set_pid = getattr(self.writer, "set_tool_run_pid", None)
            if callable(set_pid):
                set_pid(run_id, pid)
        except Exception:
            pass

    def _unregister(self, pid: int) -> None:
        if getattr(self, "_live", None) is not None:
            self._live.pop(pid, None)

    def reap(self, *, grace: float = 2.0) -> list[int]:
        'Kill every in-flight run this executor spawned. Never raises.\n\n        The registry is snapshotted FIRST: a child that dies during the\n        grace window lets its own executor thread unregister it, which\n        would otherwise make reap return nothing while scans still ran.\n        Returns the reaped pids.\n        '
        targets: dict[int, str] = dict(getattr(self, "_live", {}) or {})
        for pid in targets:
            try:
                os.killpg(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        deadline = time.monotonic() + max(0.0, grace)
        while time.monotonic() < deadline and any(
                Path(f"/proc/{pid}").exists() for pid in targets):
            time.sleep(0.1)
        reaped: list[int] = []
        for pid in targets:
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            self._unregister(pid)
            reaped.append(pid)
        return reaped

    def _record_observation(self, **kw) -> None:
        ''
        try:
            self.writer.record_observation(**kw)
        except Exception:
            pass

    def _finish_tool_run(self, action: dict, *, status: str,
                         exit_code: int | None, out_path: Path | None = None,
                         err_path: Path | None = None) -> None:
        ''
        run_id = action.get("_tool_run_id")
        if not run_id:
            return
        try:
            self.writer.finish_tool_run(
                run_id, status=status, exit_code=exit_code,
                stdout_ref=str(out_path) if out_path and out_path.exists() else None,
                stderr_ref=str(err_path) if err_path and err_path.exists() else None,
            )
        except Exception:
            pass


def util_stamp() -> str:
    import time as _t
    import uuid as _u
    return f"{int(_t.time() * 1000)}_{_u.uuid4().hex[:8]}"
