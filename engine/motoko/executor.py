"""Real tool executor — subprocess argv execution with stdout/stderr capture.

This replaces the skeleton executor in the ACT beat. Contract:

* argv arrays only — no shell string is ever constructed (F09).
* secrets arrive via ``action["env"]`` (MOTOKO_SECRET_*) and never touch argv.
* stdout/stderr land as files under the engagement's ``obs/`` dir; the
  observation's ``raw_path`` points at stdout, so the next SYNC beat parses
  real output through the parser registry.
* timeouts: SIGTERM, grace window, then SIGKILL (the ``timeout -k 5``
  semantics) — a hung tool must not hang the run.
* any failure (binary missing, spawn error, timeout) is recorded as an
  observation with the exit code / error, never raised into the main loop.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path

from . import util
from .cmd import ENV_PREFIX

# Known tool locations on the deploy host. R5 M4: these are consulted
# BEFORE PATH (the deploy host pins its binaries here). Extend per host; the
# deploy image should symlink these into ~/.local/bin anyway.
#
# The two tree-relative entries are derived from the package location rather
# than hardcoded: the 2026-09-13 move to agent-design/projects/motoko/ left
# them pointing at a deleted network-audit/tools/, and resolve_tool() then
# quietly fell through to PATH — a wrong-binary or tool-not-found failure with
# no mention of the stale path. See util.motoko_root().
_TOOLS = util.motoko_root() / "tools"


def _known_tool_dirs() -> tuple[Path, ...]:
    """Deploy-host pin dirs, in precedence order.

    ``MOTOKO_TOOLS`` overrides where the toolbox lives (product deploys may
    keep it off the package tree); the default stays package-adjacent
    ``tools/``. ``~/.local/bin`` keeps its historical first-class slot: the
    deploy host pins wrappers (grok, strix) there.
    """
    env = os.environ.get("MOTOKO_TOOLS")
    tools_root = Path(env).expanduser() if env else _TOOLS
    return (
        Path.home() / ".local" / "bin",
        tools_root / "bin",
        tools_root / "nuclei",
    )

_KILL_GRACE_S = 5

# P-030: tools whose data sources live OUTSIDE the GFW (wayback/Common
# Crawl for gau) and therefore must run through the inherited proxy.
# Everything else runs DIRECT (proxy vars stripped) — see __call__.
# 2026-09-13 P1: the set is extensible via MOTOKO_EGRESS_PROXY_TOOLS
# (comma-separated tool names, merged with the default) so a deployment can
# name per-tool egress policy without a code change. Egress policy belongs
# in configuration, not in operator discipline (P-023/P-030's lesson).
_DEFAULT_PROXY_TOOLS = frozenset({"gau"})
_PROXY_TOOLS_ENV = "MOTOKO_EGRESS_PROXY_TOOLS"


def _proxy_tools() -> frozenset:
    extra = os.environ.get(_PROXY_TOOLS_ENV, "")
    if not extra.strip():
        return _DEFAULT_PROXY_TOOLS
    names = {n.strip() for n in extra.split(",") if n.strip()}
    return _DEFAULT_PROXY_TOOLS | names


def resolve_tool(tool: str, extra_dirs: tuple[Path, ...] = ()) -> str | None:
    """Absolute path to a tool binary, or None if it cannot be found.

    R5 M4: the known tool directories are consulted BEFORE PATH (the deploy
    host pins its binaries there), and a tool name that looks like a path
    (``/``, backslash, ``..``) is refused outright — the action's ``tool``
    field is a bare binary name, never a path.
    """
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
        # P-031 (2026-09-13): live in-flight processes, {pid: run_id}.
        # An engine that dies must not leave scans running on the wire —
        # the escaped amass kept hitting an authorized domain for 3 hours
        # after its engine was gone. Registration also lands in the
        # tool_run row (db.set_tool_run_pid) for post-mortems; reap() is
        # the shutdown path (orchestrator.run finally + close()).
        self._live: dict[int, str] = {}

    def __call__(self, hyp: dict, action: dict) -> None:
        """Run one rendered action and record its raw output (never raises)."""
        tool = action.get("tool", "")
        run_id = f"{util_stamp()}"
        out_path = self.artifacts / f"{run_id}.out"
        err_path = self.artifacts / f"{run_id}.err"
        url = action.get("url") or hyp.get("url")
        host = action.get("host") or hyp.get("host")
        # R5 H4: the address the guard cleared for THIS action. The tool
        # resolves DNS itself, so this is recorded evidence, not a pin.
        bind_ip = action.get("bind_ip")

        argv = action.get("argv")
        if not argv or not isinstance(argv, list) or not argv:
            self._record_observation(
                tool=tool, engagement_id=self.engagement_id,
                raw_path=None, parsed_summary=f"no argv to execute for {tool}",
                exit_code=-1, action_id=action.get("action_id"),
                url=url, host=host,
            )
            self._finish_tool_run(action, status="error", exit_code=-1)
            return

        # R5 M9: Popen rejects non-string argv elements; validate first and
        # record instead of letting a type error reach the spawn.
        if not all(isinstance(a, str) for a in argv):
            self._record_observation(
                tool=tool, engagement_id=self.engagement_id, raw_path=None,
                parsed_summary=(f"refusing to execute {tool}: argv contains "
                                f"non-string elements"),
                exit_code=-2, action_id=action.get("action_id"),
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

        exe = resolve_tool(tool, self.tool_dirs)
        if exe is None and argv:
            # R5 M4: a rule may still carry a legacy tool name while its cmd
            # uses the real binary (kiterunner vs kr) — fall back to the
            # basename of argv[0] before giving up.
            exe = shutil.which(os.path.basename(str(argv[0])))
        runtime = action.get("runtime") or "host"
        if runtime == "container":
            # Kali container route: the binary lives INSIDE the kali-recon
            # container (msf/responder/netexec/impacket/…). Execute as
            # `podman exec <container> timeout -k … <tool> <args>` — still an
            # argv array, still no shell. Host resolve_tool is skipped (the
            # tool does not exist on the host).
            container = action.get("container") or "kali-recon"
            # R7-8: container name whitelist — a name like "--privileged"
            # would be parsed as a podman exec option, not a container name.
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", container):
                self._record_observation(
                    tool=tool, engagement_id=self.engagement_id, raw_path=None,
                    parsed_summary=f"refusing container name: {container!r}",
                    exit_code=-2, action_id=action.get("action_id"),
                    url=url, host=host)
                self._finish_tool_run(action, status="error", exit_code=-2)
                return
            podman = resolve_tool("podman", self.tool_dirs) or shutil.which("podman")
            if podman is None:
                self._record_observation(
                    tool=tool, engagement_id=self.engagement_id, raw_path=None,
                    parsed_summary="podman not found for container action",
                    exit_code=127, action_id=action.get("action_id"),
                    url=url, host=host)
                self._finish_tool_run(action, status="error", exit_code=127)
                return
            # R7-8 (kimi H-3): wrap the in-container command with `timeout`
            # so killing the podman exec CLIENT (our TERM path) can never
            # orphan the scan inside the container — the container-side
            # timeout enforces the deadline independently.
            inner = int(effective_timeout) - 5
            # P-030-R (grok HIGH-1): podman exec carries the CLIENT env into
            # the container only via explicit -e; a persistent container
            # started under the host proxy keeps those vars at STARTUP.
            # Either way, an in-container tool hitting a domestic target
            # must not traverse the GFW proxy. Non-proxy-tools get the
            # -e blanking set (same discipline as AGENTS.md podman exec).
            env_clears: list[str] = []
            if tool not in _proxy_tools():
                for v in ("http_proxy", "https_proxy", "HTTP_PROXY",
                          "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
                    env_clears += ["--env", f"{v}="]
                env_clears += ["--env", "no_proxy=*", "--env", "NO_PROXY=*"]
            argv = [podman, "exec", *env_clears, container,
                    "timeout", "-k", "5",
                    str(max(30, inner)), *argv]
        elif exe is None:
            self._record_observation(
                tool=tool, engagement_id=self.engagement_id,
                raw_path=None, parsed_summary=f"tool binary not found: {tool}",
                exit_code=127, action_id=action.get("action_id"),
                url=url, host=host,
            )
            self._finish_tool_run(action, status="error", exit_code=127)
            return
        else:
            argv = [exe, *argv[1:]] if argv else [exe]

        # R5 M3: the action's env must be a mapping, and only MOTOKO_SECRET_*
        # keys may reach the child. Anything else is dropped and recorded —
        # never a silent passthrough into the tool's environment.
        env_action = action.get("env")
        if env_action is not None and not isinstance(env_action, Mapping):
            self._record_observation(
                tool=tool, engagement_id=self.engagement_id, raw_path=None,
                parsed_summary=(f"refusing to execute {tool}: env is not a "
                                f"mapping ({type(env_action).__name__})"),
                exit_code=-2, action_id=action.get("action_id"),
                url=url, host=host,
            )
            self._finish_tool_run(action, status="error", exit_code=-2)
            return
        env = dict(os.environ)
        # P-030 (production forensics / P-023 made code): per-tool proxy
        # policy. The host sits behind a GFW-evasion proxy: domestic targets
        # (subfinder/amass/httpx/nuclei/nmap/katana/…) must go DIRECT while
        # wayback-consuming gau must go THROUGH it. Until now this was pure
        # operator discipline on the launch env — one wrong `env -u` and
        # either gau returns 0 bytes 30 times or every domestic tool dies.
        # Default is DIRECT (proxy vars stripped); tools in _proxy_tools()
        # keep the inherited proxy vars so gau can reach wayback.
        if tool not in _proxy_tools():
            for k in list(env):
                if k.lower() in ("http_proxy", "https_proxy", "all_proxy"):
                    del env[k]
        dropped_env: list[str] = []
        for k, v in (env_action or {}).items():
            if not isinstance(k, str) or not k.startswith(ENV_PREFIX):
                dropped_env.append(str(k))
                continue
            env[k] = str(v)

        try:
            with open(out_path, "wb") as out_f, open(err_path, "wb") as err_f:
                # P-026: start_new_session puts the tool in its own process
                # group so a hung multiprocess tool (amass spawns children
                # that inherit the stdout pipe) can be killed as a GROUP —
                # a bare terminate() left amass running 56 minutes while
                # communicate() waited on the inherited pipe.
                proc = subprocess.Popen(
                    argv, stdout=out_f, stderr=err_f, env=env,
                    stdin=subprocess.DEVNULL, start_new_session=True,
                )
                self._register(str(action.get("_tool_run_id") or run_id),
                               proc.pid)
                try:
                    _, _ = proc.communicate(timeout=effective_timeout)
                except subprocess.TimeoutExpired:
                    # timeout -k semantics: TERM group, grace, KILL group
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        proc.terminate()
                    try:
                        proc.wait(timeout=self.kill_grace)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            proc.kill()
                        proc.wait()
                    # close the inherited pipes from our side so no grandchild
                    # can hold communicate() open after the group is gone
                    for _f in (out_f, err_f):
                        pass
            exit_code = proc.returncode
            status = "timeout" if exit_code in (-15, -9) or exit_code == 124 else \
                ("done" if exit_code == 0 else "error")
            self._unregister(proc.pid)
        except (OSError, TypeError, ValueError) as e:
            exit_code, status = 126, "error"
            # R5 H2: the error path itself can fail (obs dir gone/unwritable);
            # that must never re-throw into the caller's main loop.
            # R5 M9: TypeError/ValueError from the spawn are contained too.
            try:
                err_path.write_text(f"spawn failed: {e}", encoding="utf-8")
            except OSError:
                pass

        summary = f"{tool} exit {exit_code} ({status})"
        if bind_ip:
            summary += f" bind_ip={bind_ip}"
        if dropped_env:
            summary += f" dropped_env_keys={','.join(dropped_env)}"
        self._record_observation(
            tool=tool, engagement_id=self.engagement_id,
            raw_path=str(out_path) if out_path.exists() else None,
            parsed_summary=summary,
            exit_code=exit_code, action_id=action.get("action_id"),
            url=url, host=host,
        )
        # R5 M6: success, failure and timeout all close the tool_run row.
        self._finish_tool_run(action, status=status, exit_code=exit_code,
                              out_path=out_path, err_path=err_path)

    def _register(self, run_id: str, pid: int) -> None:
        """P-031: track a live scan (tool_run row + in-memory registry).

        ``run_id`` here is the tool_run ROW id (``action['_tool_run_id']``) —
        the internal observation stamp is a different namespace. Legacy tests
        construct executors without ``__init__``, so the registry lazily
        initializes.
        """
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
        """Kill every in-flight run this executor spawned. Never raises.

        TERM each process group first, wait up to ``grace`` seconds for
        /proc liveness to clear, then KILL the group AND the direct pid —
        a setsid-escaping child (the P-031 amass) re-parents into a new
        session and is invisible to killpg, so the direct pid is the only
        handle left. Grandchildren of such an escapee are out of reach in
        v1; the container route is the structural fix (kill the cgroup).

        The registry is snapshotted FIRST: a child that dies during the
        grace window lets its own executor thread unregister it, which
        would otherwise make reap return nothing while scans still ran.
        Returns the reaped pids.
        """
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
        """R5 H2: a database error while recording must not kill the loop."""
        try:
            self.writer.record_observation(**kw)
        except Exception:
            pass

    def _finish_tool_run(self, action: dict, *, status: str,
                         exit_code: int | None, out_path: Path | None = None,
                         err_path: Path | None = None) -> None:
        """R5 M6: close the tool_run row this action started (never raises).

        P-030-R (grok adjudication): this method ONLY closes the tool_run
        row. The first P-030 pass retired the hypothesis here from a
        single run's status — for a 2-action hypothesis (subfinder+amass)
        the first run's 'done' sealed the (rule, asset) pair before the
        second action ever ran. Hypothesis retirement is now aggregated
        in Orchestrator._retire_hypothesis_if_complete after the whole
        action loop.
        """
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
