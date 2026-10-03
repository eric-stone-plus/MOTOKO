'Real tool executor — subprocess argv execution with stdout/stderr capture.\n\nThis replaces the skeleton executor in the ACT beat. Contract:'

from __future__ import annotations

import os
import math
import random
import re
import secrets
import selectors
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path

from . import dns_channel, egress, egress_probe, util, secret_transport
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
    # Keep resolution independent of the service's inherited PATH.  Gateway
    # units intentionally start with a small environment, while Go/Cargo
    # installs are still valid owner-local tool roots.  ``tool_search_dirs``
    # also keeps the explicit MOTOKO_TOOLS roots in the precedence order that
    # older deployments relied on.
    return util.tool_search_dirs(_TOOLS if not os.environ.get("MOTOKO_TOOLS")
                                 else None)

_KILL_GRACE_S = 5

_DEFAULT_PROXY_TOOLS = egress.DEFAULT_PROXY_TOOLS
_PROXY_TOOLS_ENV = egress.PROXY_TOOLS_ENV
_EGRESS_MODE_ENV = egress.MODE_ENV
_proxy_tools = egress.proxy_tools
_inherits_proxy = egress.tool_inherits_proxy

# gau reads NO proxy env vars — only its --proxy flag (v2.2.4 binds none) —
# so the env keep below grants permission but moves nothing by itself. The
# URL the flag is pointed at comes from the child env, first present of
# these spellings, in this order.
_GAU_PROXY_ENV_KEYS = ("https_proxy", "HTTPS_PROXY", "http_proxy",
                       "HTTP_PROXY", "all_proxy", "ALL_PROXY")


def _gau_proxy_args(tool: str, argv: list[str], env: Mapping) -> list[str]:
    """A NEW argv with ``--proxy <url>`` appended for gau, or a copy of argv.

    The inherited proxy env alone does not move gau — the binary reads no
    proxy env, so without the flag it goes direct to the wayback/archive
    APIs and its DNS rides the ISP resolver. Appended only when ALL hold:
    ``tool`` is gau, gau may use the inherited proxy at all (the egress
    allowlist decides WHETHER; this flag is the mechanism), the child env —
    post-strip — actually carries a proxy URL to point at (never a
    hardcoded address), and argv has no ``--proxy`` / ``--proxy=*`` token
    yet (a rule that rendered its own never gets a second one). Pure: the
    input is never mutated and the result is always a fresh list.
    """
    out = list(argv)
    if tool != "gau" or not _inherits_proxy(tool) or not out:
        return out
    if "--proxy" in out or any(t.startswith("--proxy=") for t in out):
        return out
    url = ""
    for key in _GAU_PROXY_ENV_KEYS:
        value = env.get(key)
        if isinstance(value, str) and value.strip():
            url = value.strip()
            break
    if not url:
        return out
    return [*out, "--proxy", url]


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


# Pre-spawn timing jitter: an ACTIVE-class tool sleeps a bounded random
# interval before its process spawns, so two engagements running the same
# graph do not paint the same wall-clock activity template. Classification
# lives in exactly one place, here next to the draw:
#
# * ACTIVE_TOOLS are the loud scanners whose burst cadence IS the template
#   being broken.
# * PASSIVE_TOOLS are quiet collection sources — delaying them costs
#   latency without changing the template, so they draw zero.
# * A name outside both sets draws zero too: an unknown tool must never
#   inherit a delay by default.
ACTIVE_TOOLS = frozenset({
    "nuclei", "ffuf", "katana", "nmap", "gobuster", "feroxbuster",
    "dalfox", "arjun", "nikto", "wpscan", "sqlmap", "hydra", "amass",
})
PASSIVE_TOOLS = frozenset({
    "subfinder", "gau", "httpx", "uncover", "whatweb", "dnsx",
})

# Truncated normal draw: gauss ranges over the whole real line, so the
# clamp, not the parameters, defines the interval's support. The low
# profile is the per-action override for rules that know the target
# watches the clock; no rule emits that key yet.
_JITTER_MU_S = 8.0
_JITTER_SIGMA_S = 4.0
_JITTER_MIN_S = 2.0
_JITTER_MAX_S = 30.0
_JITTER_LOW_MU_S = 2.0
_JITTER_LOW_SIGMA_S = 1.0
_JITTER_LOW_MIN_S = 0.5
_JITTER_LOW_MAX_S = 8.0

# Seeded from secrets so the interval sequence is not reconstructible from
# the process start time or any default seed. Unpredictability is the
# claim; the gauss draw is not a cryptographic primitive.
_JITTER_RNG = random.Random(secrets.randbits(128))

# MOTOKO_TOOL_JITTER off vocabulary (case-insensitive, stripped): off/0/false
# plus every spelling that means ZERO — 0.0, 00, no. "Zero jitter" is how an
# operator asks for no delay, so reading it as ENABLED inverts the switch in
# the one direction the operator cannot see: the run pays the full clamp and
# the record shows only a slower cadence. Matching is exact, never numeric or
# prefix — "nope" and "0.5" stay enabled, and unset or blank means enabled.
# The mechanism must be switchable off without a code edit. The ready-queue
# shuffle's kill switch is a separate reader with its own vocabulary
# (core/orchestrator.py::_schedule_shuffle_enabled).
_JITTER_OFF_VALUES = frozenset({"off", "0", "false", "0.0", "00", "no"})


def _jitter_seconds(tool: str, action: Mapping) -> float:
    """Seconds to sleep before spawning ``tool``; 0.0 means spawn now.

    The draw happens only on a path that will return a positive interval,
    so passive, overridden-off and killed paths never consume randomness.
    """
    if os.environ.get("MOTOKO_TOOL_JITTER", "").strip().lower() in _JITTER_OFF_VALUES:
        return 0.0
    override = action.get("jitter")
    if override == "off":
        return 0.0
    if override == "low":
        mu, sigma, lo, hi = (_JITTER_LOW_MU_S, _JITTER_LOW_SIGMA_S,
                             _JITTER_LOW_MIN_S, _JITTER_LOW_MAX_S)
    elif override == "high" or tool in ACTIVE_TOOLS:
        mu, sigma, lo, hi = (_JITTER_MU_S, _JITTER_SIGMA_S,
                             _JITTER_MIN_S, _JITTER_MAX_S)
    else:
        # Passive, unlisted, or carrying an override string the table does
        # not define: the answer is no sleep.
        return 0.0
    return min(hi, max(lo, _JITTER_RNG.gauss(mu, sigma)))


def _sleep_jitter(tool: str, action: Mapping) -> None:
    """Sleep this action's pre-spawn jitter interval (a no-op at zero).

    Runs on the executor's never-raise path outside the spawn's error
    containment, so a jitter defect must degrade to an undelayed spawn
    rather than an exception into the loop.
    """
    try:
        delay = _jitter_seconds(tool, action)
        if delay > 0:
            time.sleep(delay)
    except Exception:      # noqa: BLE001 - jitter must never break a spawn
        pass


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
            # A direct-path tool must not leak the engagement's
            # target-domain query list to the ISP resolver — the engine
            # only appends the tool's own resolver flag, it never edits the
            # host resolver. Proxy-inheriting tools are excluded: their DNS
            # resolves at the egress, and pointing them at a local resolver
            # would bypass the very lane they ride.
            if not _inherits_proxy(tool):
                argv = dns_channel.inject_args(tool, argv)

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
        # A gateway/service may provide only a minimal PATH.  Keep the
        # process relocatable by deriving the same owner-local tool roots used
        # by resolve_tool(); this is an in-memory child setting, never a
        # profile mutation.
        env["PATH"] = util.effective_path(env.get("PATH", ""))
        stripped_host_secrets = egress.strip_host_secrets(env, strip_engine_secrets=True)
        if not _inherits_proxy(tool):
            egress.strip_host_proxy(env)
        dropped_env: list[str] = []
        for k, v in (env_action or {}).items():
            if not isinstance(k, str) or not k.startswith(ENV_PREFIX):
                dropped_env.append(str(k))
                continue
            env[k] = str(v)

        # Host path only: `podman exec` carries the client env solely via
        # explicit --env, and a persistent container's startup env is
        # authoritative — a client-side proxy URL could name a proxy the
        # container cannot see, so the container route gets no flag.
        if runtime != "container":
            argv = _gau_proxy_args(tool, argv, env)

        # Credentials need renderer-owned bindings and a tool-specific
        # transport. Never expand legacy markers directly into OS argv.
        bindings = action.get("secret_bindings") or {}
        proc = None
        reason = None
        started_at = time.monotonic()
        try:
            # Both preconditions are renderer defects, not spawn candidates:
            # they are checked BEFORE the jitter sleep so a refused action
            # never pays the delay, and their ValueError keeps the spawn
            # block's handling shape (126, "tool setup failed" on stderr).
            if not bindings and any(value.startswith("@env:") for value in argv):
                raise ValueError("credential reference has no renderer binding")
            if runtime == "container" and bindings:
                raise ValueError("container credential transport is not configured")
            # The jitter sleep sits after every rejection path above and
            # before the re-stamp, so duration_s stays the tool's own
            # runtime and only the path reaching Popen pays the delay.
            _sleep_jitter(tool, action)
            started_at = time.monotonic()
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
                # Stamp the exit identity on the registration transition.
                # The kwarg is passed only when a fingerprint is known —
                # legacy writer stubs pin the exact signature and must not
                # be asked for a parameter they lack.
                stamp = egress_probe.exit_ip()
                if stamp is not None:
                    set_pid(run_id, pid, exit_ip=stamp)
                else:
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
            # Carry the cached exit identity onto the closing transition,
            # but only when one is known — legacy writer stubs pin the exact
            # signature, and an unknown identity is recorded by its absence,
            # never by a placeholder value.
            stamp = egress_probe.exit_ip()
            if stamp is not None:
                self.writer.finish_tool_run(
                    run_id, status=status, exit_code=exit_code,
                    stdout_ref=str(out_path) if out_path and out_path.exists() else None,
                    stderr_ref=str(err_path) if err_path and err_path.exists() else None,
                    exit_ip=stamp)
            else:
                self.writer.finish_tool_run(
                    run_id, status=status, exit_code=exit_code,
                    stdout_ref=str(out_path) if out_path and out_path.exists() else None,
                    stderr_ref=str(err_path) if err_path and err_path.exists() else None)
        except Exception:
            pass


def util_stamp() -> str:
    import time as _t
    import uuid as _u
    return f"{int(_t.time() * 1000)}_{_u.uuid4().hex[:8]}"
