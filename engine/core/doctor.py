"""motoko doctor — read-only environment self-check for the runtime.

A reproducible runtime needs a way to answer "would the engine work on
this host, and if not, what is missing?" without running anything.
doctor() walks the dependency surface (python, engagement root, disk
headroom, tmp litter, toolbox, loop config, linter, key envs, wordlists,
podman) and reports one line per check. Contract:

* never prints secret VALUES — set/unset only;
* never writes anything (no config creation, no dir mkdir);
* exit 0 when nothing FAILs; WARN is informational (an operator may run
  the loop over CLI legs with no HTTP keys at all, so missing keys are
  not a failure — the loop config decides what is required);
* exit 1 on any FAIL (broken config, unwritable root).
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

from . import (cmd, db, deploy_config, dns_channel, egress, egress_probe,
               executor, util)

OK, WARN, FAIL = "OK", "WARN", "FAIL"

_DISK_FREE_MIN = 0.10
_TMP_LITTER_MAX = 1000


def _check_python() -> tuple[str, str]:
    v = sys.version_info
    if v >= (3, 11):
        return OK, f"python {v.major}.{v.minor}.{v.micro}"
    return FAIL, f"python {v.major}.{v.minor} too old (need >= 3.11)"


def _check_root() -> tuple[str, str]:
    root = db.default_root()
    if not root.exists():
        return WARN, f"engagements root missing (created on init): {root}"
    if not os.access(root, os.W_OK):
        return FAIL, f"engagements root not writable: {root}"
    return OK, f"engagements root: {root}"


def _check_disk() -> list[tuple[str, str]]:
    ''
    out: list[tuple[str, str]] = []
    paths = [Path(tempfile.gettempdir())]
    root = db.default_root()
    if root.exists():
        paths.append(root)
    for p in paths:
        try:
            usage = shutil.disk_usage(p)
        except OSError as e:
            out.append((WARN, f"disk {p}: cannot stat ({e})"))
            continue
        ratio = usage.free / usage.total if usage.total else 0.0
        msg = f"disk {p}: {usage.free / 2**30:.1f} GiB free ({ratio:.0%})"
        if ratio < _DISK_FREE_MIN:
            out.append((WARN, msg + f" — under {_DISK_FREE_MIN:.0%} free: "
                                    "ENOSPC kills every process on the "
                                    "host (by design)"))
        else:
            out.append((OK, msg))
    return out


def _check_tmp_litter() -> tuple[str, str]:
    ''
    tmp = Path(tempfile.gettempdir())
    try:
        n = sum(1 for p in tmp.glob("motoko-*") if p.is_dir())
    except OSError as e:
        return WARN, f"cannot census {tmp}/motoko-*: {e}"
    if n > _TMP_LITTER_MAX:
        return WARN, (f"tmp litter: {n} motoko-* dirs in {tmp} "
                      f"(> {_TMP_LITTER_MAX}) — sweep stale ones (by design)")
    return OK, f"tmp litter: {n} motoko-* dirs in {tmp}"


# Absolute paths a wrapper pins: its shebang interpreter, and anything on an
# `exec` / `"$@"` line. `#!/usr/bin/env X` names a program, not a path, so it is
# resolved through PATH instead of being checked as a literal.
# An absolute path only STARTS where a token can start: line start, whitespace,
# a quote, `=`, `(`, `,` or `;`. Matching any `/` instead — the shape this
# shipped with — reported three false-positive classes on the first live run of
# `provision.sh verify-wrappers`: `$HOME/.local/...` (matched the `/` after
# HOME), `${DIR}/run_shadow.py` (after the brace) and `scheme://host:port`
# (after the colon). A variable-relative target cannot be verified statically,
# and "cannot verify" must not read as "broken": a gate that cries wolf on
# working wrappers gets ignored, including the day it is right.
_ABS_PATH_RE = re.compile(r"""(?:^|[\s"'=(,;`])(/[^\s'"`]+)""")


def _wrapper_defect(path: Path) -> str | None:
    'Why a RESOLVED tool still cannot exec, or None when it looks runnable.'
    try:
        head = path.read_bytes()[:4096]
    except OSError:
        return None
    if head.startswith(b"\x7fELF") or b"\x00" in head:
        return None                       # a real binary, not a script
    lines = head.decode("utf-8", "ignore").splitlines()[:12]
    probe: list[str] = []
    if lines and lines[0].startswith("#!"):
        parts = lines[0][2:].strip().split()
        if parts and parts[0].endswith("/env"):
            if len(parts) > 1:
                probe.append(shutil.which(parts[1]) or "")
        elif parts:
            probe.append(parts[0])
    for line in lines[1:]:
        if "exec " in line or '"$@"' in line:
            probe.extend(_ABS_PATH_RE.findall(line))
    missing = [q for q in probe if q.startswith("/") and not Path(q).exists()]
    if not missing:
        return None
    extra = f" (+{len(missing) - 1} more)" if len(missing) > 1 else ""
    return f"cannot exec — missing {missing[0]}{extra}"


def _corpus_tools(rules_dir: Path) -> dict[str, set[str]]:
    """Tool name -> the rule ids that drive it ({} if the corpus is unreadable).

    Doctor asks the corpus rather than a hardcoded list: a rule added tomorrow
    is probed tomorrow, with no edit here.
    """
    out: dict[str, set[str]] = {}
    try:
        paths = sorted(Path(rules_dir).rglob("*.json"))
    except OSError:
        return out
    for path in paths:
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        rid = str(data.get("id") or path.stem)
        then = data.get("then")
        actions = (then or {}).get("actions") if isinstance(then, dict) else None
        for action in actions or []:
            if isinstance(action, dict) and isinstance(action.get("tool"), str):
                out.setdefault(action["tool"], set()).add(rid)
    return out


def broken_wrappers(bin_dir: Path | None = None,
                    rules_dir: Path | None = None) -> dict[str, list[tuple]]:
    'Every wrapper in `bin_dir` whose pinned absolute paths have vanished.\n\n    Shared with `core/tools_anchor/provision.sh verify-wrappers` so the\n    deployment gate and the runtime report answer "is this wrapper broken" the\n    same way and cannot drift apart. Doctor\'s own `_check_tools` keeps probing\n    only corpus tools (its question is "can this engine run its rules"); the\n    gate reports the stray ones too, because a wrapper pointing at a vanished\n    venv breaks whatever workflow uses it, whether or not a rule names it.\n\n    A missing or unreadable `bin_dir` yields empty lists, not an exception: a\n    host that keeps its tools in the toolbox or on PATH has no wrappers and is\n    not defective.\n    '
    root = Path(bin_dir).expanduser() if bin_dir else Path(
        os.environ.get("MOTOKO_WRAPPER_BIN", "~/.local/bin")).expanduser()
    named = _corpus_tools(Path(rules_dir) if rules_dir
                          else util.default_rules_dir())
    out: dict[str, list[tuple]] = {"corpus": [], "other": []}
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return out
    for entry in entries:
        try:
            if entry.is_dir():
                continue
            why = _wrapper_defect(entry)
        except OSError:
            continue
        if not why:
            continue
        key = "corpus" if entry.name in named else "other"
        out[key].append((entry.name, str(entry), why))
    return out


def _strix_pyproject_version() -> str | None:
    "Version declared in the tools/strix checkout's pyproject.toml, or None."
    env = os.environ.get("MOTOKO_TOOLS")
    root = Path(env).expanduser() if env else util.motoko_root() / "tools"
    try:
        with open(root / "strix" / "pyproject.toml", "rb") as fh:
            project = tomllib.load(fh).get("project")
    except (OSError, ValueError):
        return None
    if not isinstance(project, dict):
        return None
    version = project.get("version")
    return version.strip() if isinstance(version, str) and version.strip() else None


def _strix_cli_version(timeout: int = 10) -> tuple[bool, str]:
    """(answered, version) from the deployed `strix --version`, bounded.

    Mirrors _podman: `answered` False means strix is absent or did not answer
    — cannot-verify, never a defect (the corpus-tools line already reports an
    absent strix). Bounded because doctor is the fresh-host gate and must not
    hang; `--version` exits before any IO (measured ~0.2 s, no network).
    """
    where = executor.resolve_tool("strix")
    if not where:
        return False, ""
    try:
        proc = subprocess.run([where, "--version"], capture_output=True,
                              text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return False, ""
    if proc.returncode != 0:
        return False, ""
    parts = (proc.stdout or "").split()  # `strix 1.6.2` -> "1.6.2"
    return True, (parts[-1] if parts else "")


def _check_strix_version() -> list[tuple[str, str]]:
    'WARN when the deployed strix and the tools/strix source tree disagree.'
    declared = _strix_pyproject_version()
    if not declared:
        return []
    answered, deployed = _strix_cli_version()
    if not answered or not deployed:
        return []
    if declared != deployed:
        return [(WARN, "strix version split: tools/strix/pyproject.toml declares "
                       f"{declared}, deployed `strix --version` is {deployed} "
                       "(a recorded pitfall — the running bytes are the uv-tool install, not "
                       "the source tree the patches merge against). Reconcile "
                       "via `provision.sh strix-upgrade` or re-pin the checkout")]
    return [(OK, f"strix version consistent: {deployed}")]


def _check_tools() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    env = os.environ.get("MOTOKO_TOOLS")
    root = Path(env).expanduser() if env else util.motoko_root() / "tools"
    if not root.is_dir():
        out.append((WARN, f"toolbox not found: {root} (set MOTOKO_TOOLS; "
                          "see engine/core/tools_anchor/ — provision.sh, with "
                          "manifest.json generated per host by make_manifest.py)"))
    else:
        out.append((OK, f"toolbox: {root}"))
    # resolve a few well-known binaries — absence is a warning, not a
    # failure: a minimal host may only need the CLI-side legs.
    for name in ("nuclei", "subfinder", "httpx"):
        where = executor.resolve_tool(name)
        out.append((OK if where else WARN,
                    f"tool {name}: {where or 'not found'}"))
    # A tool that resolves but cannot exec is invisible to every other check:
    # resolve_tool finds the wrapper, rulecheck's resolve_tools counts it
    # available, and at runtime its exit 127 is charged to the (rule, asset)
    # pair like a rule defect. Probe the corpus's own tool list, statically.
    named = _corpus_tools(util.default_rules_dir())
    runtimes = _tool_runtimes(util.default_rules_dir())
    container_only = sorted(t for t in named if runtimes.get(t) == {"container"})
    host_named = {t: r for t, r in named.items() if t not in set(container_only)}
    dead, absent = [], []
    for name in sorted(host_named):
        where = executor.resolve_tool(name)
        if not where:
            absent.append(name)
            continue
        why = _wrapper_defect(Path(where))
        if why:
            dead.append(f"{name} ({where}) {why}")
    if dead:
        out.append((WARN, "corpus tools that RESOLVE BUT CANNOT EXEC — every "
                          "rule using them will fail as a deployment defect, "
                          "not a target finding: " + "; ".join(dead)))
    if absent:
        rules_using = sorted({r for n in absent for r in host_named.get(n, ())})
        out.append((WARN, f"corpus tools not found on this host: "
                          f"{', '.join(absent)} (rules: "
                          f"{', '.join(rules_using)})"))
    out.extend(_container_tools_lines(named, container_only))
    host_runnable = len(host_named) - len(dead) - len(absent)
    out.append((OK if not dead and not absent else WARN,
                f"corpus tools: {len(named)} named ({len(host_named)} host, "
                f"{len(container_only)} container-only), {host_runnable} "
                f"host-runnable, {len(dead)} broken wrapper(s), "
                f"{len(absent)} missing on host"))
    podman = executor.resolve_tool("podman")
    if podman:
        sock = Path(f"/run/user/{os.getuid()}/podman/podman.sock")
        if sock.exists():
            out.append((OK, f"podman socket: {sock}"))
        else:
            out.append((WARN, "podman socket missing "
                              "(systemctl --user start podman.socket)"))
    out.extend(_check_strix_version())
    return out


def _oob_rules(rules_dir: Path) -> list[str]:
    """Rules whose templates render `{oob}` — derived, never a hardcoded list.

    `obs_url` counts: it renders with the same ctx, so a canary callback written
    there depends on the engagement's OOB domain exactly like a command does.
    """
    out: set[str] = set()
    try:
        paths = sorted(Path(rules_dir).rglob("*.json"))
    except OSError:
        return []
    for path in paths:
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        then = data.get("then")
        actions = (then or {}).get("actions") if isinstance(then, dict) else None
        for action in actions or []:
            if not isinstance(action, dict):
                continue
            for value in action.values():
                if not isinstance(value, str):
                    continue
                if "oob" in {n.lower() for n in cmd.placeholder_names(value)}:
                    out.add(str(data.get("id") or path.stem))
                    break
    return sorted(out)


def _browser_backend() -> str | None:
    """A headless-browser backend this host could offer an injected validator."""
    try:
        if importlib.util.find_spec("playwright"):
            return "playwright"
    except (ImportError, ValueError, OSError):
        pass
    for name in ("chromium", "chromium-browser", "google-chrome", "chrome"):
        if shutil.which(name):
            return name
    return None


def _run_wires_backends() -> tuple[bool, bool]:
    """Does `motoko run` inject a browser / canary? Read, never assumed.

    Deriving this from cmd_run's own source is what keeps the caveat honest: the
    day the CLI starts wiring them, the line stops printing instead of lying.
    """
    try:
        from . import cli
        src = inspect.getsource(cli.cmd_run)
    except Exception:      # noqa: BLE001 - a doctor line must never raise
        return False, False
    return "browser=" in src, "canary=" in src


def _check_backends() -> list[tuple[str, str]]:
    'The verification-backend contract doctor is cited for.'
    out: list[tuple[str, str]] = []
    browser = _browser_backend()
    out.append((OK if browser else WARN,
                f"dom backend: {browser or 'none found'} — "
                + ("available to an injected validator" if browser else
                   "client-side (dom) findings park as `missing_backend` "
                   "instead of being verified; the documented wiring is "
                   "playwright + chromium (graph_health._BLOCK_SUGGESTIONS)")))
    canary = executor.resolve_tool("interactsh-client")
    out.append((OK if canary else WARN,
                f"oob canary tool: {canary or 'interactsh-client not found'} — "
                "`motoko run` builds an interactsh canary manager from this "
                "binary (lazily: the poller starts on the first canary issue, "
                "so a run that verifies no OOB finding spawns none) and the "
                "engagement also needs `--oob-domain`; without the domain the "
                "callback URL cannot be rendered at all"))
    oob = _oob_rules(util.default_rules_dir())
    out.append((OK, f"rules rendering {{oob}}: {', '.join(oob) or 'none'} — on "
                    "an engagement without `--oob-domain` these are not "
                    "proposed (a recorded pitfall mint door, one "
                    "`mint.placeholder_unsatisfiable` event each): a config "
                    "gap, not a dead rule"))
    wires_browser, wires_canary = _run_wires_backends()
    if not (wires_browser and wires_canary):
        # Name the leg that is actually missing. "injects neither" was true
        # while both were unwired; the day the canary got wired it would have
        # started lying about the half that works, which is the one failure
        # mode this line exists to prevent.
        missing = "/".join(n for n, wired in (("browser", wires_browser),
                                              ("canary", wires_canary))
                           if not wired)
        out.append((WARN,
                    f"`motoko run` does not inject the {missing} backend "
                    f"(browser={'wired' if wires_browser else 'NOT wired'}, "
                    f"canary={'wired' if wires_canary else 'NOT wired'}): the "
                    "runtime is stdlib-only by design, so findings needing "
                    "it park as `missing_backend` even with everything above "
                    "installed — inject them through the API, or read the park "
                    "as the expected outcome"))
    return out


def _check_loop_config() -> tuple[str, str]:
    from .cli import validate_loop_config
    from .loop import default_config_path, load_loop_config

    path = default_config_path()
    if not path.exists():
        return WARN, ("no loop config found ($MOTOKO_CONFIG > "
                      "engine/loop/loop.yaml > ~/.motoko/loop.yaml) — "
                      "`motoko loop` unavailable")
    try:
        cfg = load_loop_config(path)
    except ValueError as e:  # unset ${VAR} etc.
        return FAIL, f"loop config {path}: {e}"
    problems = validate_loop_config(cfg)
    if problems:
        return FAIL, (f"loop config {path} invalid: " + "; ".join(problems[:3]))
    legs = [a.get("name", "?") for a in cfg.get("auditors", [])]
    adj = cfg.get("adjudicator")
    adj = adj.get("name", "?") if isinstance(adj, dict) else (
        adj[0].get("name", "?") if isinstance(adj, list) and adj else "?")
    return OK, (f"loop config {path} valid (auditors: "
                f"{', '.join(legs) or '-'}; adjudicator: {adj})")


def _check_pyflakes() -> tuple[str, str]:
    """The loop's static_warnings metric shells out to `python -m
    pyflakes`; with no pyflakes installed the run degrades to a silent
    (0, 0) and the convergence signal flatlines at zero."""
    if importlib.util.find_spec("pyflakes") is None:
        return WARN, ("pyflakes not installed — loop static_warnings "
                      "metric silently 0")
    return OK, "pyflakes: available"


def credential_defect(value: str | None) -> str | None:
    'Static shape check on a credential read from the environment.'
    if value is None:
        return None
    if not value.strip():
        return "empty value"
    if "$(" in value:
        return ("unexpanded $(...) command substitution — systemd "
                "environment.d files are plain KEY=value and perform no "
                "substitution; write the literal value into the file")
    if "`" in value:
        return "unexpanded `...` command substitution (same cause as $(...))"
    if "${" in value:
        return ("unexpanded ${...} variable reference — environment.d does "
                "not expand it either")
    if value != value.strip():
        return "leading/trailing whitespace (paste artifact)"
    if any(ch.isspace() for ch in value):
        return "embedded whitespace (paste artifact)"
    return None


def _credential_line(label: str, env_name: str) -> tuple[str, str]:
    """One key-env verdict: unset warns, set-but-broken FAILs, else OK.

    The asymmetry is the point. An absent credential is a configuration
    choice — optional legs are allowed to be unwired, and failing on them
    would make doctor unusable on any partial host. A credential that is
    *present but structurally not one* is worse than absent: it reads as
    configured, so the leg silently authenticates with shell text and the
    failure surfaces as a vendor 401 nobody connects back to this file.
    """
    value = os.environ.get(env_name)
    if value is None:
        return WARN, f"{label} {env_name}: UNSET"
    defect = credential_defect(value)
    if defect:
        return FAIL, f"{label} {env_name}: {defect}"
    return OK, f"{label} {env_name}: set"


def _launch_credential_line(label: str, env_name: str) -> tuple[str, str]:
    'Launch-gate key-env verdict: unset/empty/broken all FAIL.'
    value = os.environ.get(env_name)
    if value is None:
        return FAIL, f"{label} {env_name}: UNSET (launch gate)"
    defect = credential_defect(value)
    if defect:
        return FAIL, f"{label} {env_name}: {defect} (launch gate)"
    return OK, f"{label} {env_name}: set"


def _check_key_envs() -> list[tuple[str, str]]:
    'Every api_key_env the live config references: shape-checked.'
    from .loop import default_config_path, load_loop_config

    out: list[tuple[str, str]] = []
    path = default_config_path()
    if not path.exists():
        return out
    try:
        cfg = load_loop_config(path)
    except ValueError:
        return out
    endpoints = list(cfg.get("auditors") or [])
    if isinstance(cfg.get("adjudicator"), dict):
        endpoints.append(cfg["adjudicator"])
    gate = os.environ.get("MOTOKO_LAUNCH_GATE") == "1"
    for ep in endpoints:
        env_name = (ep or {}).get("api_key_env")
        if not env_name:
            continue
        if gate:
            out.append(_launch_credential_line("key env", env_name))
        else:
            out.append(_credential_line("key env", env_name))
    return out


def _check_reflector() -> tuple[str, str]:
    protocol = os.environ.get("MOTOKO_REFLECTOR_PROTOCOL", "anthropic").strip().lower()
    if protocol not in {"anthropic", "openai"}:
        return FAIL, ("MOTOKO_REFLECTOR_PROTOCOL must be 'anthropic' or "
                      "'openai'")
    have = [v for v in ("MOTOKO_REFLECTOR_MODEL", "MOTOKO_REFLECTOR_BASE_URL")
            if os.environ.get(v)]
    key_env = os.environ.get("MOTOKO_REFLECTOR_KEY_ENV")
    if key_env:
        level, msg = _credential_line("reflector key env", key_env)
        if level != OK:
            return level, msg
    if len(have) == 2:
        if not key_env:
            # reflector_from_env() requires MOTOKO_REFLECTOR_KEY_ENV (it names
            # the variable holding the key); without it the reflector is None
            # and `motoko run --reflector` silently continues with no
            # reflector. Optional stays optional — WARN, not FAIL — but it
            # must not read as configured.
            return WARN, ("reflector env incomplete (MOTOKO_REFLECTOR_KEY_ENV "
                          "unset — `motoko run --reflector` needs it; the "
                          "reflector stays disabled without it)")
        base = os.environ.get("MOTOKO_REFLECTOR_BASE_URL", "").rstrip("/")
        if protocol == "anthropic" and base.endswith("/v1"):
            return FAIL, ("MOTOKO_REFLECTOR_BASE_URL must not end in /v1 — "
                          "the reflector appends /v1/messages (one "
                          "convention across every anthropic adapter); a "
                          "doubled segment 404s at launch")
        if protocol == "anthropic" and base.endswith("/v1/messages"):
            return FAIL, ("MOTOKO_REFLECTOR_BASE_URL must not carry the full "
                          "endpoint path — the reflector appends "
                          "/v1/messages; the paste doubles the segment and "
                          "404s at launch")
        if protocol == "openai" and base.endswith("/chat/completions"):
            return FAIL, ("MOTOKO_REFLECTOR_BASE_URL must not carry the full "
                          "endpoint path — the reflector appends "
                          "/chat/completions for openai; the paste doubles "
                          "the segment and 404s at launch")
        return OK, f"reflector env: configured ({protocol})"
    return WARN, ("reflector env incomplete (optional — "
                  "`motoko run --reflector` needs MOTOKO_REFLECTOR_*)")


def _container_rules(rules_dir: Path | None = None) -> set[str]:
    """Rule ids with an action declaring `runtime: container`.

    Derived from the corpus, never hardcoded (the `{oob}` precedent): this set
    IS the blast radius of an image behind the container name that has drifted
    from `util.KALI_IMAGE`, because those are the rules that `podman exec` into
    it. A rule added tomorrow appears in tomorrow's line.
    """
    out: set[str] = set()
    try:
        paths = sorted(Path(rules_dir or util.default_rules_dir()).rglob("*.json"))
    except OSError:
        return out
    for path in paths:
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        then = data.get("then")
        actions = (then or {}).get("actions") if isinstance(then, dict) else None
        for action in actions or []:
            if isinstance(action, dict) and action.get("runtime") == "container":
                out.add(str(data.get("id") or path.stem))
    return out


def _podman(argv: list[str], timeout: int = 20) -> tuple[bool, str]:
    'A read-only podman query → (answered, stdout).'
    podman = shutil.which("podman")
    if podman is None:
        return False, ""
    try:
        proc = subprocess.run([podman, *argv], capture_output=True, text=True,
                              timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return False, ""
    return proc.returncode == 0, (proc.stdout or "")


def _check_kali_container() -> list[tuple[str, str]]:
    'Is the live toolbox container running the image the corpus expects?'
    rules = _container_rules()
    scope = (f"{len(rules)} rule(s) declare runtime: container"
             if rules else "no rule declares runtime: container")
    if shutil.which("podman") is None:
        return [(WARN, "kali container: podman absent — the container route "
                       f"(`{util.KALI_CONTAINER}`) is unavailable, so those "
                       f"actions refuse; {scope}. Host tools still work (by design)")]
    ok, names = _podman(["ps", "-a", "--filter", f"name={util.KALI_CONTAINER}",
                         "--format", "{{.Names}}"])
    if not ok:
        return [(WARN, "kali container: cannot verify — podman did not answer "
                       "(socket down? `systemctl --user start podman.socket`); "
                       f"{scope}")]
    present = util.KALI_CONTAINER in {n.strip() for n in names.splitlines()}
    if not present:
        return [(WARN, f"kali container: `{util.KALI_CONTAINER}` does not exist "
                       f"— `motoko kali start` creates it from {util.KALI_IMAGE}; "
                       f"{scope}")]
    ok_img, raw = _podman(["inspect", "--format", "{{.Config.Image}}",
                           util.KALI_CONTAINER])
    image = raw.strip()
    if not ok_img or not image:
        return [(WARN, f"kali container: `{util.KALI_CONTAINER}` exists but its "
                       "image cannot be verified (podman inspect did not "
                       f"answer); {scope}")]
    if image != util.KALI_IMAGE:
        return [(FAIL, f"kali container: `{util.KALI_CONTAINER}` runs {image}, "
                 f"not the configured {util.KALI_IMAGE} — rules declaring "
                 "runtime: container exec INTO this container, so they get the "
                 f"OLD toolset ({scope}). Remedy: `motoko kali start "
                 f"--recreate`, or set MOTOKO_KALI_IMAGE={image} if {image} "
                 "is the intended tag")]
    return [(OK, f"kali container: `{util.KALI_CONTAINER}` on {image}; {scope}")]


def _is_safe_tool_name(name: str) -> bool:
    'True when a tool name may be interpolated into a `sh -c` unquoted.'
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", name or ""))


def _tool_runtimes(rules_dir: Path | None = None) -> dict[str, set[str]]:
    """tool name -> the runtimes its actions declare ({} if unreadable).

    Derived from the corpus like `_corpus_tools`, so a rule added tomorrow is
    classified tomorrow. A tool used by BOTH a host and a container action lands
    in both sets, which is what keeps it host-probed: the host really needs it.
    """
    out: dict[str, set[str]] = {}
    try:
        paths = sorted(Path(rules_dir or util.default_rules_dir()).rglob("*.json"))
    except OSError:
        return out
    for path in paths:
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        then = data.get("then")
        actions = (then or {}).get("actions") if isinstance(then, dict) else None
        for action in actions or []:
            if not isinstance(action, dict):
                continue
            tool = action.get("tool")
            if not isinstance(tool, str) or not tool:
                continue
            out.setdefault(tool, set()).add(
                "container" if action.get("runtime") == "container" else "host")
    return out


def _container_tools_present(tools: list[str]) -> tuple[str, list[str], list[str]]:
    """Probe container-only tools inside the live toolbox container.

    Returns (state, present, absent) where state is "ok" or "cannot-verify".
    Read-only (`command -v`), one exec for the whole set, and a tool the probe
    never answered for counts as absent rather than present — an unanswered name
    is the shape a changed base image produces.
    """
    unsafe = [t for t in tools if not _is_safe_tool_name(t)]
    if unsafe:
        return "cannot-verify", [], unsafe
    safe = list(tools)
    if not safe:
        return "ok", [], []
    answered, running = _podman(
        ["ps", "--filter", f"name={util.KALI_CONTAINER}",
         "--filter", "status=running", "--format", "{{.Names}}"])
    if not answered or util.KALI_CONTAINER not in {
            n.strip() for n in running.splitlines()}:
        return "cannot-verify", [], safe
    script = ("for t in " + " ".join(safe) + '; do printf "%s\\t%s\\n" "$t" '
              '"$(command -v "$t" 2>/dev/null)"; done')
    answered, out = _podman(["exec", util.KALI_CONTAINER, "sh", "-c", script],
                            timeout=60)
    if not answered or not out.strip():
        return "cannot-verify", [], safe
    present, absent, seen = [], [], set()
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, _, where = line.partition("\t")
        name = name.strip()
        seen.add(name)
        (present if where.strip() else absent).append(name)
    absent.extend(t for t in safe if t not in seen)
    return "ok", present, absent


def _container_tools_lines(named: dict[str, set[str]],
                           container_only: list[str]) -> list[tuple[str, str]]:
    if not container_only:
        return []
    state, present, absent = _container_tools_present(container_only)
    box = util.KALI_CONTAINER
    if state == "cannot-verify":
        return [(WARN, f"corpus tools that live inside the container `{box}`: "
                       f"{', '.join(container_only)} — cannot verify "
                       f"(the container is not running or the probe did not "
                       f"answer; `motoko kali start` then re-run doctor). Not "
                       f"counted as missing: their runtime is the container")]
    if absent:
        return [(WARN, f"corpus tools missing inside the container `{box}`: "
                       f"{', '.join(absent)} — rules declaring "
                       f"runtime: container will fail at exec and the strike is "
                       f"charged to the (rule, asset) pair. The image tag can be "
                       f"correct and the tool still absent from it: rebuild the "
                       f"image, or retire the rule")]
    return [(OK, f"corpus tools present inside the container `{box}`: "
                 f"{', '.join(present)}")]


def _check_wordlists() -> tuple[str, str]:
    wl = os.environ.get("MOTOKO_WORDLIST_DIR", "~/.motoko/wordlists")
    p = Path(wl).expanduser()
    if p.is_dir():
        return OK, f"wordlists: {p}"
    return WARN, f"wordlists dir missing: {p}"


def _check_engagements() -> list[tuple[str, str]]:
    """Census only: sealed vs unsealed, WAL leftovers on sealed ones."""
    out: list[tuple[str, str]] = []
    root = db.default_root()
    if not root.is_dir():
        return out
    dirs = [d for d in root.iterdir() if d.is_dir() and (d / "graph.db").exists()]
    sealed = sum(1 for d in dirs if (d / "engagement.manifest.json").exists())
    archived = 0
    arch_root = root.parent / "archive"
    if arch_root.is_dir():
        archived = sum(1 for d in arch_root.iterdir()
                       if d.is_dir() and (d / "graph.db").exists())
    suffix = f", {archived} archived" if archived else ""
    out.append((OK, f"engagements: {len(dirs)} on disk, {sealed} sealed"
                    f"{suffix}"))
    stale = []
    for d in dirs:
        # only WAL frames count as dirt. A 0-byte -wal next to a sealed db
        # is the known SQLite ro-open artifact: read-only connections
        # create the sidecar and cannot delete it on close — cosmetic.
        if (d / "graph.db-wal").exists() and \
                (d / "graph.db-wal").stat().st_size > 0 and \
                (d / "engagement.manifest.json").exists():
            stale.append(d.name)
    if stale:
        out.append((WARN, f"sealed engagements with WAL FRAMES (re-seal): "
                          f"{', '.join(stale[:5])}"))
    return out


def _latest_egress_fingerprint() -> dict | None:
    """The newest durable fingerprint record across engagements, or None.

    Doctor runs in its own process, so the per-process probe cache is empty
    by definition here; the engagement-side ``egress-fingerprint.json`` files
    are the durable half of the measurement. Read-only, and NEVER a probe: a
    doctor run that sent traffic would ride the very lane it reports on.
    """
    root = db.default_root()
    if not root.is_dir():
        return None
    best: tuple[float, dict] | None = None
    for path in root.glob("*/egress-fingerprint.json"):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        # valid JSON is not necessarily a record: a list/string body has no
        # probed_at to compare and must not kill the whole CLI
        if not isinstance(data, dict):
            continue
        at = data.get("probed_at")
        if not isinstance(at, (int, float)) or isinstance(at, bool):
            continue
        if not math.isfinite(at):
            # Infinity/NaN pass a numeric type check and then read as age
            # 0.0h — a record that can never go stale. Not a measurement.
            continue
        if best is None or at > best[0]:
            best = (at, data)
    return best[1] if best else None


def _check_egress_fingerprint() -> tuple[str, str]:
    "The exit-identity axis: which exit ip the last probe measured, how\n    old that measurement is, and the rotation deadline.\n\n    Levels: lane mode without an echo URL is a WARN — every tool_run row\n    then records an unattributable exit, and that deserves visibility\n    without breaking deployments. An overdue known identity WARNs too, and so\n    does a record whose ``exit_ip`` fails the probe's own plausibility bar\n    (doctor reads the file back rather than measuring, so it re-judges the\n    value before repeating it as fact). The unknown/no-echo states in\n    non-lane modes are informational: the feature is fail-closed dormant,\n    which is a configured choice, not a defect."
    echo = egress.echo_url()
    if echo:
        defect = egress.echo_url_defect(echo)
        if defect:
            return FAIL, (f"exit fingerprint: unknown — "
                          f"{egress.ECHO_URL_ENV} is configured but unusable "
                          f"({defect}); no probe through it can measure an "
                          f"exit, so attribution is impossible")
    hours = egress.rotate_hours()
    record = _latest_egress_fingerprint()
    if record is None or not record.get("exit_ip"):
        if egress.mode() == egress.LANE and not egress.echo_url():
            return WARN, (f"exit fingerprint: unknown — lane mode with no "
                          f"echo URL ({egress.ECHO_URL_ENV} unset); exit "
                          f"attribution is impossible")
        if not egress.echo_url():
            return OK, (f"exit fingerprint: unknown — no echo URL configured "
                        f"({egress.ECHO_URL_ENV} unset); feature dormant")
        return OK, ("exit fingerprint: unknown — echo configured but no "
                    "successful probe recorded yet (first measured at the "
                    "first tool_run)")
    ip = str(record["exit_ip"])
    if egress_probe.plausible_ip(ip) is None:
        return WARN, (f"exit fingerprint: unknown — the durable record's "
                      f"exit_ip ({ip!r}) is not an IP literal, so there is no "
                      f"measurement to report; re-probe to re-establish "
                      f"attribution")
    at = float(record.get("probed_at") or 0.0)
    age_h = max(0.0, (time.time() - at) / 3600.0)
    if hours <= 0:
        # <=0 and unparseable both disable the hook, but must not share a
        # message: "<=0" claims the operator chose to disable, which an
        # unparseable value never is.
        try:
            deliberate = float(
                os.environ.get(egress.ROTATE_HOURS_ENV, "")) <= 0
        except ValueError:
            deliberate = False
        state = (f"disabled via {egress.ROTATE_HOURS_ENV}<=0" if deliberate
                 else f"unparseable {egress.ROTATE_HOURS_ENV} — hook off")
        return OK, (f"exit fingerprint: {ip} (age {age_h:.1f}h; rotation "
                    f"hook {state})")
    if age_h >= hours:
        return WARN, (f"exit fingerprint: {ip} (age {age_h:.1f}h >= rotate "
                      f"{hours}h) — rotation overdue; the wave-boundary hook "
                      f"will demand a refresh")
    return OK, (f"exit fingerprint: {ip} (age {age_h:.1f}h, rotate at "
                f"{hours}h)")


# Subcommands of the engine CLI that open a writer and can send target
# traffic — the shapes core/cli.py's entry points produce (`motoko <cmd>` /
# `python -m core <cmd>`). Read-only commands (doctor, rules, query, …)
# never match, so a doctor run never flags itself.
_LIVE_WRITER_COMMANDS = frozenset({"run", "adapter"})
# Top-level CLI options that consume a separate value token; the subcommand
# is the first bare token after them (cli.build_parser's _interface_options).
_CLI_VALUE_OPTIONS = frozenset({"--root", "--theme"})


def _writer_command(tokens: list[str]) -> str | None:
    """The traffic-writer subcommand a /proc cmdline invokes, or None.

    Both launch shapes land here: the console script (the kernel rewrites
    argv to ``python …/bin/motoko run eng``) and the module form
    (``python -m core run eng``). Only the token AFTER the CLI name is the
    command; global options and their values are stepped over.
    """
    argv: list[str] = []
    for i, tok in enumerate(tokens[:-1]):
        if tok == "-m" and tokens[i + 1] == "core":
            argv = tokens[i + 2:]
            break
    if not argv:
        for i, tok in enumerate(tokens):
            if tok.rsplit("/", 1)[-1] == "motoko":
                argv = tokens[i + 1:]
                break
    if not argv:
        return None
    skip_value = False
    for tok in argv:
        if skip_value:
            skip_value = False
            continue
        if tok in _CLI_VALUE_OPTIONS:
            skip_value = True
            continue
        if tok.startswith("-"):
            continue            # boolean or inline-value options (--demo, --root=/x)
        return tok if tok in _LIVE_WRITER_COMMANDS else None
    return None


def _proc_env(blob: bytes, name: str) -> str:
    """One variable out of a NUL-separated /proc/<pid>/environ blob ("" absent)."""
    prefix = name.encode() + b"="
    for field in blob.split(b"\0"):
        if field.startswith(prefix):
            return field[len(prefix):].decode("utf-8", "replace").strip()
    return ""


def _proc_lane(blob: bytes) -> bool:
    """Whether a /proc environ blob carries a lane address, in any spelling.

    ``_proc_env`` is name-exact, so every case of every lane variable is
    asked in turn — the same set ``egress.strip_host_forwarding`` matches
    case-insensitively against a child env.
    """
    return any(_proc_env(blob, name)
               for var in egress.HOST_FWD_VARS
               for name in (var, var.upper()))


def _check_egress_live(proc_root: Path | None = None) -> tuple[str, str]:
    'The live-writer axis: the egress env of RUNNING engine processes.'
    root = Path(proc_root) if proc_root is not None else Path("/proc")
    if not root.is_dir():
        return OK, "live engine writers: no /proc to scan — cannot verify"
    try:
        self_pgid = os.getpgid(0)
    except OSError:
        self_pgid = None
    self_pid = os.getpid()
    writers: list[tuple[int, str]] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return OK, f"live engine writers: cannot list {root} — cannot verify"
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == self_pid:
            continue                        # never flag the doctor itself
        try:
            raw_cmd = (entry / "cmdline").read_bytes()
        except OSError:
            continue                        # vanished mid-scan: skip, not report
        tokens = [t for t in
                  raw_cmd.decode("utf-8", "replace").split("\0") if t]
        if _writer_command(tokens) is None:
            continue
        if self_pgid is not None:
            try:
                if os.getpgid(pid) == self_pgid:
                    continue                # the writer doctor runs inside of
            except OSError:
                pass                        # synthetic or vanished pid: keep it
        try:
            blob = (entry / "environ").read_bytes()
        except OSError:
            continue                        # unreadable environ: skip, not report
        mode = _proc_env(blob, egress.MODE_ENV)
        if not mode:
            state = ("accepted-direct" if _proc_env(
                blob, egress.ACCEPT_DIRECT_ENV).lower()
                in {"1", "true", "yes", "on"} else "undeclared")
        elif mode.lower() not in egress.MODE_VALUES:
            state = f"unrecognized:{mode}"
        elif mode.lower() == egress.LANE:
            state = "lane" if _proc_lane(blob) else "lane-no-address"
        else:
            state = "direct"
        writers.append((pid, state))
    if not writers:
        return OK, "live engine writers: none running (run/adapter)"
    detail = ", ".join(f"pid {pid} mode={state}" for pid, state in writers)
    if any(state == "undeclared" for _pid, state in writers):
        return FAIL, (f"live engine writers with UNDECLARED egress mode "
                      f"({detail}) — {egress.MODE_ENV} is absent from the "
                      f"process's own environ: the incident shape "
                      f"(by design). Stop and relaunch with the variable set")
    if any(state.startswith("unrecognized") for _pid, state in writers):
        return FAIL, (f"live engine writers with an UNRECOGNIZED egress mode "
                      f"({detail}) — {egress.MODE_ENV} carries a value that is "
                      f"neither {egress.LANE} nor {egress.DIRECT}, so it reads "
                      f"as the forbidden direct fallback and the launch gate "
                      f"refuses it (by design). Stop and relaunch with a legal value")
    if any(state == "lane-no-address" for _pid, state in writers):
        return FAIL, (f"live engine writers declaring a lane with NO lane "
                      f"address in their own environ ({detail}; checked "
                      f"{', '.join(sorted(egress.HOST_FWD_VARS))}) — the "
                      f"engine only inherits or strips a lane, so every tool "
                      f"is running DIRECT over the bare uplink while the "
                      f"mode says otherwise (by design). Stop and relaunch with a "
                      f"lane address exported")
    if any(state != "lane" for _pid, state in writers):
        return WARN, (f"live engine writers on direct egress ({detail}) — "
                      f"the bare uplink reaches targets unrouted (by design)")
    return OK, f"live engine writers: {detail}"


def _check_egress() -> list[tuple[str, str]]:
    '    The first line FAILs on the two declarations that do not mean what they\n    say — a value outside the mode vocabulary, and a lane claim the env\n    carries no lane for — because both are launch refusals, and a WARN beside\n    an OK would report the launch as healthy.'
    state = egress.summary()
    mode = state["mode"]
    if not state["mode_recognized"]:
        # A value outside the vocabulary reads as DIRECT downstream, so the
        # WARN below would name a mode the operator never chose. The launch
        # gate refuses it; doctor must say so rather than print "direct".
        first = (FAIL, f"egress mode: {egress.declared_mode()!r} is not one of "
                       f"{egress.LANE}|{egress.DIRECT} — {egress.MODE_ENV} "
                       f"carries a value the policy cannot parse, which reads "
                       f"as the forbidden direct fallback and refuses the "
                       f"launch (by design). Set it to one of the two legal values")
    elif mode == egress.LANE and not state["lane"]:
        lanes = ", ".join(sorted(egress.HOST_FWD_VARS))
        first = (FAIL, f"egress mode: lane but NO lane address in this "
                       f"process's env ({lanes}) — the engine never sets a "
                       f"lane, so every tool would run DIRECT over the "
                       f"bare uplink (by design). Export one, or declare "
                       f"{egress.MODE_ENV}={egress.DIRECT}")
    elif mode == egress.LANE:
        first = (OK, "egress mode: lane (anonymity-first, all tools via "
                     "egress)")
    elif state["mode_declared"]:
        first = (WARN, "egress mode: direct — the bare uplink reaches "
                       "targets unrouted; forbidden for new targets (by design)")
    else:
        first = (WARN, f"egress mode: unset (defaults to direct) — set "
                       f"{egress.MODE_ENV}=lane for anonymity-first launches "
                       f"(by design)")
    second = ((OK if state["replay_asserted"] else WARN), state["replay_note"])
    return [first, second, _check_egress_live(), _check_egress_fingerprint()]


def _local_dns_endpoint(addr: str) -> tuple[str, int]:
    """("host", port) parsed from a "host[:port]" local-forwarder address.

    Port defaults to 53 — the one a DNS forwarder listens on unless the
    operator said otherwise. Bracketed IPv6 (``[::1]:5353``) and colon-count
    disambiguate a port suffix from a bare IPv6 literal (``::1`` is a host,
    not host "" with port 1). A numeric-but-out-of-range port (0 < p <
    65536) falls to the unparsable state: the probe would silently wrap
    mod 65536 onto a different port while the report still named the
    configured one.
    """
    host = addr.strip()
    if host.startswith("[") and "]" in host:
        inside, _, rest = host[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
            if 0 < port < 65536:
                return inside, port
        return inside, 53
    if host.count(":") == 1:
        left, _, right = host.rpartition(":")
        if right.isdigit() and 0 < int(right) < 65536:
            return left, int(right)
    return host, 53


def _local_dns_listener_alive(host: str, port: int,
                              timeout: float = 2.0) -> bool:
    """True when a TCP connect to ``host:port`` answers. Never raises.

    Connect, not query: doctor only asks "is the forwarder there" — a DNS
    question would be traffic on the very lane doctor reports on. Bounded
    because doctor is the fresh-host gate and must not hang on a blackholed
    address.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _check_dns() -> list[tuple[str, str]]:
    """The resolver channel direct-path tools ride.

    A direct-path tool resolves target domains through the host resolver —
    usually the ISP's — which hands the operator's provider the engagement's
    query list. The channel is ``MOTOKO_DNS_RESOLVER``: a plain IP tools are
    pointed at, or a DoH/DoT URL an operator-run local forwarder fronts
    (tools then get ``MOTOKO_DNS_LOCAL_ADDR``). Doctor reports the
    unconfigured exposure and a dead local forwarder as WARNs and NEVER
    FAILs: a missing resolver is an exposure, not a broken deployment, and
    a dead forwarder must not brick doctor for hosts that never opted in.
    """
    resolver = dns_channel.configured()
    if not resolver:
        if egress.mode() == egress.LANE:
            return [(OK, "dns resolver: none configured — lane mode "
                         "resolves at the egress, no direct-path exposure")]
        return [(WARN, f"dns resolver: {dns_channel.resolver_env} unset while "
                      "egress mode is direct — every direct-path tool resolves "
                      "target domains through the ISP resolver, exposing the "
                      "engagement's query list; set it to a resolver IP or a "
                      "DoH/DoT URL fronted by a local forwarder")]
    if "://" not in resolver:
        return [(OK, f"dns resolver: {resolver} (appended to direct-path "
                     "tools via their own resolver flags; the host resolver "
                     "is never edited)")]
    local = dns_channel.tool_resolver_addr() or ""
    host, port = _local_dns_endpoint(local)
    if _local_dns_listener_alive(host, port):
        return [(OK, f"dns resolver: local forwarder {host}:{port} reachable "
                     f"(fronting {resolver}; direct-path tools point at "
                     f"{dns_channel.local_addr_env})")]
    return [(WARN, f"dns resolver: local forwarder not listening on "
                   f"{host}:{port} — {dns_channel.resolver_env} is a URL "
                   f"spec, so direct-path tools point at "
                   f"{dns_channel.local_addr_env}; start the forwarder "
                   "(a local split-DNS resolver such as smartdns) or every injected run fails to "
                   "resolve")]


def _check_deploy_config() -> list[tuple[str, str]]:
    """FIX-7: the deploy substrate file, one full-scope section.

    The file feeds egress + dns + strix, so it gets one owner here rather
    than a new egress axis. Absent file is the legal feature-off state
    (OK, like the dormant echo); present with defects FAILs — the file
    names egress gateways, so a defect at doctor time is a launch waiting
    to die at gate 2, better surfaced now. Deployment-state-free: the
    section never prints class names or addresses (class names are seat
    specifics), so like ``audit_config`` it stays out of scope=scan.
    """
    try:
        cfg = deploy_config.load()
    except deploy_config.DeployConfigError as exc:
        return [(FAIL, f"deploy config: {exc}")]
    if cfg.path is None:
        return [(OK, f"deploy config: none (feature off; looked at "
                     f"{deploy_config.deploy_path()})")]
    found = deploy_config.defects(cfg)
    if found:
        return [(FAIL, line) for line in found]
    classes = len(cfg._data.get("egress", {}).get("classes", {}))
    return [(OK, f"deploy config: {cfg.path} — {classes} egress class(es), "
                 f"loader-validated")]


def check_environment(scope: str = "full") -> list[tuple[str, list[tuple[str, str]]]]:
    """Named sections let supervisors report status without diagnostic text."""
    if scope not in {"full", "scan"}:
        raise ValueError("doctor scope must be full or scan")
    checks = [
        ("python", [_check_python()]), ("storage", [_check_root(), *_check_disk()]),
        ("temporary_storage", [_check_tmp_litter()]), ("tools", _check_tools()),
        ("verification_backends", _check_backends()), ("container", _check_kali_container()),
        ("wordlists", [_check_wordlists()]), ("engagements", _check_engagements()),
        ("egress", _check_egress()), ("dns", _check_dns()),
    ]
    if scope == "full":
        checks.extend([("audit_config", [_check_loop_config()]),
                       ("deploy_config", _check_deploy_config()),
                       ("linter", [_check_pyflakes()]), ("credentials", _check_key_envs()),
                       ("reflector", [_check_reflector()])])
    return checks


def _ready_lines() -> list[tuple[str, str]]:
    """Readiness verdict lines — printed only under ``--require-ready``.

    Scope boundary, deliberately narrow: readiness verifies what a
    FRESH INSTALL can honestly check — a tasks root that is creatable
    and writable OUTSIDE the interpreter's install tree (see
    ``util.under_interpreter_prefix``), and a rule corpus that loads
    with at least one rule. Operator-only substrate (credentials, echo
    URL, toolbox, container, loop config) is deployment state, not
    install state: those keep their existing WARN/cannot-verify levels
    and never gate the ready verdict, so a scrubbed CI environment
    cannot FAIL a ready check it has no substrate to satisfy. A check
    that cannot run at all (unreadable rules corpus) FAILs — readiness
    is fail-closed.
    """
    out: list[tuple[str, str]] = []
    root = db.default_root()
    if util.under_interpreter_prefix(root):
        out.append((FAIL, f"ready tasks root: {root} sits inside the "
                          "interpreter's install tree — a pip upgrade or "
                          "uninstall wipes every engagement there; set "
                          "MOTOKO_HOME to a location outside it"))
    else:
        probe = root
        while not probe.exists():
            probe = probe.parent
        if os.access(probe, os.W_OK):
            out.append((OK, f"ready tasks root: {root} (creatable/writable "
                            f"via {probe})"))
        else:
            out.append((FAIL, f"ready tasks root: {root} is not creatable — "
                              f"{probe} is not writable"))
    try:
        from .hypothesis_engine import HypothesisEngine
        count = HypothesisEngine(util.default_rules_dir()).rule_count()
    except (ValueError, RuntimeError) as e:
        # RuntimeError: the missing-dir refusal (a broken install);
        # ValueError: the loader's bad-file/duplicate-id raises.
        out.append((FAIL, f"ready rule corpus: cannot load — {e}"))
    else:
        if count <= 0:
            out.append((FAIL, "ready rule corpus: 0 rules loaded — the "
                              "engine would propose nothing and report it "
                              "as a clean run"))
        else:
            out.append((OK, f"ready rule corpus: {count} rules loaded"))
    return out


def doctor(scope: str = "full",
           require_ready: bool = False) -> tuple[int, list[tuple[str, str]]]:
    lines = [line for _category, checks in check_environment(scope) for line in checks]
    if require_ready:
        lines.extend(_ready_lines())
    rc = 1 if any(level == FAIL for level, _ in lines) else 0
    return rc, lines


def cmd_doctor(args) -> int:
    scope = getattr(args, "scope", "full")
    require_ready = getattr(args, "require_ready", False)
    rc, lines = doctor(scope, require_ready=require_ready)
    print(f"doctor scope: {scope}")
    for level, msg in lines:
        print(f"{level:4} {msg}")
    print(f"--- {'FAILURES PRESENT' if rc else 'no failures'} "
          f"(exit {rc})")
    return rc
