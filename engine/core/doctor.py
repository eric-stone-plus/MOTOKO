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
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import cmd, db, egress, executor, util

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
                                    "host (the internal doctrine)"))
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
                      f"(> {_TMP_LITTER_MAX}) — sweep stale ones (the internal doctrine)")
    return OK, f"tmp litter: {n} motoko-* dirs in {tmp}"


# Absolute paths a wrapper pins: its shebang interpreter, and anything on an
# `exec` / `"$@"` line. `#!/usr/bin/env X` names a program, not a path, so it is
# resolved through PATH instead of being checked as a literal.
# An absolute path only STARTS where a token can start: line start, whitespace,
# a quote, `=`, `(`, `,` or `;`. Matching any `/` instead — the shape this
# shipped with — reported three false-positive classes on the first live run of
# `provision.sh verify-wrappers`: `$HOME/.local/...` (matched the `/` after
# HOME), `${DIR}/run_shadow.py` (after the brace) and `socks5://host:port`
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
    'Every wrapper in `bin_dir` whose pinned absolute paths have vanished.\n\n    A missing or unreadable `bin_dir` yields empty lists, not an exception: a\n    host that keeps its tools in the toolbox or on PATH has no wrappers and is\n    not defective.\n    '
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


def _check_tools() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    env = os.environ.get("MOTOKO_TOOLS")
    root = Path(env).expanduser() if env else util.motoko_root() / "tools"
    if not root.is_dir():
        out.append((WARN, f"toolbox not found: {root} (set MOTOKO_TOOLS; "
                          f"see the internal tooling area (manifest.json + provision.sh))"))
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
                "the oob validator needs a canary manager AND an engagement "
                "`--oob-domain`; without the domain the callback URL cannot be "
                "rendered at all"))
    oob = _oob_rules(util.default_rules_dir())
    out.append((OK, f"rules rendering {{oob}}: {', '.join(oob) or 'none'} — on "
                    "an engagement without `--oob-domain` these are not "
                    "proposed (a recorded pitfall mint door, one "
                    "`mint.placeholder_unsatisfiable` event each): a config "
                    "gap, not a dead rule"))
    wires_browser, wires_canary = _run_wires_backends()
    if not (wires_browser and wires_canary):
        out.append((WARN,
                    "`motoko run` injects neither backend (browser="
                    f"{'wired' if wires_browser else 'NOT wired'}, canary="
                    f"{'wired' if wires_canary else 'NOT wired'}): the runtime "
                    "is stdlib-only by design (the internal doctrine), so dom/oob findings park as "
                    "`missing_backend` even with everything above installed — "
                    "inject them through the API, or read the park as the "
                    "expected outcome"))
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


def _check_key_envs() -> list[tuple[str, str]]:
    """Every api_key_env the live config references: shape-checked."""
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
    for ep in endpoints:
        env_name = (ep or {}).get("api_key_env")
        if not env_name:
            continue
        out.append(_credential_line("key env", env_name))
    return out


def _check_reflector() -> tuple[str, str]:
    have = [v for v in ("MOTOKO_REFLECTOR_MODEL", "MOTOKO_REFLECTOR_BASE_URL")
            if os.environ.get(v)]
    key_env = os.environ.get("MOTOKO_REFLECTOR_KEY_ENV")
    if key_env:
        level, msg = _credential_line("reflector key env", key_env)
        if level != OK:
            return level, msg
    if len(have) == 2:
        return OK, "reflector env: configured"
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
                       f"actions refuse; {scope}. Host tools still work (the internal doctrine)")]
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
                 f"not the documented {util.KALI_IMAGE} — rules declaring "
                 "runtime: container exec INTO this container, so they get the "
                 f"OLD toolset ({scope}). Remedy: `motoko kali start "
                 f"--recreate`, or bump util.KALI_IMAGE if {image} is the "
                 "intended tag")]
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


def _check_egress() -> list[tuple[str, str]]:
    ''
    state = egress.summary()
    mode = state["mode"]
    if mode == egress.PROXY:
        first = (OK, "egress mode: proxy (anonymity-first, all tools via "
                     "egress)")
    elif state["mode_declared"]:
        first = (WARN, "egress mode: direct — the residential IP reaches "
                       "targets unrouted; forbidden for new targets (the internal doctrine)")
    else:
        first = (WARN, f"egress mode: unset (defaults to direct) — set "
                       f"{egress.MODE_ENV}=proxy for anonymity-first launches "
                       f"(the internal doctrine)")
    second = ((OK if state["replay_asserted"] else WARN), state["replay_note"])
    return [first, second]


def check_environment() -> list[tuple[str, list[tuple[str, str]]]]:
    """Named sections let supervisors report status without diagnostic text."""
    return [
        ("python", [_check_python()]), ("storage", [_check_root(), *_check_disk()]),
        ("temporary_storage", [_check_tmp_litter()]), ("tools", _check_tools()),
        ("verification_backends", _check_backends()), ("container", _check_kali_container()),
        ("audit_config", [_check_loop_config()]), ("linter", [_check_pyflakes()]),
        ("credentials", _check_key_envs()), ("reflector", [_check_reflector()]),
        ("wordlists", [_check_wordlists()]), ("engagements", _check_engagements()),
        ("egress", _check_egress()),
    ]


def doctor() -> tuple[int, list[tuple[str, str]]]:
    lines = [line for _category, checks in check_environment() for line in checks]
    rc = 1 if any(level == FAIL for level, _ in lines) else 0
    return rc, lines


def cmd_doctor(args) -> int:
    rc, lines = doctor()
    for level, msg in lines:
        print(f"{level:4} {msg}")
    print(f"--- {'FAILURES PRESENT' if rc else 'no failures'} "
          f"(exit {rc})")
    return rc
