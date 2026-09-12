"""motoko doctor — read-only environment self-check for the runtime.

A reproducible runtime needs a way to answer "would the engine work on
this host, and if not, what is missing?" without running anything.
doctor() walks the dependency surface (python, engagement root, toolbox,
loop config, key envs, wordlists, podman) and reports one line per
check. Contract:

* never prints secret VALUES — set/unset only;
* never writes anything (no config creation, no dir mkdir);
* exit 0 when nothing FAILs; WARN is informational (an operator may run
  the loop over CLI legs with no HTTP keys at all, so missing keys are
  not a failure — the loop config decides what is required);
* exit 1 on any FAIL (broken config, unwritable root).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import db, executor, util

OK, WARN, FAIL = "OK", "WARN", "FAIL"


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


def _check_tools() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    env = os.environ.get("MOTOKO_TOOLS")
    root = Path(env).expanduser() if env else util.motoko_root() / "tools"
    if not root.is_dir():
        out.append((WARN, f"toolbox not found: {root} (set MOTOKO_TOOLS; "
                          f"see tools/manifest.json + provision.sh)"))
    else:
        out.append((OK, f"toolbox: {root}"))
    # resolve a few well-known binaries — absence is a warning, not a
    # failure: a minimal host may only need the CLI-side legs.
    for name in ("nuclei", "subfinder", "httpx"):
        where = executor.resolve_tool(name)
        out.append((OK if where else WARN,
                    f"tool {name}: {where or 'not found'}"))
    podman = executor.resolve_tool("podman")
    if podman:
        sock = Path(f"/run/user/{os.getuid()}/podman/podman.sock")
        if sock.exists():
            out.append((OK, f"podman socket: {sock}"))
        else:
            out.append((WARN, "podman socket missing "
                              "(systemctl --user start podman.socket)"))
    return out


def _check_loop_config() -> tuple[str, str]:
    from .cli import validate_loop_config
    from .loop import default_config_path, load_loop_config

    path = default_config_path()
    if not path.exists():
        return WARN, ("no loop config found ($MOTOKO_CONFIG > "
                      "config/loop.yaml > ~/.motoko/loop.yaml) — "
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


def _check_key_envs() -> list[tuple[str, str]]:
    """Every api_key_env the live config references: set/unset only."""
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
        out.append((OK if os.environ.get(env_name) else WARN,
                    f"key env {env_name}: "
                    f"{'set' if os.environ.get(env_name) else 'UNSET'}"))
    return out


def _check_reflector() -> tuple[str, str]:
    have = [v for v in ("MOTOKO_REFLECTOR_MODEL", "MOTOKO_REFLECTOR_BASE_URL")
            if os.environ.get(v)]
    if len(have) == 2:
        return OK, "reflector env: configured"
    return WARN, ("reflector env incomplete (optional — "
                  "`motoko run --reflector` needs MOTOKO_REFLECTOR_*)")


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
    out.append((OK, f"engagements: {len(dirs)} on disk, {sealed} sealed"))
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


def doctor() -> tuple[int, list[tuple[str, str]]]:
    lines: list[tuple[str, str]] = []
    lines.append(_check_python())
    lines.append(_check_root())
    lines.extend(_check_tools())
    lines.append(_check_loop_config())
    lines.extend(_check_key_envs())
    lines.append(_check_reflector())
    lines.append(_check_wordlists())
    lines.extend(_check_engagements())
    rc = 1 if any(level == FAIL for level, _ in lines) else 0
    return rc, lines


def cmd_doctor(args) -> int:
    rc, lines = doctor()
    for level, msg in lines:
        print(f"{level:4} {msg}")
    print(f"--- {'FAILURES PRESENT' if rc else 'no failures'} "
          f"(exit {rc})")
    return rc
