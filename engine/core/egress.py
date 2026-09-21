'Three code paths used to decide egress separately, reading two env vars with\ndifferent semantics and no shared truth:\n\nTwo axes, and they are not the same claim:\n\nSo this module answers the questions and reports both axes together\n(``summary()``); callers keep doing the IO. Nothing here sends traffic,\nresolves a name or reads a target.\n'

from __future__ import annotations

import os
import re

MODE_ENV = "MOTOKO_EGRESS_MODE"
PROXY_TOOLS_ENV = "MOTOKO_EGRESS_PROXY_TOOLS"
DIRECT_REPLAY_ENV = "MOTOKO_ALLOW_DIRECT_REPLAY"

PROXY, DIRECT = "proxy", "direct"

DEFAULT_PROXY_TOOLS = frozenset({"gau"})

HOST_PROXY_VARS = frozenset({"http_proxy", "https_proxy", "all_proxy"})

# Container path: `podman exec` carries the client env only via explicit
# `--env`, and a persistent container inherits its startup env, so every
# spelling has to be named and blanked.
CONTAINER_PROXY_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY",
                        "HTTPS_PROXY", "all_proxy", "ALL_PROXY")
CONTAINER_NO_PROXY_VARS = ("no_proxy", "NO_PROXY")

HOST_SECRET_NAME_RE = re.compile(
    r"KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH", re.IGNORECASE)
# SSH_AUTH_SOCK is a socket path, not a credential. Action credentials are
# added only AFTER stripping the host environment, including MOTOKO secrets.
HOST_SECRET_KEEP = frozenset({"SSH_AUTH_SOCK"})
# Name-shape misses an innocuous name carrying a key-shaped value; these are
# the token families this host actually circulates.
HOST_SECRET_VALUE_RE = re.compile(
    r"(?:sk-[A-Za-z0-9._-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}"
    r"|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,})")


def mode() -> str:
    '`proxy` (anonymity-first) or `direct` (legacy reachability mode).'
    if os.environ.get(MODE_ENV, "").strip().lower() == PROXY:
        return PROXY
    return DIRECT


def mode_declared() -> bool:
    """Whether `MOTOKO_EGRESS_MODE` carries a value at all."""
    return bool(os.environ.get(MODE_ENV, "").strip())


def proxy_tools() -> frozenset:
    """Tools allowed to keep the inherited proxy env in `direct` mode."""
    extra = os.environ.get(PROXY_TOOLS_ENV, "")
    if not extra.strip():
        return DEFAULT_PROXY_TOOLS
    return DEFAULT_PROXY_TOOLS | {n.strip() for n in extra.split(",")
                                  if n.strip()}


def tool_inherits_proxy(tool: str) -> bool:
    """Whether `tool` may keep the host's proxy environment."""
    if mode() == PROXY:
        return True
    return tool in proxy_tools()


def container_env_clears(tool: str) -> list[str]:
    """`podman exec` args blanking the proxy env for `tool` ([] if it keeps it).

    The list is empty rather than absent for a proxy-inheriting tool: gau must
    reach wayback through the proxy from inside the container too.
    """
    if tool_inherits_proxy(tool):
        return []
    clears: list[str] = []
    for var in CONTAINER_PROXY_VARS:
        clears += ["--env", f"{var}="]
    for var in CONTAINER_NO_PROXY_VARS:
        clears += ["--env", f"{var}=*"]
    return clears


def strip_host_proxy(env: dict) -> None:
    """Delete the proxy vars from a host child env, in place (direct-mode tools)."""
    for key in list(env):
        if key.lower() in HOST_PROXY_VARS:
            del env[key]


def strip_host_secrets(env: dict, *, strip_engine_secrets: bool = False) -> list[str]:
    'Delete credential-shaped host vars from a child base env, in place.'
    dropped: list[str] = []
    for key in list(env):
        if key in HOST_SECRET_KEEP or (key.startswith("MOTOKO_") and not strip_engine_secrets):
            continue
        value = env[key] if isinstance(env[key], str) else ""
        if (HOST_SECRET_NAME_RE.search(key)
                or HOST_SECRET_VALUE_RE.search(value)):
            del env[key]
            dropped.append(key)
    return dropped


def replay_asserted() -> bool:
    """Whether the deployment asserts its host route as the anonymous lane.

    The value crosses a process boundary, so it uses an explicit boolean
    vocabulary.  In particular, the host adapter must be able to send a
    false setting without accidentally turning the string ``"0"`` into a
    truthy Python value.  Unknown values fail closed.
    """
    value = os.environ.get(DIRECT_REPLAY_ENV, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def summary() -> dict:
    """Both axes, for reports. Doctor prints this; graph_health's park reason
    for `egress_policy` points at the same var names."""
    asserted = replay_asserted()
    if asserted:
        note = (f"replay egress asserted via {DIRECT_REPLAY_ENV} — the built-in "
                "fetcher will re-issue requests over this host's route")
    elif mode() == PROXY:
        note = (f"replay egress NOT asserted: {DIRECT_REPLAY_ENV} is unset, and "
                f"{MODE_ENV}=proxy does not imply it — tools ride the egress "
                "while the built-in replay fetcher still fails closed, so "
                "replay verdicts park as `egress_policy` instead of burning "
                "strikes. Assert it inside the verified anonymous lane, or "
                "inject a fetcher that egresses through the campaign proxy")
    else:
        note = (f"replay egress NOT asserted ({DIRECT_REPLAY_ENV} unset) — the "
                "built-in fetcher fails closed, so replay verdicts park as "
                "`egress_policy`. Do not assert it on a direct-egress host: "
                "that is exactly the residential-IP-in-target-logs case the internal doctrine "
                "forbids")
    return {
        "mode": mode(),
        "mode_declared": mode_declared(),
        "proxy_tools": sorted(proxy_tools()),
        "replay_asserted": asserted,
        "replay_note": note,
    }
