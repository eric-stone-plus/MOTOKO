"""Shared helpers: sortable IDs, UTC timestamps, and tree-relative paths
(stdlib only, no deps)."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def motoko_root() -> Path:
    """Absolute path of the MOTOKO tree, derived from this file's location.

    ``<root>/engine/motoko/util.py`` -> ``parents[2]`` == ``<root>``.

    Deriving rather than hardcoding keeps the tree relocatable. The 2026-09-13
    move from ``private/network-audit/`` to
    ``private/agent-design/projects/motoko/`` silently broke every absolute
    path in this package (engagements root, tool search dirs), and the failure
    mode was an empty or absent directory rather than an exception — so nothing
    announced the breakage. Any new path default must go through here.
    """
    return Path(__file__).resolve().parents[2]

# Entity ID prefixes. One prefix per entity kind, so a bare ID is
# self-describing (mirrors the `kind` column; keep them in sync with
# schema.ENTITY_KINDS).
PREFIX = {
    "asset": "ast",
    "finding": "fnd",
    "hypothesis": "hyp",
    "evidence": "ev",
    "access": "acc",
    "path": "pth",
    "observation": "obs",
    "action": "act",
    "service": "srv",
    "tool_run": "run",
    "engagement": "eng",
}

_epoch = 0


def _millis() -> int:
    return int(time.time() * 1000)


def new_id(prefix: str) -> str:
    """Return a sortable, collision-safe ID: ``{prefix}_{ms}_{uuid8}``.

    Millisecond timestamp gives loose time-ordering (what ULID buys us)
    without any third-party dependency; the 8-hex UUID suffix keeps IDs
    unique across a burst within the same millisecond.
    """
    if prefix not in PREFIX.values():
        # Accept either a canonical short key ("finding") or a raw prefix.
        prefix = PREFIX.get(prefix, prefix)
    return f"{prefix}_{_millis()}_{uuid.uuid4().hex[:8]}"


def now_iso() -> str:
    """UTC ISO-8601 timestamp with microseconds, the canonical time format."""
    return datetime.now(timezone.utc).isoformat()


_CN_TWO_LABEL_SUFFIXES = ("com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn")


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (eTLD+1) without a public-suffix list.

    Chinese registries use two-label suffixes (.com.cn etc.); everything
    else assumes one-label TLD. Returns the original host when it already
    looks like a registrable domain.
    """
    host = str(host or "").strip().lower().rstrip(".")
    if not host or "." not in host:
        return host
    labels = host.split(".")
    for suffix in _CN_TWO_LABEL_SUFFIXES:
        if host.endswith("." + suffix) and len(labels) >= 3:
            return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def utc_ms() -> int:
    return _millis()
