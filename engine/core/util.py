"""Shared helpers: sortable IDs, UTC timestamps, and tree-relative paths
(stdlib only, no deps)."""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit

KALI_CONTAINER = "kali-recon"
KALI_IMAGE = "localhost/kali-recon:20260919"


def motoko_root() -> Path:
    "Absolute path of the MOTOKO tree, derived from this file's location.\n\n    ``<root>/engine/core/util.py`` -> ``parents[2]`` == ``<root>``."
    return Path(__file__).resolve().parents[2]


def default_rules_dir() -> Path:
    """The bundled rule-pack directory, in either tree this file lives in.

    Source checkout: the corpus is ``<root>/engine/rules/``. Installed
    wheel: the packs ship as package data of the ``core.rules`` package,
    i.e. ``.../site-packages/core/rules/`` next to this file. The checkout
    wins when both exist, so a source tree beside an install never loads
    the install's stale copy. When neither holds a rules directory the
    source-layout path is returned anyway, so the caller's error names the
    canonical location rather than a site-packages path.
    """
    src = motoko_root() / "engine" / "rules"
    if src.is_dir():
        return src
    installed = Path(__file__).resolve().parent / "rules"
    if installed.is_dir():
        return installed
    return src

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


# Characters that would move an argv token boundary once `cmd.render_command`
# re-splits the rendered template with shlex. The values normalised below come
# from tool output — that is, from the target — so they are rebuilt from parsed
# components or refused outright, never passed through verbatim.
_SHELLY = frozenset(" \t\r\n'\"\\;|&$`<>")
# A bare `host[:port]`: the weakest shape still worth treating as a fetch
# target when no query value carries a scheme of its own.
_HOSTISH = re.compile(r"^[A-Za-z0-9._-]+(:\d{1,5})?$")


def ssrf_injection_point(url: str) -> tuple[str, str] | None:
    'Split a confirmed-SSRF endpoint into ``(base, param)``, or return None.\n\n    This is a normaliser, not a splitter. The base is rebuilt with `urlunsplit`\n    from parsed components (query and fragment dropped) and either half is\n    refused if it carries a character that would move a token boundary in the\n    rendered argv. Refusing is the cheap direction: an unsupplied slot leaves\n    the hypothesis unminted and visible on the board, while a mangled one\n    reaches the target.\n\n    Parameter choice is two-tier. A value carrying a scheme (`?url=http://…`,\n    what an SSRF template actually fires on) wins outright; failing that, a\n    bare `host[:port]` shape is accepted as the weakest usable guess. A\n    path-ish value (`?file=/etc/passwd`) is traversal rather than SSRF and is\n    skipped, so this never invents an injection point out of an LFI.\n    '
    text = str(url or "").strip()
    if not text:
        return None
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    base = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
    if any(c in _SHELLY for c in base):
        return None
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return None
    fallback: tuple[str, str] | None = None
    for name, value in pairs:
        if not name or any(c in _SHELLY for c in name):
            continue
        v = str(value or "").strip()
        if "://" in v or v.startswith("//"):
            return base, name
        if (fallback is None and v and "/" not in v
                and "." in v and _HOSTISH.match(v)):
            fallback = (base, name)
    return fallback


def utc_ms() -> int:
    return _millis()
