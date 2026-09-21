"""Shared helpers: sortable IDs, UTC timestamps, and tree-relative paths
(stdlib only, no deps)."""

from __future__ import annotations

import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit


_MISSING = object()

KALI_CONTAINER = "kali-recon"
KALI_IMAGE = os.environ.get("MOTOKO_KALI_IMAGE") or "localhost/kali-recon:latest"


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


def default_root_path() -> Path:
    """Resolve the live task root without importing the database layer."""
    value = os.environ.get("MOTOKO_HOME")
    return Path(value).expanduser() if value else motoko_root() / "tasks"


def tool_search_dirs(tools_root: Path | None = None) -> tuple[Path, ...]:
    """Return owner-local tool directories MOTOKO should search automatically.

    A service or gateway often starts with a deliberately small ``PATH``.  A
    scan should still find tools installed for the same account, without
    mutating the service unit or trusting a directory from the current
    working directory.  Explicit ``MOTOKO_TOOL_DIRS`` entries come first;
    then the conventional user bin, toolbox, Go and Cargo locations.  Missing
    directories are retained so callers can use the result to build a stable
    child ``PATH``; executable resolution still checks the file and execute
    bit before using an entry.

    The function is deliberately read-only and deployment-neutral.  It does
    not run ``go env``, source shell startup files, or write a profile.  A
    deployment can pin a different toolbox with ``MOTOKO_TOOLS`` and add
    owner-controlled directories with ``MOTOKO_TOOL_DIRS`` (``os.pathsep``
    separated).
    """
    home = Path.home()
    candidates: list[Path] = []

    configured = os.environ.get("MOTOKO_TOOL_DIRS", "")
    if configured:
        for raw in configured.split(os.pathsep):
            raw = raw.strip()
            if not raw:
                continue
            path = Path(raw).expanduser()
            # Relative search roots make a service depend on its working
            # directory and can accidentally select a checkout-local binary.
            if path.is_absolute():
                candidates.append(path)

    # Keep the historical wrapper directory first.  The remaining entries
    # cover the layouts used by Go/Cargo installers without requiring PATH to
    # be expanded by systemd, Telegram, or another host gateway.
    candidates.extend([
        home / ".local" / "bin",
        home / ".local" / "share" / "go" / "bin",
        home / ".local" / "go" / "bin",
        home / "go" / "bin",
        home / ".cargo" / "bin",
    ])

    gobin = os.environ.get("GOBIN", "").strip()
    if gobin:
        path = Path(gobin).expanduser()
        if path.is_absolute():
            candidates.append(path)
    gopath = os.environ.get("GOPATH", "")
    if gopath:
        for raw in gopath.split(os.pathsep):
            raw = raw.strip()
            if raw:
                path = Path(raw).expanduser()
                if path.is_absolute():
                    candidates.append(path / "bin")

    if tools_root is None:
        configured_root = os.environ.get("MOTOKO_TOOLS", "")
        tools_root = Path(configured_root).expanduser() if configured_root else (
            motoko_root() / "tools")
    candidates.extend([Path(tools_root) / "bin", Path(tools_root) / "nuclei"])

    result: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        try:
            key = str(path.resolve(strict=False))
        except OSError:
            key = str(path)
        if key not in seen:
            seen.add(key)
            result.append(path)
    return tuple(result)


def effective_path(path: str | None = None) -> str:
    """Prepend discovered tool directories to a child process ``PATH``.

    The caller's existing path remains intact and keeps its original order;
    only unique, absolute MOTOKO search roots are added ahead of it.  This is
    an in-memory value for a subprocess environment, never a shell/profile
    mutation.
    """
    base = path if path is not None else os.environ.get("PATH", "")
    parts = [str(p) for p in tool_search_dirs()]
    parts.extend(item for item in base.split(os.pathsep) if item)
    result: list[str] = []
    seen: set[str] = set()
    for item in parts:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return os.pathsep.join(result)


def adapt_local_environment() -> dict[str, str | object]:
    """Apply non-secret local defaults for the lifetime of one CLI process.

    This is the local-runtime bridge between portable configuration and the
    actual host process.  It fills only missing, derived values, prepends the
    discovered tool roots to ``PATH`` in memory, and returns the previous
    values so :func:`restore_local_environment` can undo the change when the
    CLI is embedded in a test or another Python process.  It never writes a
    profile, reads credential values, starts a service, or asserts an egress
    route.

    Explicit deployment variables always win.  The resulting environment is
    therefore suitable for a gateway with a minimal PATH while remaining
    relocatable on a fresh checkout or wheel install.
    """
    defaults = {
        "MOTOKO_HOME": str(default_root_path()),
        "MOTOKO_TOOLS": str(motoko_root() / "tools"),
        "MOTOKO_WORDLIST_DIR": str(Path("~/.motoko/wordlists").expanduser()),
    }
    previous: dict[str, str | object] = {}
    for key, value in defaults.items():
        if key in os.environ and os.environ[key]:
            continue
        previous[key] = os.environ.get(key, _MISSING)
        os.environ[key] = value
    current_path = os.environ.get("PATH", "")
    adapted_path = effective_path(current_path)
    if adapted_path != current_path:
        previous["PATH"] = current_path if "PATH" in os.environ else _MISSING
        os.environ["PATH"] = adapted_path
    return previous


def restore_local_environment(previous: dict[str, str | object]) -> None:
    """Restore the keys returned by :func:`adapt_local_environment`."""
    for key, value in previous.items():
        if value is _MISSING:
            os.environ.pop(key, None)
        else:
            os.environ[key] = str(value)

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
