"""Toolchain ownership: where tools live, and which uid spawns them.

This module is the ONE place that answers two coupled questions the engine
used to answer implicitly:

1. **Where does a tool binary come from?** Section 5.5's resolution order
   (``~/.local/bin`` -> ``$MOTOKO_TOOLS`` -> PATH) was written for a deploy
   host whose toolbox sat inside the operator's home. That layout cannot be
   combined with privilege separation: a child that drops to an unprivileged
   uid cannot traverse ``/home/<operator>`` when it is 0700, so a toolbox
   pinned under the operator's home is unreachable from the exact identity
   that is supposed to run it.

2. **Which identity spawns the tool?** Before this module the executor
   spawned every scan tool as its own uid (``core/executor.py``'s bare
   ``Popen``). An engine that runs as the operator therefore handed every
   third-party scanner the operator's full session: a scanner exploit, or a
   merely hostile tool, inherited the operator's 0600 credential stores and
   every other readable secret on the host.

The layout that satisfies both is a **system-wide tool root** outside any
home (``/opt/motoko-tools``), world-readable and owner-writable only by
root, combined with a **drop of the spawned child to a dedicated
unprivileged account** (``motoko-anon`` by default). The two belong in one
module because a change to one without the other silently produces a
toolbox the running identity cannot see: the separation is only real when
the identity that execs a binary can also read it.

Design rules
------------

* **The engine process and the tool process have different identities.**
  The engine reads the graph, holds the LLM key and writes evidence; the
  tool only talks to targets. Dropping the TOOL is the point; the engine is
  not moved.
* **The drop is fail-closed at the boundary.** When the engine runs as root
  it MUST drop; a resolvable target account that cannot be looked up is a
  hard refusal, never a silent fall-through to spawning as root. When the
  engine already runs AS the target account the spawn is correct with no
  drop. When the engine runs as some third, non-root uid, privilege
  separation is impossible and the condition is reported (``isolation_status``)
  rather than faked — the caller decides whether that is acceptable, and
  ``doctor`` surfaces it.
* **Nothing here sends traffic, reads a target or opens a socket.** It
  resolves paths and identities, and hands the executor the one callable it
  needs to drop privileges in a forked child.

The credential-transport fd set (``core/secret_transport.py``) is unaffected
by the drop: those fds are opened by the parent and inherited across exec, so
a secret still never touches argv and the child reads it through
``/proc/self/fd/N`` under the dropped uid.
"""

from __future__ import annotations

import os
import pwd
import shutil
from pathlib import Path

# The system-wide tool root. Outside every home so a dropped child can read
# it; root-owned and world-readable so only the operator can modify what the
# dropped child executes. MOTOKO_TOOLS still overrides (Section 5.4's
# configuration layering), which is what a self-hosted test tree uses.
DEFAULT_TOOL_ROOT = Path("/opt/motoko-tools")

DEFAULT_TOOL_USER = "motoko-anon"
TOOL_USER_ENV = "MOTOKO_TOOL_USER"
TOOL_ROOT_ENV = "MOTOKO_TOOLS"


class IsolationError(RuntimeError):
    """A spawn that must be isolated cannot be. Fail-closed, never spawn."""


def tool_root() -> Path:
    """The directory that holds the toolbox (%s overrides)."""
    configured = os.environ.get(TOOL_ROOT_ENV, "").strip()
    if configured:
        return Path(configured).expanduser()
    return DEFAULT_TOOL_ROOT


def tool_user_name() -> str:
    """The account name spawned tools drop to."""
    return os.environ.get(TOOL_USER_ENV, "").strip() or DEFAULT_TOOL_USER


def _lookup(name: str) -> pwd.struct_passwd | None:
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def drop_target() -> tuple[int, int] | None:
    """``(uid, gid)`` to drop to, or None when the engine already IS that uid.

    Returns None in two distinct situations the caller must not conflate:
    the engine already runs as the target account (nothing to do), and the
    target account does not exist. ``isolation_status`` distinguishes them;
    this function is the mechanical half used by the child.
    """
    record = _lookup(tool_user_name())
    if record is None:
        return None
    if record.pw_uid == os.geteuid():
        return None
    return (record.pw_uid, record.pw_gid)


def isolation_status() -> tuple[str, str]:
    '``(state, detail)`` describing whether the next spawn will be isolated.\n\n    States, most-isolated first:'
    name = tool_user_name()
    record = _lookup(name)
    euid = os.geteuid()
    if record is None:
        return ("absent", f"account {name!r} not found; no drop possible")
    if euid == record.pw_uid:
        return ("native", f"engine already runs as {name}")
    if euid == 0:
        return ("enforced", f"root engine will drop children to {name}")
    return ("unenforced",
            f"engine runs as uid {euid}, not root and not {name}; "
            f"children cannot be dropped (run the engine as root, or as {name})")


def preexec_drop():
    """A ``preexec_fn`` that drops a forked child to the tool account, or None.

    Called in the child after ``fork`` and before ``exec``. It runs as root
    (that is the only way to reach the setuid syscalls), so ordering matters:
    ``setgroups`` first — once the effective uid is gone the process can no
    longer change its supplementary groups — then ``setgid``, then ``setuid``.
    ``PR_SET_NO_NEW_PRIVS`` is set last so a setuid bit on any binary the
    child execs cannot be used to regain privileges.

    Returns None when no drop applies or is possible:

    * the engine already runs AS the target account (children are already
      that identity), or
    * the target account is absent, or
    * the engine is not root. This last case is load-bearing: ``setuid``
      fails in the forked child with EPERM, which Python surfaces as
      ``SubprocessError: Exception occurred in preexec_fn`` and aborts the
      spawn. A non-root engine has no privilege to shed, so returning None
      (spawn normally) is both the only thing that works and the correct
      thing — ``isolation_status`` reports the degraded posture separately.
    """
    if os.geteuid() != 0:
        return None
    target = drop_target()
    if target is None:
        return None
    uid, gid = target

    def _drop() -> None:      # pragma: no cover - runs in the forked child
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        try:
            import ctypes

            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            PR_SET_NO_NEW_PRIVS = 38
            libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        except Exception:
            pass

    return _drop


def assert_can_spawn() -> None:
    'Raise when a spawn that MUST be isolated cannot be.'
    state, detail = isolation_status()
    if state in ("enforced", "native"):
        return
    if os.geteuid() == 0:
        raise IsolationError(
            f"refusing to spawn a scan tool as root: {detail}. "
            f"Create the account or set {TOOL_USER_ENV} to an existing one.")
    # A non-root engine cannot setuid; there is no drop to enforce. Proceed,
    # but the condition is visible through isolation_status()/doctor.


def _extra_search_dirs(root: Path) -> tuple[Path, ...]:
    """Tool directories under ``root``, most specific first.

    Kept beside the resolver so a layout change is one edit: ``bin/`` holds
    the Go/Cargo binaries and the wrapper scripts, ``nuclei/`` the pinned
    template engine's own layout, matching Section 6.2's invocation shapes.
    """
    return (root / "bin", root / "nuclei")


def search_dirs(root: Path | None = None) -> tuple[Path, ...]:
    """Every directory a tool binary may be resolved from, in precedence order.

    The system-wide root comes FIRST: it is the only location guaranteed
    readable by the dropped uid, so preferring it keeps resolution and
    execution identities aligned. After it come the retained owner-local
    layouts (``~/.local/bin`` and the Go/Cargo roots) so a self-hosted
    checkout that has not yet migrated its toolbox still resolves — a
    deployment mid-migration must not go dark.
    """
    base = util_tool_search_dirs(root)
    return base


def util_tool_search_dirs(root: Path | None = None) -> tuple[Path, ...]:
    """``util.tool_search_dirs`` with the toolchain root prepended.

    Imported lazily so this module stays importable without the rest of the
    package (doctor and provision.sh both reach for it early).
    """
    from . import util

    target = root if root is not None else tool_root()
    ordered: list[Path] = []
    seen: set[str] = set()

    def _add(path: Path) -> None:
        key = str(path)
        if key not in seen:
            seen.add(key)
            ordered.append(path)

    for path in _extra_search_dirs(target):
        _add(path)
    for path in util.tool_search_dirs(target):
        _add(path)
    return tuple(ordered)


def resolve_tool(tool: str, extra_dirs: tuple[Path, ...] = ()) -> str | None:
    """Absolute path to ``tool``, or None. Mirrors ``executor.resolve_tool``.

    Same refusal of path-shaped names (``/``, ``\\``, ``..``): the action's
    ``tool`` field is a bare binary name. ``extra_dirs`` keeps their
    historical precedence ahead of the search roots.

    NOTE the identity: ``os.access`` answers for the CALLER (the engine's
    uid). Since scan tools are dropped to a separate account, a hit here is
    not proof the process that will exec it can reach it — see
    :func:`reachable_by_drop_target`, which doctor's isolation axis uses to
    close that gap.
    """
    if not isinstance(tool, str) or not tool:
        return None
    if "/" in tool or "\\" in tool or ".." in tool:
        return None
    for d in (*extra_dirs, *search_dirs()):
        p = Path(d) / tool
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return shutil.which(tool) or None


def reachable_by_drop_target(path: str | Path) -> bool | None:
    'Can the DROPPED identity read and execute ``path``?\n\n    Returns None when there is no drop to check (the engine already runs as\n    the tool account, or the account is absent) — the caller must treat that\n    as "not applicable", never as False.\n\n    Checks permission BITS rather than calling ``os.access``, which can only\n    speak for the current process: the child\'s outcome depends on its euid,\n    its egid and (after ``setgroups([])``) NO supplementary groups, plus the\n    traverse bit on every parent directory. That is exactly modelled by\n    ``other``/``group``/``owner`` bits against the target uid/gid.\n    '
    target = drop_target()
    if target is None:
        return None
    uid, gid = target
    p = Path(path)

    def _can(st) -> bool:      # type: ignore[no-untyped-def]
        if st.st_uid == uid:
            bits = (st.st_mode >> 6) & 0o7
        elif st.st_gid == gid:
            bits = (st.st_mode >> 3) & 0o7
        else:
            bits = st.st_mode & 0o7
        return (bits & 0o5) == 0o5      # r-x

    try:
        st = p.stat()
    except OSError:
        return False
    if not _can(st):
        return False
    # Every parent needs the traverse bit; /home/<operator> at 0700 is the
    # usual blocker and the one this function exists to name.
    for parent in p.parents:
        try:
            pst = parent.stat()
        except OSError:
            return False
        if not _can(pst):
            return False
    return True
