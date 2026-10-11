"Tool stall watchdog — kill a spinning run before its full timeout.\n\nThe signature is deliberately narrow, so a legitimate heavy run is never cut:\na run is judged stuck only when it burns ~a full core AND holds no network file\ndescriptor for ``stall_after`` seconds. A tool that is talking (a socket fd) or\nthat is blocked/idle (near-zero CPU) is left alone. When the fd state cannot be\nread (a foreign uid's /proc), the sample is treated as UNKNOWN and the run is\nnever flagged — the watchdog is a bonus, not the guarantee; the executor's\n``timeout`` wrapper remains the hard bound.\n\nPolicy and the /proc readers live here; the executor only decides which pids to\nwatch (its own process tree on the host route; the container's pids on the\ncontainer route) — the same split as ``core/egress.py`` vs ``core/egress_probe``.\n"

from __future__ import annotations

import os
import time

# Seconds of "no network fd while burning CPU" before a run is judged stuck.
# 0 disables the watchdog; a negative/unparsable value keeps the default
# rather than silently switching a safety net off.
STALL_AFTER_ENV = "MOTOKO_TOOL_STALL_S"
DEFAULT_STALL_AFTER_S = 120.0
# Fraction of ONE core. The observed spin sits at ~100%; a legitimately busy
# single-threaded tool also sits near 100% — the discriminator is the fd, not
# this, which is why the threshold may sit well below 1.0.
SPIN_CPU_FRACTION = 0.75
# Minimum gap between samples; the capture loop calls poll() far more often.
SAMPLE_INTERVAL_S = 4.0

_CLK_TCK = os.sysconf("SC_CLK_TCK")


def stall_after_s() -> float:
    """Seconds of no-I/O full-CPU before a run is judged stuck (0 disables)."""
    raw = os.environ.get(STALL_AFTER_ENV, "").strip()
    if not raw:
        return DEFAULT_STALL_AFTER_S
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_STALL_AFTER_S
    return value if value >= 0 else DEFAULT_STALL_AFTER_S


def cpu_seconds(pids) -> float:
    """Sum of utime+stime (seconds) over ``pids``; unreadable pids add 0."""
    total = 0.0
    for pid in pids:
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                data = fh.read().decode("ascii", "replace")
        except OSError:
            continue
        # comm may contain spaces and parens: measure from the LAST ')'.
        try:
            rest = data[data.rindex(")") + 2:].split()
            total += (int(rest[11]) + int(rest[12])) / _CLK_TCK
        except (ValueError, IndexError):
            continue
    return total


def has_net_fd(pids) -> bool | None:
    """True if any of ``pids`` holds a socket fd; None if that cannot be read.

    None is "unknown", not "no socket": a foreign uid's ``/proc/<pid>/fd`` is
    unreadable, and reading a permission error as "no network" would let the
    watchdog kill a working run. The caller treats None as progress.
    """
    for pid in pids:
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            return None
        for fd in fds:
            try:
                if os.readlink(f"/proc/{pid}/fd/{fd}").startswith("socket:"):
                    return True
            except OSError:
                continue
    return False


def descendant_pids(pid: int) -> list[int]:
    """``pid`` plus every live descendant (via /proc/<pid>/task/*/children)."""
    if pid <= 0:
        return []
    out = [pid]
    seen = {pid}
    stack = [pid]
    while stack:
        cur = stack.pop()
        try:
            tasks = os.listdir(f"/proc/{cur}/task")
        except OSError:
            continue
        for task in tasks:
            try:
                with open(f"/proc/{cur}/task/{task}/children") as fh:
                    kids = fh.read().split()
            except OSError:
                continue
            for kid in kids:
                try:
                    k = int(kid)
                except ValueError:
                    continue
                if k not in seen:
                    seen.add(k)
                    out.append(k)
                    stack.append(k)
    return out


class StallWatch:
    """Sample a run's CPU and network-fd state; decide when it is stuck.

    ``pids_fn`` returns the pids to watch. ``poll()`` is cheap and
    self-throttling — call it every capture-loop iteration; it samples at most
    once per ``sample_interval``. ``now`` is injectable for tests.
    """

    def __init__(self, pids_fn, *, stall_after: float | None = None,
                 sample_interval: float | None = None, now=time.monotonic):
        self._pids_fn = pids_fn
        self._stall_after = stall_after_s() if stall_after is None else stall_after
        self._interval = (SAMPLE_INTERVAL_S if sample_interval is None
                          else sample_interval)
        self._now = now
        self._last_sample: float | None = None
        self._last_cpu: float | None = None
        self._no_net_since: float | None = None
        self.stalled = False

    def enabled(self) -> bool:
        return self._stall_after > 0

    def poll(self) -> bool:
        if not self.enabled() or self.stalled:
            return self.stalled
        t = self._now()
        if self._last_sample is not None and t - self._last_sample < self._interval:
            return False
        try:
            pids = list(self._pids_fn())
        except Exception:      # noqa: BLE001 - a probe must never break exec
            pids = []
        if not pids:
            # Nothing to watch (container gone, or no permission): stay
            # neutral and keep the previous baseline from going stale.
            self._last_sample = t
            return False
        net = has_net_fd(pids)
        if net is None or net:
            # Progress (a socket) or state we cannot read: never flag.
            self._no_net_since = None
            self._last_cpu = cpu_seconds(pids)
            self._last_sample = t
            return False
        cpu = cpu_seconds(pids)
        if self._last_cpu is not None:
            dt = max(1e-6, t - self._last_sample)
            if (cpu - self._last_cpu) / dt >= SPIN_CPU_FRACTION:
                if self._no_net_since is None:
                    self._no_net_since = t
                elif t - self._no_net_since >= self._stall_after:
                    self.stalled = True
            else:
                # No socket but also not burning CPU: blocked or waiting —
                # not the spin we guard against.
                self._no_net_since = None
        self._last_cpu = cpu
        self._last_sample = t
        return self.stalled
