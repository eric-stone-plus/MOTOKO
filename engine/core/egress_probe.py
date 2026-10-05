"""The egress exit-identity probe — the ONE module that opens a socket.

``core/egress.py`` owns the policy (env names, rotation math, and the pure
string judgement on the echo endpoint's shape) and stays IO-free by design;
everything that actually talks lives here, so "which code may send traffic"
stays answerable with one filename. Exactly one GET
against the operator-configured IP echo (``MOTOKO_EGRESS_ECHO_URL``, no code
default), through the CURRENT environment — lane vars are deliberately
untouched, because in lane mode the echo riding the egress like any tool
would IS the measurement.

No-traffic rule (fail closed): nothing in this module probes on read.
``fingerprint()``/``exit_ip()`` are pure cache lookups; an unknown is
reported as unknown. Only ``refresh()`` sends anything, and the only
callers sanctioned to invoke it are the orchestrator's lazy
first-tool_run establishment and its wave-boundary rotation hook.
One attempt, short timeout, never raises, never retries in-line.

The cache is per-process and deliberately not keyed by engagement: one
engine process runs one engagement, and a shared exit lane would be the
anomaly worth seeing in the log, not hiding.
"""

from __future__ import annotations

import json
import time
import urllib.request

from . import egress

# Short by design: this sits on the wave boundary, and a dead echo must not
# stall the loop for a default-socket timeout. One attempt, no retry.
DEFAULT_TIMEOUT_S = 8.0

# An echo answers in well under a KiB; the bound exists so a misconfigured
# URL pointing at a large body cannot pin the wave boundary's memory.
_MAX_BODY_BYTES = 65536

# Last SUCCESSFUL probe record (the "fingerprint"), and the time of the most
# recent refresh ATTEMPT whether or not it succeeded — the rotation hook
# reports both, and a failed attempt must not look like "never tried".
_CACHE: dict | None = None
_LAST_ATTEMPT_AT: float | None = None


plausible_ip = egress.plausible_ip


def probe_once(echo_url: str, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
    """Exactly one GET against ``echo_url``; never raises, never retries.

    Returns ``{"exit_ip": str|None, "echo": echo_url, "probed_at": <epoch
    float>, "asn": str|None, "country": str|None, "reason": str|None}``.
    ``probed_at`` is set on every attempt (success or failure); ``reason``
    is None only on a successful parse. An endpoint that cannot be probed at
    all is judged BEFORE the GET, on ``core/egress.echo_url_defect``, and
    comes back as a failed attempt with a reason naming the variable.
    Parsing: a JSON object body contributes its ip/asn/country keys when
    present; any other body's first
    non-empty line is treated as the bare exit IP. The parsed ip is trusted
    only when it is a plausible IPv4/IPv6 literal.
    """
    record: dict = {"exit_ip": None, "echo": echo_url, "probed_at": time.time(),
                    "asn": None, "country": None, "reason": None}
    defect = egress.echo_url_defect(echo_url)
    if defect:
        record["reason"] = f"{egress.ECHO_URL_ENV} unusable: {defect}"[:200]
        return record
    try:
        with urllib.request.urlopen(echo_url, timeout=timeout) as resp:
            body = resp.read(_MAX_BODY_BYTES).decode("utf-8", "replace")
    except Exception as exc:    # noqa: BLE001 - one attempt, never raises
        record["reason"] = f"{type(exc).__name__}: {exc}"[:200]
        return record

    candidate = None
    asn = None
    country = None
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if isinstance(data, dict):
        candidate = data.get("ip")
        asn = data.get("asn")
        country = data.get("country")
    if candidate is None:
        # Bare-text echo: the whole answer is the address on its first
        # non-empty line. A JSON object that carried no ip key lands here
        # too and then fails the plausibility check below — correct, since
        # a JSON body is not a bare-IP echo.
        candidate = next(
            (line.strip() for line in body.splitlines() if line.strip()), "")
    exit_ip = plausible_ip(candidate)
    if exit_ip is None:
        record["reason"] = "echo body carried no plausible exit ip"
        return record
    record["exit_ip"] = exit_ip
    if isinstance(asn, (str, int)) and str(asn).strip():
        record["asn"] = str(asn).strip()
    if isinstance(country, str) and country.strip():
        record["country"] = country.strip()
    return record


def refresh(echo_url: str, timeout: float = DEFAULT_TIMEOUT_S) -> dict:
    """Run one probe and cache it on success. Never raises.

    On failure the previous cache is KEPT — a dead echo must not erase the
    last known identity — and the failure stays visible in the record's
    ``reason`` so the caller can log it as an unknown-fingerprint with a
    cause rather than as silence.
    """
    global _CACHE, _LAST_ATTEMPT_AT
    record = probe_once(echo_url, timeout)
    _LAST_ATTEMPT_AT = record["probed_at"]
    if record.get("exit_ip"):
        _CACHE = dict(record)
    return record


def adopt(record) -> None:
    """Seed the per-process cache from a durable record. No traffic.

    The restart path: the deadline math already reads the engagement-side
    file, but every tool_run row stamps the CACHE's exit ip — a fresh
    process must re-adopt its own last measurement instead of stamping
    unknown for a full rotation window. A record without a plausible ip or
    a numeric ``probed_at`` is ignored, so a corrupt file cannot poison
    the cache. Does not touch ``_LAST_ATTEMPT_AT``: nothing was attempted.
    """
    global _CACHE
    if not isinstance(record, dict):
        return
    ip = plausible_ip(record.get("exit_ip"))
    at = record.get("probed_at")
    if ip is None or not isinstance(at, (int, float)) or isinstance(at, bool):
        return
    cached: dict = {"exit_ip": ip, "probed_at": float(at),
                    "asn": None, "country": None, "reason": None}
    echo = record.get("echo")
    if isinstance(echo, str) and echo.strip():
        cached["echo"] = echo
    for key in ("asn", "country"):
        value = record.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            cached[key] = str(value).strip()
    _CACHE = cached


def fingerprint() -> dict | None:
    """The cached fingerprint record, or None when none is established.

    NEVER probes and never reads the environment: an unknown is an unknown
    (fail closed, no silent traffic). Only ``refresh()`` sends anything.
    """
    return dict(_CACHE) if _CACHE is not None else None


def exit_ip() -> str | None:
    """The cached exit ip, or None when unknown. Pure read; no traffic."""
    cached = _CACHE
    return cached.get("exit_ip") if cached else None


def last_attempt_at() -> float | None:
    """Epoch seconds of the most recent refresh attempt, or None (never
    attempted in this process). Pure read; no traffic."""
    return _LAST_ATTEMPT_AT


def reset() -> None:
    """Drop the per-process probe state.

    Test seam first, but also the honest operation between engagements run
    by one long-lived process: a new engagement must not inherit the previous
    one's exit identity as its own measurement.
    """
    global _CACHE, _LAST_ATTEMPT_AT
    _CACHE = None
    _LAST_ATTEMPT_AT = None
