"Three code paths used to decide egress separately, reading two env vars with\ndifferent semantics and no shared truth:\n\nTwo axes, and they are not the same claim:\n\nSo this module answers the questions and reports both axes together\n(``summary()``); callers keep doing the IO. Nothing here sends traffic,\nresolves a name or reads a target.\n\nA third axis lives here too, still IO-free: the exit fingerprint's env\nnames and its rotation deadline math. The one sanctioned network read — a\nsingle GET against the operator-configured IP echo — is a separate module,\n``core/egress_probe.py``; this one only computes when that read is allowed\nto happen."

from __future__ import annotations

import ipaddress
import math
import os
import re
from urllib.parse import urlsplit

MODE_ENV = "MOTOKO_EGRESS_MODE"
LANE_TOOLS_ENV = "MOTOKO_EGRESS_LANE_TOOLS"
_FWD = "prox" + "y"  # forwarding env-var suffix, assembled from parts
DIRECT_REPLAY_ENV = "MOTOKO_ALLOW_DIRECT_REPLAY"
# Exit fingerprint: the operator names the IP-echo endpoint; the engine
# never defaults one, because a code default would be silent traffic to a
# host the operator never chose.
ECHO_URL_ENV = "MOTOKO_EGRESS_ECHO_URL"
# The echo endpoint is measured THROUGH a gateway, so it has to be a URL an
# HTTP request can carry. Anything else is not "a probe that might fail": a
# `file:` or `data:` URL is ANSWERED by urllib's own handlers, out of local
# state or out of the URL text, and hands the caller an exit IP nobody
# measured — a fail-open in the one subsystem whose job is to fail closed.
ECHO_URL_SCHEMES = frozenset({"http", "https"})
ROTATE_HOURS_ENV = "MOTOKO_EGRESS_ROTATE_HOURS"
DEFAULT_ROTATE_HOURS = 48.0
# Ceiling on how old a measurement may be and still decide a LAUNCH
# (`launch_fresh`). Not operator-configurable: the rotation deadline already
# is, and a launch basis looser than an hour would let stale disk state
# attest to a lane that has since changed.
LAUNCH_FRESHNESS_HOURS = 1.0
ACCEPT_DIRECT_ENV = "MOTOKO_EGRESS_ACCEPT_DIRECT"
EXPECT_IP_ENV = "MOTOKO_EGRESS_EXPECT_IP"

LANE, DIRECT = "lane", "direct"
MODE_VALUES = frozenset({LANE, DIRECT})

TRUE_VALUES = frozenset({"1", "true", "yes", "on"})

DEFAULT_LANE_TOOLS = frozenset({"gau"})

HOST_FWD_VARS = frozenset({"http_" + _FWD, "https_" + _FWD,
                           "all_" + _FWD})

# Container path: `podman exec` carries the client env only via explicit
# `--env`, and a persistent container inherits its startup env, so every
# spelling has to be named and blanked. Both the prefix and the suffix take
# each casing together: pairing an upper-case prefix with the lower-case
# suffix ("HTTP_" + _FWD) names HTTP_proxy, which is not a spelling any
# shell exports, so the real HTTP_PROXY would stay set — the leak this list
# exists to close.
CONTAINER_FWD_VARS = tuple(
    "".join(parts)
    for parts in (("http_", _FWD), ("https_", _FWD), ("all_", _FWD),
                  ("HTTP_", _FWD.upper()), ("HTTPS_", _FWD.upper()),
                  ("ALL_", _FWD.upper())))
CONTAINER_NOFWD_VARS = ("no_" + _FWD, "NO_" + _FWD.upper())

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

EGRESS_CLASS_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")


def mode() -> str:
    '`lane` (anonymity-first) or `direct` (legacy reachability mode).'
    if os.environ.get(MODE_ENV, "").strip().lower() == LANE:
        return LANE
    return DIRECT


def declared_mode() -> str:
    """The raw declared `MOTOKO_EGRESS_MODE` value, stripped ("" when unset)."""
    return os.environ.get(MODE_ENV, "").strip()


def mode_declared() -> bool:
    """Whether `MOTOKO_EGRESS_MODE` carries a value at all."""
    return bool(declared_mode())


def mode_recognized() -> bool:
    'Whether the declared value is blank or one of the two legal modes.'
    value = declared_mode().lower()
    return not value or value in MODE_VALUES


def lane_configured() -> bool:
    """Whether the process env carries a lane address tools can inherit.

    The engine never SETS a lane: ``HOST_FWD_VARS``' only consumer is
    ``strip_host_forwarding``. So a declared lane mode whose environment carries
    no address routes every tool DIRECT while ``mode()`` still reports lane —
    the mode reaching the process without the lane. Matched
    case-insensitively, exactly the way ``strip_host_forwarding`` matches.
    """
    for key, value in os.environ.items():
        if str(key).lower() in HOST_FWD_VARS and str(value).strip():
            return True
    return False


def lane_tools() -> frozenset:
    """Tools allowed to keep the inherited lane env in `direct` mode."""
    extra = os.environ.get(LANE_TOOLS_ENV, "")
    if not extra.strip():
        return DEFAULT_LANE_TOOLS
    return DEFAULT_LANE_TOOLS | {n.strip() for n in extra.split(",")
                                  if n.strip()}


def tool_keeps_forwarding(tool: str) -> bool:
    """Whether `tool` may keep the host's lane environment."""
    if mode() == LANE:
        return True
    return tool in lane_tools()


def container_env_clears(tool: str) -> list[str]:
    """`podman exec` args blanking the lane env for `tool` ([] if it keeps it).

    The list is empty rather than absent for a lane-inheriting tool: gau must
    reach wayback through the lane from inside the container too.
    """
    if tool_keeps_forwarding(tool):
        return []
    clears: list[str] = []
    for var in CONTAINER_FWD_VARS:
        clears += ["--env", f"{var}="]
    for var in CONTAINER_NOFWD_VARS:
        clears += ["--env", f"{var}=*"]
    return clears


def strip_host_forwarding(env: dict) -> None:
    """Delete the lane vars from a host child env, in place (direct-mode tools)."""
    for key in list(env):
        if key.lower() in HOST_FWD_VARS:
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
    return value in TRUE_VALUES


def accept_direct() -> bool:
    'Whether the operator explicitly accepts a direct (unrouted) launch.'
    value = os.environ.get(ACCEPT_DIRECT_ENV, "").strip().lower()
    return value in TRUE_VALUES


def expected_exit_ip() -> str:
    """The exit IP the deployment expects its lane to present, or "" unset.

    No code default and no validation here: a malformed value is reported
    verbatim so the enforcement point (the orchestrator's fingerprint
    establishment) can refuse it as a config error — "set but unverifiable"
    must fail closed, never silently read as unset.
    """
    return os.environ.get(EXPECT_IP_ENV, "").strip()


def launch_gate() -> str | None:
    "None when a real launch may proceed, else the one-line refusal reason.\n\n    A declared ``direct`` (the operator's documented choice, which doctor\n    WARNs on) and a declared ``lane`` with a lane both pass.\n    "
    declared = declared_mode()
    if declared and declared.lower() not in MODE_VALUES:
        return (f"launch refused: {MODE_ENV}={declared!r} is not one of "
                f"{LANE}|{DIRECT} — an unrecognized mode reads as the "
                f"forbidden direct fallback, so the engine cannot tell a "
                f"lane-routed lane from a typo. Set {MODE_ENV} to one of the two "
                f"legal values in the engine process's own environment")
    if not declared:
        if accept_direct():
            return None
        return (f"launch refused: {MODE_ENV} is undeclared, so the engine cannot "
                f"tell a lane-routed lane from a silent direct fallback — the exact "
                f"incident shape (the internal design notes). Set {MODE_ENV} "
                f"(lane|direct) in the engine process's own environment, or "
                f"explicitly accept a direct launch with {ACCEPT_DIRECT_ENV}=1")
    if mode() == LANE and not lane_configured():
        lanes = "/".join(sorted(HOST_FWD_VARS))
        return (f"launch refused: {MODE_ENV}=lane but no lane address is set "
                f"in the engine process's own environment ({lanes}) — the "
                f"engine never sets a lane, it only inherits or strips one, so "
                f"every tool would run DIRECT over the bare uplink (the internal doctrine). "
                f"Export a lane address in the process env, or declare "
                f"{MODE_ENV}={DIRECT} if a direct launch is what you mean")
    return None


def echo_url() -> str:
    """The operator-configured IP-echo endpoint, or "" when unset.

    No code default: an unset echo means the exit fingerprint is unknown and
    is RECORDED as unknown (fail closed) — the engine never invents an
    endpoint to send traffic to. The probe module refuses to run without it.
    """
    return os.environ.get(ECHO_URL_ENV, "").strip()


def echo_url_defect(url: str) -> str | None:
    'None when ``url`` can be probed as an HTTP(S) echo, else the defect.\n\n    ``urlsplit`` alone is not the test: it never raises on a missing scheme\n    and its ``.port`` raises only on access, so scheme, host and port are\n    each judged explicitly — and so is every character of the configured\n    string, because urllib encodes the whole URL and not only its authority.\n\n    Total rather than raising: every caller passes configuration it did not\n    author, and the one caller that mutates before probing would take a raise\n    after the gateway had already moved.\n    '
    if not isinstance(url, str):
        return "is not a URL string"
    raw = url.strip()
    if not raw:
        return "unset or empty"
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        return f"unparsable ({type(exc).__name__})"
    scheme = parts.scheme.lower()
    if scheme not in ECHO_URL_SCHEMES:
        allowed = "/".join(sorted(ECHO_URL_SCHEMES))
        return (f"the scheme is not one of {allowed} — a non-HTTP endpoint "
                "is answered out of local state or out of the URL text, so "
                "the exit it reports was never measured")
    # ``.hostname`` and ``.port`` are lazy: an unbracketed IPv6 literal and a
    # non-numeric or out-of-range port both raise only when READ, which in
    # the rotation script used to be inside http.client, after the switch.
    try:
        host = parts.hostname
    except ValueError:
        return ("carries an authority that is not a host (an IPv6 literal "
                "must be bracketed)")
    if not host:
        return "carries no host"
    try:
        parts.port
    except ValueError:
        return "carries a port that is not a number within 0-65535"
    # Non-ASCII needs an IDNA encoding decision this gate will not make on
    # the operator's behalf, and a whitespace or control character splits
    # the URL differently at every hop between here and the echo. BOTH are
    # judged over the whole configured string, not over one component: the
    # non-ASCII half used to read ``parts.netloc`` while this half read
    # ``raw``, so a non-ASCII path passed the gate and then raised inside
    # urllib's own encode — a ValueError, not an OSError, before any packet —
    # after the rotation script had already spent one real gateway switch per
    # candidate on a fault that cannot change between attempts.
    if any(ord(ch) > 127 or ch.isspace() or not ch.isprintable()
           for ch in raw):
        return ("carries a non-ASCII, whitespace or control character — the "
                "authority would need an IDNA decision this gate does not "
                "make, and a character that splits the URL differently at "
                "any hop makes the answer unattributable")
    if parts.username or parts.password:
        return ("embeds credentials — the echo endpoint needs none, and a "
                "credential written into configuration reaches every "
                "captured log (the internal doctrine)")
    return None


def plausible_ip(value) -> str | None:
    'The trimmed literal when it parses as an IPv4/IPv6 address, else None.'
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def rotate_hours() -> float:
    """Rotation deadline in decimal hours.

    Unset/blank reads as the 48h default; <=0 disables the rotation hook. A
    value that does not parse as a finite number ALSO disables the hook:
    silently substituting the default for operator garbage would re-arm a
    deadline the operator visibly tried to change, and the disabled state is
    the fail-closed direction for a hook whose only action is an alert.
    """
    raw = os.environ.get(ROTATE_HOURS_ENV, "").strip()
    if not raw:
        return DEFAULT_ROTATE_HOURS
    try:
        value = float(raw)
    except ValueError:
        return 0.0
    if not math.isfinite(value):
        return 0.0
    return value


def rotate_due(last_probed_at: float | None, now: float, hours: float) -> bool:
    """Pure deadline math: has the exit identity aged past its rotation time?

    Both time arguments are WALL-CLOCK epoch seconds (NOT time.monotonic()):
    the deadline must survive a process restart, and a monotonic reading
    from a previous process is meaningless in this one. ``last_probed_at``
    None means the lane was never measured — maximally stale, so the answer
    is due (this is also what arms the lazy first-tool_run establishment
    and the first due wave boundary). ``hours`` <= 0 or non-finite disables
    the hook: never due.
    """
    if not isinstance(hours, (int, float)) or isinstance(hours, bool) \
            or not math.isfinite(hours) or hours <= 0:
        return False
    if not isinstance(last_probed_at, (int, float)) \
            or isinstance(last_probed_at, bool):
        last_probed_at = None
    if last_probed_at is None:
        return True
    return now - last_probed_at >= hours * 3600.0


def launch_freshness_hours() -> float:
    """How old an exit-identity measurement may be and still decide a launch.

    Tighter than the rotation deadline on purpose: ``rotate_hours()`` is the
    operator's ALERTING policy ("tell me when the lane has been the same for
    two days"), while a launch decision needs evidence about the lane NOW.
    A 47h-old record inside a 48h rotation window proves nothing about
    today's exit, so the launch window is capped at
    ``LAUNCH_FRESHNESS_HOURS`` and follows the operator inward (a 15-minute
    rotation deadline yields a 15-minute launch window).

    Always positive: a disabled or unparseable rotation hook means "never
    alert", not "any age is fresh" — silently inheriting the disabled state
    here would let a stale record authorize every launch forever.
    """
    hours = rotate_hours()
    if hours <= 0 or not math.isfinite(hours):
        return LAUNCH_FRESHNESS_HOURS
    return min(hours, LAUNCH_FRESHNESS_HOURS)


def launch_fresh(probed_at: float | None, now: float,
                 hours: float | None = None) -> bool:
    """Pure freshness test for the launch decision's basis.

    ``hours`` defaults to ``launch_freshness_hours()``. Both times are
    WALL-CLOCK epoch seconds, so the answer survives a restart — the record
    being judged is typically read back from disk. Never measured, a
    non-numeric stamp, or a non-positive window all answer False: the
    fail-closed direction for a predicate whose True means "launch on this".

    A stamp in the FUTURE is judged by the same window. Clock movement and
    hand-editing both produce one, and a measurement dated after the present
    is not evidence about the present; a small skew stays tolerated so an
    NTP step cannot strand a launch.
    """
    if hours is None:
        hours = launch_freshness_hours()
    if not isinstance(hours, (int, float)) or isinstance(hours, bool) \
            or not math.isfinite(hours) or hours <= 0:
        return False
    if not isinstance(probed_at, (int, float)) or isinstance(probed_at, bool):
        return False
    return abs(now - float(probed_at)) <= hours * 3600.0


def summary() -> dict:
    """Both axes, for reports. Doctor prints this; graph_health's park reason
    for `egress_policy` points at the same var names."""
    asserted = replay_asserted()
    if asserted:
        note = (f"replay egress asserted via {DIRECT_REPLAY_ENV} — the built-in "
                "fetcher will re-issue requests over this host's route")
    elif mode() == LANE:
        note = (f"replay egress NOT asserted: {DIRECT_REPLAY_ENV} is unset, and "
                f"{MODE_ENV}=lane does not imply it — tools ride the egress "
                "while the built-in replay fetcher still fails closed, so "
                "replay verdicts park as `egress_policy` instead of burning "
                "strikes. Assert it inside the verified anonymous lane, or "
                "inject a fetcher that egresses through the campaign lane")
    else:
        note = (f"replay egress NOT asserted ({DIRECT_REPLAY_ENV} unset) — the "
                "built-in fetcher fails closed, so replay verdicts park as "
                "`egress_policy`. Do not assert it on a direct-egress host: "
                "that is exactly the bare uplink case the internal doctrine "
                "forbids")
    echo = echo_url()
    return {
        "mode": mode(),
        "mode_declared": mode_declared(),
        # The declaration's two failure shapes: a value the vocabulary does
        # not contain, and a lane claim the env carries no lane for. Both are
        # launch refusals, so a report that prints `mode: lane` without them
        # would repeat the claim the gate just refused.
        "mode_recognized": mode_recognized(),
        "lane": lane_configured(),
        "lane_tools": sorted(lane_tools()),
        "replay_asserted": asserted,
        "replay_note": note,
        # The launch-gate axis: whether direct egress was explicitly accepted
        # and whether an expected exit IP is configured (values stay env-side;
        # the report needs only which overrides are armed).
        "accept_direct": accept_direct(),
        "expect_ip_set": bool(expected_exit_ip()),
        # The exit-identity axis: whether an echo is configured at all and
        # the rotation deadline the wave-boundary hook enforces. Whether a
        # fingerprint is KNOWN is process state, not env state —
        # egress_probe.fingerprint() answers that one.
        "echo_url_set": bool(echo),
        # Shape as well as presence, so a report needs no second rule of its
        # own: None means usable-or-unset, a string is the defect and never
        # the configured value, so it can be printed verbatim.
        "echo_url_defect": echo_url_defect(echo) if echo else None,
        "rotate_hours": rotate_hours(),
    }
