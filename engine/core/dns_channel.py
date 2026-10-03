"""The DNS resolver channel — the engine never edits the system resolver.

A tool that runs DIRECT (forwarding vars stripped) resolves target domains
through whatever the host resolver is — usually the ISP's — which hands the
operator's provider the engagement's full query list. The channel is one
env var: the operator points the engine at a resolver, and the executor
APPENDS the tool's own resolver flag at spawn.

Doctrine:

* the engine never touches ``/etc/resolv.conf`` or any other system resolver
  setting — that would leak past the process boundary and persist after the
  engagement ends;
* a URL spec (``https://doh.example/dns-query``) is not something nmap or
  subfinder can consume. It assumes an operator-run local forwarder
  (dnslane, smartdns) fronting that URL; the engine only points tools at
  ``MOTOKO_DNS_LOCAL_ADDR`` (default loopback). Running the forwarder is the
  operator's job — the engine never starts one.

This is the policy half, IO-free by the same split as ``core/egress.py`` vs
``core/egress_probe.py``: env names, spec resolution and the pure argv
injection live here; the one sanctioned socket read for this feature (the
local-forwarder reachability probe) belongs to doctor's check. Nothing in
this module opens a socket, resolves a name or reads a target.
"""

from __future__ import annotations

import ipaddress
import os

resolver_env = "MOTOKO_DNS_RESOLVER"
local_addr_env = "MOTOKO_DNS_LOCAL_ADDR"

# Where a URL spec's local forwarder is expected unless the operator says
# otherwise. A code default is fine here: it names no endpoint and sends no
# traffic — it is only the address tools are pointed at when the operator
# already chose a URL resolver.
DEFAULT_LOCAL_ADDR = "127.0.0.1"

# The only tools whose resolver flag semantics are actually known (v1).
# subfinder/amass take `-r <resolvers>`, nmap takes `--dns-servers
# <servers>`. A tool outside the map is never guessed at: a wrong flag is a
# tool error charged to the (rule, asset) pair, exactly the miss a
# hardcoded "every tool gets -r" map would produce.
RESOLVER_FLAGS = {
    "subfinder": "-r",
    "amass": "-r",
    "nmap": "--dns-servers",
}

# The only flag whose grammar takes BARE servers, no host:port. nmap
# silently disables reverse DNS (stderr warning only) when handed a port
# suffix — invisible to the executor's exit-code contract and exactly the
# shape a `detected`-classifier risk is made of.
_BARE_SERVER_FLAGS = frozenset({"--dns-servers"})

# The characters a resolver list is spelled with. A short option may glue its
# value onto the flag, and the glued remainder is the only way to tell that
# spelling from a neighbour flag that merely starts with the same letter
# (``-rl``/``-rls``/``-rsr``/``-rlist``/``-recursive`` all share ``-r``).
_ADDRESS_CHARS = frozenset("0123456789abcdefABCDEF.,:")
_ASCII_DIGITS = frozenset("0123456789")


def _valid_port(text: str) -> bool:
    """True for an ASCII-digit port inside doctor's ``0 < port < 65536``.

    ``str.isdigit()`` alone is True for a non-ASCII digit form, which then
    either raises out of ``int()`` or silently reads as a different port.
    """
    return (bool(text) and all(c in _ASCII_DIGITS for c in text)
            and 0 < int(text) < 65536)


def _bare_server(addr: str) -> str:
    """``addr`` as a BARE server for a host-only grammar, or "" if malformed.

    Bracketed IPv6 (``[::1]:5353`` -> ``[::1]``) and the one-colon host:port
    split mirror doctor's endpoint parsing — same bracket and colon-count
    disambiguation, same ``0 < port < 65536`` range — and a bare IPv6 literal
    (two or more colons, no brackets) is a host and passes through. Where
    doctor falls back to a default port for an unparsable value, this rejects
    it and returns "": a port tail that is not a port (``192.0.2.10:5353abc``,
    ``[::1]5353``, ``192.0.2.10:5353:9``) is not strippable without guessing
    which half the operator meant, and forwarding the guess is what makes the
    tool drop this channel on a stderr warning the executor's exit-code
    contract never sees. The caller then injects nothing, so the fault stays
    where the operator can read it — the spec doctor's DNS axis prints —
    instead of inside a spawned argv.
    """
    host = addr.strip()
    if not host or any(c.isspace() for c in host):
        return ""
    if host.startswith("["):
        if "]" not in host:
            return ""
        inside, _, rest = host[1:].partition("]")
        if not inside:
            return ""
        if not rest:
            return f"[{inside}]"
        if rest.startswith(":") and _valid_port(rest[1:]):
            return f"[{inside}]"
        return ""
    if host.count(":") == 1:
        left, _, right = host.partition(":")
        return left if left and _valid_port(right) else ""
    if ":" in host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return ""
    return host


def _resolver_flag_rendered(flag: str, argv: list[str]) -> bool:
    """True when ``argv`` already carries ``flag`` in FLAG position.

    Membership is not a role test: in ``["subfinder", "-d", "x", "-o", "-r"]``
    the ``-r`` is ``-o``'s VALUE, and reading it as a rendered resolver flag
    leaves the run on the host resolver. An occurrence counts when the flag
    has a value after it (the split spelling), when a long flag carries
    ``=value``, or when a SHORT flag has an address-shaped value glued to it —
    a value-bearing flag is never the last token, and a glued remainder
    counts only when it reads as a resolver list, never when it reads as the
    rest of a longer flag name.
    """
    short = flag.startswith("-") and not flag.startswith("--")
    for i, token in enumerate(argv):
        if token == flag:
            nxt = argv[i + 1] if i + 1 < len(argv) else ""
            if nxt and not nxt.startswith("-"):
                return True
        elif token.startswith(flag + "="):
            return True
        elif short and token.startswith(flag):
            rest = token[len(flag):]
            if rest and all(c in _ADDRESS_CHARS for c in rest) \
                    and any(c in _ASCII_DIGITS for c in rest):
                return True
    return False


def configured() -> str:
    """The stripped resolver spec, or "" when unset or blank."""
    return os.environ.get(resolver_env, "").strip()


def tool_resolver_addr() -> str | None:
    """The address a tool receives, or None when no resolver is configured.

    A URL spec (contains ``://``, DoH/DoT) resolves to the local forwarder's
    address — ``MOTOKO_DNS_LOCAL_ADDR``, defaulting to loopback, never to the
    URL itself. Anything else is passed through unchanged: the operator
    configured a plain address, and the tool gets exactly that address.
    """
    spec = configured()
    if not spec:
        return None
    if "://" in spec:
        local = os.environ.get(local_addr_env, "").strip()
        return local or DEFAULT_LOCAL_ADDR
    return spec


def inject_args(tool: str, argv: list[str]) -> list[str]:
    """A NEW argv with ``tool``'s resolver flag appended, or a copy of argv.

    ``[flag, addr]`` is appended only when ALL hold: ``tool`` is in the flag
    map, a resolver is configured, the flag does not already occur in
    ``argv`` in FLAG position (``_resolver_flag_rendered`` — a rule that
    rendered its own resolver flag never gets a second one), and, for a
    bare-server flag, the configured address survives validation. Bare-server
    flags (nmap's) receive the address with any ``:port`` stripped: the local
    forwarder's port is for the doctor probe, not for a grammar that takes
    hosts only — and an address that grammar cannot take is dropped rather
    than forwarded, since the failure it causes is invisible to the
    exit-code contract.
    Pure: the input is never mutated and the result is always a fresh list.
    The lane and container gates stay with the caller (the executor): a
    lane-inheriting tool resolves at the egress, and the container route
    takes no resolver flags at all.
    """
    out = list(argv)
    flag = RESOLVER_FLAGS.get(tool)
    addr = tool_resolver_addr()
    if not flag or addr is None or not out:
        return out
    if _resolver_flag_rendered(flag, out):
        return out
    if flag in _BARE_SERVER_FLAGS:
        addr = _bare_server(addr)
        if not addr:
            return out
    return [*out, flag, addr]
