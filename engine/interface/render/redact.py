"""Redaction helpers — the interface's P5 doctrine, in one place.

Every string that leaves a collector toward the UI passes through here.
Design rules (design/DESIGN.md section 9):

- never render raw target identifiers: hosts/domains/IPs/URLs are masked to a
  stable short label so tables stay diffable without leaking the target;
- finding/credential text renders only as a fingerprint prefix (<=8 hex) +
  last 3 chars, never the content;
- ``obs/*.out|*.err`` captures are NEVER read by any collector, so they cannot
  leak through this module.

stdlib-only. No I/O here by design: pure string shaping, trivially testable.
"""

from __future__ import annotations

import hashlib
import re

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{8}", re.IGNORECASE)
_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"']+")
#: Bare hostname/domain (>=1 dot, alphabetic TLD, optional port). Version
#: strings ("1.2.3", "v2.1") and underscore words never match: the final
#: label must be pure alpha. The boundary classes are ASCII word chars only:
#: ``\w`` also matches CJK, which let a host wedged between adjacent CJK
#: characters — a domain glued into a run of non-ASCII prose — leak whole.
#: A sentence-final dot stays in place (the
#: trailing lookahead excludes word chars and hyphens only). Applied to
#: FREE TEXT only — never to engine vocabulary such as dotted event kinds
#: (those stay out of redact_text, see collectors/graph.py event_summary).
_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,24}(?::\d{1,5})?"
    r"(?![A-Za-z0-9-])"
)
#: IPv4 literal (validated octets) with optional port; a sentence-final dot
#: stays in place. The lookarounds keep "v1.2.3.4" and dotted quads inside
#: longer words from partially matching (ASCII classes, per _HOST_RE).
_IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9_.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
    r"(?::\d{1,5})?(?![A-Za-z0-9])"
)
#: IPv6 literal: bracketed form (optional port), the full 8-group form, or
#: a bare compressed form containing "::" and at least one digit —
#: "08:00:05" clocks and "key::name" prose never match. A bare address
#: followed by ":port" stays unmasked (ambiguous with the address tail;
#: the bracketed form carries ports).
_IPV6_RE = re.compile(
    r"\[[0-9a-fA-F:]{2,45}\](?::\d{1,5})?"
    r"|(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"(?![0-9a-fA-F:])"
    r"|(?<![0-9a-fA-F:])(?=[0-9a-fA-F:]*\d)[0-9a-fA-F:]*::[0-9a-fA-F:]*"
    r"(?![0-9a-fA-F:])"
)
#: A glued ``?key=value`` tail in free text (a bare host+path is the shape
#: that survives host masking). redact_url never keeps a query — "tokens
#: ride query strings" — so free text must not become the one place a
#: query survives. Only key=value shapes collapse; prose question marks
#: ("ready? proceed") pass.
_QUERY_TAIL_RE = re.compile(r"\?[^\s\"'=]*=[^\s\"']*")
#: A whole free-text token ending in ``@`` — the userinfo (``user[:password]``)
#: of a bare target. Masking the host alone leaves the credential in the
#: string, and the userinfo is exactly where a credential rides — the reason
#: redact_url keeps neither a query nor a netloc. Token boundaries are the ones
#: the patterns above already use (whitespace, quotes) plus ``/`` and ``@``;
#: a token is taken whole rather than character-class-matched, so an unusual
#: password character cannot leave half a credential behind, and the leading
#: class negation gives the run exactly one start position — a long ``@``-free
#: token costs one pass, not one per character.
_USERINFO_RE = re.compile(r"(?<![^\s\"'/@])[^\s\"'/@]+@")
#: What may follow that ``@`` for the token to count as a userinfo: the very
#: matchers redact_text applies next, so the two can never disagree about what
#: a target is.
_TARGET_AFTER_AT = (_HOST_RE, _IPV4_RE, _IPV6_RE)


def _drop_userinfo(text: str) -> str:
    """Delete every ``user[:password]@`` that precedes a bare target.

    Only the prefix goes: the target itself is masked by the host/IP passes
    that run next, so ``user:pass@host`` and ``host`` render identically. An
    ``@`` with no target behind it is ordinary prose ("ping @team",
    "nginx@latest") and is left alone.
    """
    if "@" not in text:
        return text
    kept: list[str] = []
    last = 0
    for match in _USERINFO_RE.finditer(text):
        # match(text, pos) rather than a slice: the lookbehind of each target
        # pattern sees the ``@``, which none of them admits, so the answer is
        # the same and no per-``@`` copy of the tail is made.
        if not any(p.match(text, match.end()) for p in _TARGET_AFTER_AT):
            continue
        kept.append(text[last:match.start()])
        last = match.end()
    if not kept:
        return text
    kept.append(text[last:])
    return "".join(kept)


def origin_label(origin: str) -> str:
    """Stable, non-reversible label for a host/IP/URL origin.

    Same input -> same label (tables stay sortable/diffable across ticks),
    but the label leaks nothing about the target.
    """
    digest = hashlib.sha256(origin.encode("utf-8")).hexdigest()[:8]
    return f"origin-{digest}"


def mask_secret(text: str) -> str:
    """Render a credential-shaped value as fingerprint-prefix + last 3."""
    stripped = text.strip()
    if len(stripped) <= 11:
        return "*" * len(stripped)
    head = stripped[:8] if _FINGERPRINT_RE.match(stripped) else stripped[:2] + "…"
    return f"{head}…{stripped[-3:]}"


def redact_text(text: str) -> str:
    """Replace every URL, host/domain and IP literal with masked placeholders.

    URLs keep their own ``<redacted-url>`` placeholder; bare hostnames and
    IPv4/IPv6 literals (port included) collapse to ``<redacted-host>``, and a
    ``user[:password]@`` prefix riding one is dropped rather than rendered
    beside its placeholder. Free-text paths (heartbeat messages, collector
    errors, cooldown reasons) carry bare targets, not only scheme'd URLs, so
    host masking cannot stop at ``scheme://``. Deliberately narrow: version
    strings ("1.2.3") and ordinary dotted prose that is not host-shaped pass
    through, and dotted ENGINE vocabulary (event kinds such as
    ``scan.wave.completed``) never enters here — see
    ``collectors/graph.py`` ``event_summary``.
    """
    if not text:
        return text
    masked = _URL_RE.sub("<redacted-url>", text)
    masked = _drop_userinfo(masked)
    masked = _HOST_RE.sub("<redacted-host>", masked)
    masked = _IPV4_RE.sub("<redacted-host>", masked)
    masked = _IPV6_RE.sub("<redacted-host>", masked)
    return _QUERY_TAIL_RE.sub("?…", masked)


def redact_url(url: str) -> str:
    """Mask a URL to its scheme + '<redacted-host>' + path shape.

    ``https://api.example.com/v1/login?token=x`` -> ``hxxp://<redacted>/v1/login?…``
    The query string is never kept (tokens ride query strings too often).
    """
    if not url:
        return url
    match = _URL_RE.match(url)
    scheme = match.group(0).split("://", 1)[0] if match else "hxxp"
    path = ""
    if match:
        rest = match.group(0).split("://", 1)[1]
        _, _, path = rest.partition("/")
    path = path.split("?", 1)[0]
    scheme_name = "hxxp" if scheme.startswith("http") else scheme
    shown = f"{scheme_name}://<redacted>"
    if path:
        shown += "/" + path
    if "?" in url:
        shown += "?…"
    return shown


def short_id(value: str | int, width: int = 8) -> str:
    """Stable short id for logs/feeds that must not carry the raw value."""
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:width]
    return digest
