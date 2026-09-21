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
    """Replace every URL in free text with a masked placeholder."""
    if not text:
        return text
    return _URL_RE.sub("<redacted-url>", text)


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
