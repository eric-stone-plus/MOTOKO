'The dedup key is ``sha1(class | host | path_template | param | sink)``. Path\ntemplates collapse the hundreds of variants katana/gau/ffuf produce for the\nsame logical endpoint into one.\n'

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HEX16 = re.compile(r"[0-9a-f]{16,}", re.I)
# Segment-scoped on purpose: "/" inside a path template is a separator, not
# token evidence — a class spanning it collapsed ANY 16+ char path
# ("/user/123/orders" -> "/{b64}") and dictionary-word paths
# ("/kb/administratorspanelguide") into one template.
_B64 = re.compile(r"[A-Za-z0-9+]{16,}={0,2}")
_DIGITS = re.compile(r"\d+")
_PLACEHOLDER = re.compile(r"(\{[^}]*\})")


def _b64_placeholder(m: re.Match) -> str:
    """Collapse a candidate base64 run only when it carries token evidence
    (a digit or a "+"); a pure-alpha run is a dictionary word, not a token.
    """
    tok = m.group(0)
    return "/{b64}" if any(c in "0123456789+" for c in tok) else tok


def normalize_host(host: str) -> str:
    h = (host or "").lower().rstrip(".")
    return h


def normalize_path_template(path: str) -> str:
    """Collapse ID/UUID/base64 path segments into placeholders.

    ``/user/123/orders/9f8c3d2e-...`` -> ``/user/{id}/orders/{uuid}``.
    """
    if not path:
        return "/"
    p = path.rstrip("/") or "/"
    p = _UUID.sub("/{uuid}", p)
    p = _HEX16.sub("/{hex}", p)
    p = _B64.sub(_b64_placeholder, p)
    # Digit collapsing must not touch the placeholders just inserted —
    # "{b64}" itself contains digits and used to come out as "{b{id}}".
    p = "".join(part if _PLACEHOLDER.fullmatch(part)
                else _DIGITS.sub("{id}", part)
                for part in _PLACEHOLDER.split(p))
    return p


def endpoint_template(url: str) -> str:
    """Normalize a URL to host + path-template (scheme defaulted, no query)."""
    if not url:
        return ""
    try:
        u = urlparse(url)
        # urlparse().hostname strips userinfo, brackets and the port with
        # IPv6 awareness — netloc.split(":")[0] truncated a bracketed v6
        # host to "[2001", merging every [2001:db8::/32] host into one key.
        host = normalize_host(u.hostname or "")
    except ValueError:
        # Malformed target output must not discard the rest of an observation.
        # Keep distinct invalid URLs distinct without treating them as targets.
        return "invalid-url:" + hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()
    scheme = u.scheme or "https"
    return f"{scheme}://{host}{normalize_path_template(u.path)}"


def compute_dedup_key(finding: dict) -> str:
    'Composite dedup key for a finding dict.\n\n    Uses ``class``, endpoint template (host+path), vulnerable param, and a\n    sink/vector discriminator when present. Param-aware for the classes where\n    the same endpoint can host multiple distinct vulns (sqli/xss/ssrf/lfi).'
    # A present-but-null class is not a string: the join below would raise
    # TypeError out of the ingest path, so null/empty falls back to
    # "unknown" exactly like an absent class.
    klass = finding.get("class") or "unknown"
    endpoint = endpoint_template(finding.get("url", ""))
    param = finding.get("param", "") or ""
    sink = finding.get("sink", "") or finding.get("vector", "") or ""
    parts = [klass, endpoint, param, sink]
    cve = (finding.get("cve") or "").strip().upper()
    if cve:
        parts.append(cve)
    if not endpoint:
        parts.append(finding.get("title", "") or "")
        parts.append(finding.get("detector", "") or "")
    raw = "|".join(parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()
