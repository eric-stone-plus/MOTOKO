"""Cross-tool dedup: composite keys, not just URL (kimi review §6.2).

The dedup key is ``sha1(class | host | path_template | param | sink)``. Path
templates collapse the hundreds of variants katana/gau/ffuf produce for the
same logical endpoint into one.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HEX16 = re.compile(r"[0-9a-f]{16,}", re.I)
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_DIGITS = re.compile(r"\d+")


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
    p = _B64.sub("/{b64}", p)
    p = _DIGITS.sub("{id}", p)
    return p


def endpoint_template(url: str) -> str:
    """Normalize a URL to host + path-template (scheme defaulted, no query)."""
    if not url:
        return ""
    u = urlparse(url)
    scheme = u.scheme or "https"
    host = normalize_host(u.netloc.split("@")[-1].split(":")[0])
    return f"{scheme}://{host}{normalize_path_template(u.path)}"


def compute_dedup_key(finding: dict) -> str:
    """Composite dedup key for a finding dict.

    Uses ``class``, endpoint template (host+path), vulnerable param, and a
    sink/vector discriminator when present. Param-aware for the classes where
    the same endpoint can host multiple distinct vulns (sqli/xss/ssrf/lfi).

    P-030-R (grok adjudication, HIGH): the cve is APPENDED ONLY WHEN
    NON-EMPTY. The first P-030 pass made the key 5 sections unconditionally
    (`klass|endpoint|param|sink|`) — one trailing pipe more than the legacy
    4-section key, so EVERY pre-existing finding's stored key stopped
    matching and a rescan would have re-inserted the whole finding table.
    With conditional append, cve-less findings reuse the legacy key byte
    for byte; cve findings (all new data) get the extended key. No
    migration needed. Regression test pins a precomputed legacy key.
    """
    klass = finding.get("class", "unknown")
    endpoint = endpoint_template(finding.get("url", ""))
    param = finding.get("param", "") or ""
    sink = finding.get("sink", "") or finding.get("vector", "") or ""
    parts = [klass, endpoint, param, sink]
    cve = (finding.get("cve") or "").strip().upper()
    if cve:
        parts.append(cve)
    raw = "|".join(parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()
