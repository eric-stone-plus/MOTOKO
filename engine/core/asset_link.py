'Shared finding->asset linking helpers.'

from __future__ import annotations

from urllib.parse import urlparse


def _host(value: str) -> str:
    """Host part of an asset value / finding URL (scheme+port stripped)."""
    try:
        if "://" in value:
            return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""
    return value.lower()


def asset_id_for_url(w, url: str, engagement_id: str | None = None) -> str | None:
    'Find the asset a finding URL belongs to (exact value or host match).'
    host = _host(url)
    hostport = host
    if "://" in url:
        netloc = url.split("://", 1)[1].split("/", 1)[0]
        hostport = netloc.lower()
    kwargs = {"engagement_id": engagement_id} if engagement_id else {}
    assets = w.query_entities(kind="asset", **kwargs)
    for a in assets:
        if str(a.get("value") or "") == url:
            return a["id"]
    for a in assets:
        v = str(a.get("value") or "")
        if hostport and _host(v) == host and v.split("://", 1)[-1].split("/", 1)[0].lower() == hostport:
            return a["id"]
    for a in assets:
        if host and _host(str(a.get("value") or "")) == host:
            return a["id"]
    return None
