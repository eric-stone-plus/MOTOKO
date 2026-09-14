"""Shared finding->asset linking helpers.

Asset linking: both ingest paths need to
answer "which asset does this finding's URL belong to" —
``orchestrator._ingest_finding`` (SYNC beat) and
``cli.ingest_strix_findings`` (strix report ingest). The logic previously
lived only on the Orchestrator method, so the CLI path silently skipped
the link: strix class facts never reached ``orchestrator._fact_view`` and
the per-asset class rules were blind to strix output. One implementation
lives here; both callers delegate (no copy-paste drift).
"""

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
    """Find the asset a finding URL belongs to (exact value or host match).

    ``w`` is a motoko ``db.Database`` handle (writer or read-only);
    ``engagement_id`` narrows the query when given. Matching is the R5 M7
    contract: an exact asset ``value`` wins, then host equality (scheme,
    port and path ignored on both sides). Returns None when nothing
    matches — callers decide whether that is fatal.
    """
    host = _host(url)
    hostport = host
    if "://" in url:
        netloc = url.split("://", 1)[1].split("/", 1)[0]
        hostport = netloc.lower()
    kwargs = {"engagement_id": engagement_id} if engagement_id else {}
    assets = w.query_entities(kind="asset", **kwargs)
    # round-4 audit: three passes with DECREASING specificity — an exact
    # URL beats host:port beats bare host. The old single pass returned
    # the FIRST host match in arbitrary row order, so a :8443 finding
    # could bind to the :443 asset.
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
