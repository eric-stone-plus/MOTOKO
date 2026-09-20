'When MOTOKO_CAIDO_UPSTREAM is set ("host:port" of the egress gateway),\nthe bootstrap installs an enabled HTTP upstream proxy inside the sandbox\ncaido instance so that every proxied request leaves through the egress,\nnever the residential IP. Fail-closed: any error here aborts the launch\n(caller treats bootstrap failure as session failure).'

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession
    from caido_sdk_client import Client

logger = logging.getLogger(__name__)

_UPSTREAM_ENV = "MOTOKO_CAIDO_UPSTREAM"

_CREATE_UPSTREAM_MUTATION = """
mutation CreateUpstream($input: CreateUpstreamProxyHttpInput!) {
  createUpstreamProxyHttp(input: $input) {
    proxy { id enabled connection { host port isTLS } }
  }
}
"""


def upstream_from_env() -> tuple[str, int] | None:
    """(host, port) parsed from MOTOKO_CAIDO_UPSTREAM, or None when unset."""
    value = os.environ.get(_UPSTREAM_ENV, "").strip()
    if not value:
        return None
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(
            f"{_UPSTREAM_ENV} must be host:port, got {value!r}")
    return host, int(port)


async def _gql_exec(session: BaseSandboxSession, token: str,
                    query: str, variables: dict) -> dict:
    """One GraphQL call via in-container curl (guest token auth)."""
    payload = json.dumps({"query": query, "variables": variables})
    result = await session.exec(
        "curl", "-fsS", "-X", "POST",
        "-H", "Content-Type: application/json",
        "-H", f"Authorization: Bearer {token}",
        "-d", payload,
        "http://127.0.0.1:48080/graphql",
        timeout=15,
    )
    if not result.ok():
        raise RuntimeError(
            "caido upstream GraphQL failed: "
            f"exit {result.exit_code}: "
            f"{result.stderr.decode('utf-8', errors='replace')[:200]}")
    body = json.loads(result.stdout)
    if body.get("errors"):
        raise RuntimeError(
            f"caido upstream GraphQL errors: {body['errors']!r}"[:300])
    return body["data"]


async def wire_upstream(session: BaseSandboxSession, token: str) -> str:
    """Install the enabled HTTP upstream inside caido. Returns its id."""
    target = upstream_from_env()
    if target is None:
        raise RuntimeError("wire_upstream called without "
                           f"{_UPSTREAM_ENV} set")
    host, port = target
    data = await _gql_exec(session, token, _CREATE_UPSTREAM_MUTATION, {
        "input": {
            "enabled": True,
            "connection": {"host": host, "port": port, "isTLS": False},
            "allowlist": [],
            "denylist": [],
        },
    })
    proxy = (data.get("createUpstreamProxyHttp") or {}).get("proxy") or {}
    proxy_id = proxy.get("id")
    if not proxy_id or not proxy.get("enabled"):
        raise RuntimeError(
            f"upstream not enabled after create: {json.dumps(data)[:200]}")
    logger.info("Caido upstream wired: %s -> %s:%s (id=%s)",
                _UPSTREAM_ENV, host, port, proxy_id)
    return str(proxy_id)


async def guest_token(session: BaseSandboxSession,
                      container_url: str) -> str:
    """Fetch a guest token directly (the SDK token path is client-side)."""
    result = await session.exec(
        "curl", "-fsS", "-X", "POST",
        "-H", "Content-Type: application/json",
        "-d",
        '{"query":"mutation { loginAsGuest { token { accessToken } } }"}',
        f"{container_url}/graphql",
        timeout=15,
    )
    if not result.ok():
        raise RuntimeError(
            f"loginAsGuest exec failed: exit {result.exit_code}")
    payload = json.loads(result.stdout)
    token = (payload.get("data", {}).get("loginAsGuest", {})
             .get("token", {}).get("accessToken"))
    if not token:
        raise RuntimeError(
            f"loginAsGuest no token: {json.dumps(payload)[:200]}")
    return str(token)
