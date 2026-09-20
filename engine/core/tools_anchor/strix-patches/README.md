# strix-patches — deploy-site anonymity patch anchors (a recorded pitfall ③ / a recorded pitfall)

`uv tool upgrade strix-agent` reinstalls site-packages and can silently wipe
the three patched runtime files. Without them strix still launches — with NO
caido upstream, i.e. residential IP direct to target (the internal doctrine violation).

Each `<version>/` directory holds the FULL patched files as deployed for that
strix-agent version (not diffs — the files are small and whole-file replay is
deterministic for same-version reinstalls; cross-version bumps need a manual
port, see provision.sh strix-upgrade's fail-closed checklist).

| file | patch content | markers verified by `provision.sh strix-verify` |
|---|---|---|
| `caido_upstream.py` | new module: GraphQL createUpstreamProxyHttp wiring, fail-closed | `MOTOKO_CAIDO_UPSTREAM` |
| `caido_bootstrap.py` | after project select, inject upstream when `MOTOKO_CAIDO_UPSTREAM` set | `MOTOKO_CAIDO_UPSTREAM` |
| `docker_client.py` | `STRIX_SANDBOX_PUBLISH_PORTS=1` → keep published ports + `_resolve_exposed_port` reads NetworkSettings.Ports → `127.0.0.1:<mapped>` (slirp4netns half-loop fix, a recorded pitfall) | `STRIX_SANDBOX_PUBLISH_PORTS`, `_resolve_exposed_port` |

Behavior lock (2026-09-20): a dedicated suite in the engine test tree
loads the NEWEST anchored `docker_client.py` with the SDK/docker import surface
stubbed and pins both a recorded pitfall branches (default: network pops ports + container-IP
resolution; publish=1: ports kept + host-side published-port resolution) plus the
fail-closed error paths. `strix-verify` gates the anchor's PRESENCE by hash; this
suite gates its BEHAVIOR — a version bump re-runs both (the test resolves the
highest `<version>/` dir, so a new anchor is locked automatically).

## 1.6.2 (anchored 2026-09-16)

- Source: deployed site `~/.local/share/uv/tools/strix-agent/lib/python3.13/site-packages/strix/runtime/`
  after the 2026-09-16 dependency refresh (strix-agent stayed 1.6.2; litellm
  1.101 / urllib3 2.8 / boto3 1.43.95 bumped; patches sha256-identical before/after).
- sha256: caido_bootstrap `a59d8982…`, caido_upstream `14eae850…`, docker_client `183e33f7…`
  (the anchored files themselves are the source of truth: `sha256sum 1.6.2/*.py`).
- NOTE: this anchor also closes the old "docker_client patch has no source
  backup" gap — the deploy site is no longer the only copy. The tools/strix
  source-checkout mirror stays pending; 1.5.3 is not the executed code path.

Upgrade procedure (mandatory): `./provision.sh strix-upgrade` — never a bare
`uv tool upgrade`. After any version bump: anchor the new patched files here,
update this README, commit with the engine.
