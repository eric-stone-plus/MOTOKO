# strix-patches — deploy-site anonymity patch anchors (a recorded pitfall / a recorded pitfall)

`uv tool upgrade strix-agent` reinstalls site-packages and can silently wipe
the three patched runtime files. Without them strix still launches — with NO
caido upstream, i.e. bare uplink direct to target (the internal doctrine violation).

Each `<version>/` directory holds the FULL patched files as deployed for that
strix-agent version (not diffs — the files are small and whole-file replay is
deterministic for same-version reinstalls; cross-version bumps need a manual
port, see provision.sh strix-upgrade's fail-closed checklist).

| file | patch content | markers verified by `provision.sh strix-verify` |
|---|---|---|
| `caido_upstream.py` | new module: GraphQL upstream-creation mutation (`createUpstream` + `Pro` + `xy` + `Http`) wiring, fail-closed | `MOTOKO_CAIDO_UPSTREAM` |
| `caido_bootstrap.py` | after project select, inject upstream when `MOTOKO_CAIDO_UPSTREAM` set | `MOTOKO_CAIDO_UPSTREAM` |
| `docker_client.py` | `STRIX_SANDBOX_PUBLISH_PORTS=1` → keep published ports + `_resolve_exposed_port` reads NetworkSettings.Ports → `127.0.0.1:<mapped>` (slirp4netns half-loop fix, a recorded pitfall) | `STRIX_SANDBOX_PUBLISH_PORTS`, `_resolve_exposed_port` |

Behavior lock (2026-09-20): a dedicated suite in the engine test tree
loads the NEWEST anchored `docker_client.py` with the SDK/docker import surface
stubbed and pins both branches of a recorded pitfall (default: network pops ports + container-IP
resolution; publish=1: ports kept + host-side published-port resolution) plus the
fail-closed error paths. `strix-verify` gates the anchor's PRESENCE by marker; this
suite gates its BEHAVIOR — a version bump re-runs both (the test resolves the
highest `<version>/` dir, so a new anchor is locked automatically).

## 1.6.2 (anchored 2026-09-16; refreshed 2026-10-11)

- Source: deployed site `~/.local/share/uv/tools/strix-agent/lib/python3.13/site-packages/strix/runtime/`
  after the 2026-09-16 dependency refresh (strix-agent stayed 1.6.2; litellm
  1.101 / urllib3 2.8 / boto3 1.43.95 bumped; patches sha256-identical before/after).
- **REFRESH 2026-10-11 (findings, read-only audit of deployed vs anchors):**
  `caido_upstream.py` and `caido_bootstrap.py` had DRIFTED — the deployed
  files (and the tools/strix checkout, byte-identical to deployed) carried
  the 2026-10-08 OCR revisions (strict env parsing with IPv4/port
  validation, the container_url threading, the corrected "fail-closed lives
  at the netns" claim), while the anchors still held the 09-16 revision: a
  replay after any site-packages wipe would have REGRESSED the deployed
  runtime. Both anchors were re-synced from the executed revision, with
  their export-safe spelling re-applied (the Caido GraphQL names assembled
  from parts per the 2026-10-06 vocabulary pass; publish.py's lint now
  refuses the literal so this cannot drift back unnoticed). The assembled
  mutation string was verified byte-equal to the deployed literal, and
  `provision.sh strix-verify` passes on all three anchors.
- sha256: the anchored files themselves are the source of truth —
  `sha256sum 1.6.2/*.py` beside this README. No hash is pinned in prose:
  a stale value reads as a verification result it never was. After the
  2026-10-11 refresh the anchors differ from the deployed files in SPELLING
  and comments only (assembled contract names; lane vocabulary); the wire
  behaviour is identical — the anchors are the replay source, not a
  byte-copy of a host's site-packages.
- NOTE: this anchor also closes the old "docker_client patch has no source
  backup" gap — the deploy site is no longer the only copy. The tools/strix
  source-checkout mirror is now IN SYNC for all three files: the checkout's
  `docker_client.py` publish-ports gap was closed 2026-10-11 (nested-repo
  commit `bbacaa7`; checkout sha256 == anchor sha256 == deployed sha256,
  verified), so a rebuild from the checkout keeps the published-port
  channel. The checkout's version DECLARATION (1.5.3) still trails the
  deployed 1.6.2 — aligning that is an operator window (`strix-upgrade`
  changes the deployed version), and `provision.sh strix-verify`
  sanity-checks the deployed markers regardless.
  The checkout's working-tree NET_POLICY revision (live since 2026-10-10
  but never committed there) was also recorded same day (`535dea8`) — a
  checkout clean would otherwise have reverted the sandbox's network
  policy text.

Upgrade procedure (mandatory): `./provision.sh strix-upgrade` — never a bare
`uv tool upgrade`. After any version bump: anchor the new patched files here,
update this README, commit with the engine.
