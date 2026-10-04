# Host integration contract

MOTOKO owns tool selection, scope checks, parsing, evidence, recovery and scan
wave feedback. The host owns the operator interface, model session and optional
messaging gateway. An adapter must not add another scheduler or edit SQLite.

| Host | Adapter | Status |
|---|---|---|
| [opencode](https://github.com/anomalyco/opencode) | TypeScript plugin (`engine/scripts/plugin.ts`) exposing the read-side CLI surface, gated `motoko strix`, shepherd control and report ingest | Tool surface verified against 0.0.0-main-202609302229 (plugin.ts verified-API-surface stamp, 2026-10-01; a later live seat acceptance on 2026-10-02 under a newer main re-checked the same surface: doctor/rules/health/query/events/digest payloads match the direct CLI, ingest with engine-side scope rejection and idempotent re-ingest, seal verify `manifest match`, six-gate refusal with no launch, seat bash gate blocking raw `strix`/unbounded `motoko run`/`--direct`, shepherd status as data and stop refusing without `force`); thin control plane — execution stays in OS-owned wrappers. |
The opencode seat plugin (`engine/scripts/plugin.ts`) is a thin
control plane: it exposes the read-side CLI surface (digest, health, query,
events), gated `motoko strix` through the six-gate wrapper, shepherd unit
control and strix-report ingest. Execution stays in OS-owned wrappers — the
plugin adds no scheduler and never edits SQLite. Existing host gateways can
carry operator messages; SSH carries the engine protocol. No host is
required by the engine.

## Install

Install the engine on the scan machine:

```bash
pip install ./engine
```

The engine is Python 3.11+, stdlib only. For the opencode seat, copy or
symlink `engine/scripts/plugin.ts` into opencode's plugin directory
(`~/.config/opencode/plugin/`); it wraps the installed `motoko` CLI and
adds no Python-side host requirements. The engine-side adapter
(`motoko adapter --stdio`) needs no host install. Deployment paths are
operator inputs, never model inputs.

The engine-side adapter runs where the engine runs; remote collectors
reach it over SSH (posture below). Provision the engine account and
target egress separately.

The host tools require an existing authorized engagement. Initialization,
scope changes and secret provisioning remain operator deployment tasks. The
plugin does not start work merely by being installed or loaded.

## Protocol and lifecycle

The host negotiates `motoko/1` over stdin/stdout. Frames are at most 64 KiB,
with at most 32 sequential requests per process. Responses correlate numeric
request IDs. Duplicate JSON keys, non-finite values, unknown fields and invalid
result shapes are rejected. Diagnostics never share protocol stdout.

Read operations are `capabilities`, `doctor`, `rules`, `digest`, `query`,
`events`, `health`. The only mutation is `run`, with finite cycle, wave, tool
and wall-time budgets. Hosts receive counts, known enums, pseudonymous entity
references and bounded wave metadata. There are no arbitrary commands, rule
paths, graph writes or raw evidence operations.

The engine side is `motoko adapter --stdio --disconnect-cancels`. SSH uses
strict host-key checking, an explicit identity, no inherited client config,
no agent, no forwarding and no PTY. Model inputs travel inside encrypted JSON;
the remote command is fixed. This creates no MOTOKO HTTP listener. MCP can
also use stdio or encrypted transports, but is not part of this implementation.

The SSH lane runs over whatever network the operator provides. A headless scan
host with no public listener is the normal shape, and an overlay network such
as [Tailscale](https://github.com/tailscale/tailscale) is one way to reach it:
the boundary becomes the private network, so the pinned known-hosts file stays
small and stable and no port is published. That is a property of the operator's
network, not of this engine — Tailscale is cited as a tool in
[INSTRUMENTS.md](INSTRUMENTS.md), the engine never invokes it, and the SSH
posture above is identical with or without it. Whatever carries the transport,
encryption of the channel says nothing about the scanner's egress route, which
is a separate control.

The supervisor keeps stdin open until the response. Closure cancels active
engine work; SSH keepalives and the engine wall deadline bound network-loss
handling. Cancellation reaps recorded scanner groups, closes tool rows,
persists partial-wave feedback and releases the writer lease. Plain `--stdio`
retains normal piped-input behavior without the disconnect lease.

Runs are marked sequential; the engine writer lease also prevents competing
processes or hosts from scanning the same engagement. Read-only calls can run
concurrently. A transport failure can leave the outcome uncertain: inspect
digest, events and health before resuming, never automatically retry mutations.
Respect `retry_after_s` when `stop_reason` is `waiting`.

## Limits

Scan adaptation reorders existing rules from discoveries, failures, empty
results and chain hints. It uses serial batches and bounded priority offsets;
it does not implement adaptive parallel resource allocation or invent rules.
The host adapter does not enable paid reflectors or external agent launches.
The separate engineering audit loop is `motoko loop`.

SSH encryption does not establish the scanner's egress route. Process groups
are cleanup handles, not containment against deliberate group escape. Use OS
isolation appropriate to the deployment. Aggregates still disclose operational
metadata to the host; raw evidence remains in engine storage.

Acceptance covers synthetic local scanners and real loopback SSH (including
abrupt client loss) for the engine-side adapter, and the opencode plugin's
tool surface against 0.0.0-main-202609302229 (bash gate, gated strix
passthrough, shepherd control, report ingest; stamp refreshed 2026-10-01 to
the installed build, API unchanged since the 2026-09-28 check). It does not establish production gateway
reliability, agent-facing effective-tool behavior inside a model session,
or model quality.
