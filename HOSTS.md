# Host integration contract

MOTOKO owns tool selection, scope checks, parsing, evidence, recovery and scan
wave feedback. The host owns the operator interface, model session and optional
messaging gateway. An adapter must not add another scheduler or edit SQLite.

| Host | Adapter | Status |
|---|---|---|
| [codewhale](https://github.com/codewhale-hq/Codewhale) (live seat since 2026-10-07) | Direct `motoko` CLI driving through verb-gated seat tools in the shared script-tool dir `~/.codewhale/plugins/tools/` (`motoko-read` for doctor/rules/status/digest/health/query/events; `motoko-launch` for strix/ingest-strix/seal, per-call approval; the bundle's `tools/` files are symlinked there), plus `systemctl --user` shepherd control. The seat is the `motoko` **plugin bundle** (`~/.codewhale/plugins/motoko/`: `plugin.toml`, `skills/motoko-seat-ops/`, `commands/motoko-seat.md`, `agents/motoko-ops.toml`, `hooks/hooks.toml` with the inlined secret-path-guard, `tools/`, and the `INTERFACE.md` seam contract). Script tools load trust-free via `[tools] plugin_dir` in config.toml; skills/commands/agents/hooks are reviewed plugin components — `/plugin trust motoko` activates them (content freezes into the staged snapshot). Ops panel: the native Codewhale `/motoko` panel, fed by `motoko adapter --stdio` (the redaction boundary). The tmux-lane terminal TUI it replaces was retired 2026-10-09; `motoko status` and `motoko watch --once` remain headless surfaces. The wrappers run unsandboxed on purpose: Codewhale's default `exec_shell` sandbox (workspace-write/bwrap) defeats the strix shim's `/proc` ancestor walk and `doctor`'s `/proc` scan, strips `MOTOKO_*`/`DOCKER_HOST`, and denies writes to the engagement tree | Acceptance 2026-10-07: read-side parity vs direct CLI (A1) and raw-strix refusal (A3) verified from the seat tool path; shepherd control read-only surface verified (A4); hygiene negative checks pass (A6, incl. the 2026-10-07 replacement of the seat→tree `social-profile` symlink by a copy). Wave calls (`motoko run`/`loop`) are documented as an operator-shell/shepherd lane — they outlive the tool host's 120 s cap and write the graph. Gate rehearsal (A2) passed synthetically 2026-10-07 (local self-test target, `--dry-run`: all six gates green, `[dry] all gates passed; not launching`; refusal half observed at the `--no-rotate` scope gate and the raw-strix shim). A5 ingest/seal idempotency passed synthetically 2026-10-07 (double ingest of a synthetic report: 4 urls/2 findings then 0/0 with 2 duplicates merged; `seal --verify` "manifest match"); real-engagement seals remain operator work. Bundle components were trusted 2026-10-07. A later edit of a reviewed component needs a new trust before the staged snapshot picks it up. |
The live seat is codewhale (since 2026-10-07). It drives the engine through
the installed `motoko` CLI: read-side subcommands (digest, health, query,
events), gated `motoko strix` through the six-gate wrapper,
`systemctl --user` shepherd control and `motoko ingest-strix` report intake.
Execution stays in OS-owned wrappers — the seat adds no scheduler and never
edits SQLite. Verb-gated wrappers are the seat's call surface; wave calls
stay on the operator-shell or shepherd lane. Existing host gateways can carry operator
messages; SSH carries the engine protocol. No host is required by the engine.

## Install

Install the engine on the scan machine:

```bash
pip install "git+https://github.com/eric-stone-plus/MOTOKO.git#subdirectory=engine"
```

The engine is Python 3.11+, stdlib only. For the codewhale seat, install the
`motoko` CLI on the host (or reach it over SSH); the seat calls it directly
and adds no Python-side host requirements.
Protect raw launches with the
strix shim (`~/.config/strix/strix-wrapper.sh`, installed as
`~/.local/bin/strix`), which admits `strix` only from a gated ancestor. The
engine-side adapter (`motoko adapter --stdio`) needs no host install.
Deployment paths are operator inputs, never model inputs.

The engine-side adapter runs where the engine runs; remote collectors
reach it over SSH (posture below). Provision the engine account and
target egress separately.

The host tools require an existing authorized engagement. Initialization,
scope changes and secret provisioning remain operator deployment tasks. The
seat starts no work merely by being connected or loaded.

## Protocol and lifecycle

The host negotiates `motoko/1` over stdin/stdout. Frames are at most 64 KiB,
with at most 32 sequential requests per process. Responses correlate numeric
request IDs. Duplicate JSON keys, non-finite values, unknown fields and invalid
result shapes are rejected. Diagnostics never share protocol stdout.

Read operations are `capabilities`, `doctor`, `rules`, `status`, `digest`,
`query`, `events`, `health`. The only mutation is `run`, with finite cycle,
wave, tool and wall-time budgets. Hosts receive counts, known enums, pseudonymous entity
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
abrupt client loss) for the engine-side adapter, and the seat's direct CLI
surface (read-side subcommands matching the CLI, gated strix passthrough,
shepherd control, report ingest). Per-seat acceptance status is recorded in each seat's
table row above (codewhale: accepted 2026-10-07). It does not establish production gateway
reliability, agent-facing effective-tool behavior inside a model session,
or model quality.
