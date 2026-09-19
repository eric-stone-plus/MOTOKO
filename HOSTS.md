# Host integration contract

MOTOKO owns tool selection, scope checks, parsing, evidence, recovery and scan
wave feedback. The host owns the operator interface, model session and optional
messaging gateway. An adapter must not add another scheduler or edit SQLite.

| Host | Adapter | Status |
|---|---|---|
| [Hermes](https://github.com/NousResearch/hermes-agent) | Python plugin importing `motoko_host.client` | Discovery, profile isolation and tool dispatch tested. |
| [Pi](https://github.com/earendil-works/pi) | Installable `motoko-pi` package with a typed extension invoking `motoko-host` | Package/skill discovery, actual extension loading, dispatch and cancellation tested on 0.85.1. |
| [OpenClaw](https://github.com/openclaw/openclaw) | None yet | Protocol boundary is reusable; no runtime acceptance claimed. |

Pi's small extension interface makes it a useful lightweight host. Its
experimental server uses a separate facet-plugin API, which this regular
extension does not support. Its Unix-socket transport leaves peer
authentication to the application. The optional Radius relay uses bearer
authentication and defaults to HTTPS/WSS, but also accepts HTTP/WS URLs.
The reviewed relay wrapper forwards payloads without application-layer
encryption; TLS does not establish confidentiality from the relay. This
adapter enables neither server nor relay. Existing host gateways can carry
operator messages; SSH carries the engine protocol. No host is required by
the engine.

## Install

Install the engine on the scan machine and the standalone client on the host:

```bash
pip install ./engine
pip install ./engine/integrations/host
```

The client uses Python 3.11+, stdlib only, with no engine imports. On Hermes,
copy `engine/integrations/hermes/motoko` to the profile plugin directory, enable
`motoko`, and supply its manifest's transport settings. Install `motoko-host`
in Hermes's Python environment. On Pi, run
`pi install ./engine/integrations/pi/motoko` for the reviewed local package; it loads the
extension and host procedure as a skill. Set `MOTOKO_HOST_EXECUTABLE` to the
absolute installed client CLI and `MOTOKO_HOST_CONFIG` to an owner-only JSON
configuration file. Both paths must be regular files, not symlinks; the CLI
must be owned by the user or root and not writable by other users. Deployment
paths are operator inputs, never model inputs.

Local configuration requires `executable` and `runtime_root`. The latter is a
private 0700 directory used as engine data root and for process records. SSH
configuration sets `transport: "ssh"`, a local private `runtime_root`, and
`remote_host`, `remote_executable`, `remote_root`, `known_hosts`, `identity_file`.
The key and known-hosts paths are local owner-only regular files. Optional
settings include `ssh_port`, toolbox/wordlist directories, `egress_mode` and
`allow_direct_replay`. Remote paths use literal absolute tokens; shell syntax
is rejected. Provision the engine account and target egress separately.

The host tools require an existing authorized engagement. Initialization,
scope changes and secret provisioning remain operator deployment tasks. The
plugin does not start work merely by being installed or loaded.

## Protocol and lifecycle

The client negotiates `motoko/1` over stdin/stdout. Frames are at most 64 KiB,
with at most 32 sequential requests per process. Responses correlate numeric
request IDs. Duplicate JSON keys, non-finite values, unknown fields and invalid
result shapes are rejected. Diagnostics never share protocol stdout.

Read operations are `capabilities`, `doctor`, `rules`, `digest`, `query`,
`events`, `health`. The only mutation is `run`, with finite cycle, wave, tool
and wall-time budgets. Hosts receive counts, known enums, pseudonymous entity
references and bounded wave metadata. There are no arbitrary commands, rule
paths, graph writes or raw evidence operations.

The client starts `motoko adapter --stdio --disconnect-cancels`. SSH uses
strict host-key checking, an explicit identity, no inherited client config,
no agent, no forwarding and no PTY. Model inputs travel inside encrypted JSON;
the remote command is fixed. This creates no MOTOKO HTTP listener. MCP can
also use stdio or encrypted transports, but is not part of this implementation.

The supervisor keeps stdin open until the response. Closure cancels active
engine work; SSH keepalives and the engine wall deadline bound network-loss
handling. Cancellation reaps recorded scanner groups, closes tool rows,
persists partial-wave feedback and releases the writer lease. Plain `--stdio`
retains normal piped-input behavior without the disconnect lease.

Pi marks runs sequential; the engine writer lease also prevents competing
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

Acceptance covers synthetic local scanners, real loopback SSH (including abrupt
client loss), Hermes discovery and Pi extension execution. It does not establish
production gateway reliability or model quality. Pi's upstream full check has
catalog/type inconsistencies at the reviewed revision; the extension's targeted
typecheck and runtime acceptance pass independently.
