---
name: motoko
description: Use the bounded MOTOKO tools from Pi without reimplementing scan scheduling.
version: 1.0.0
---

# MOTOKO in Pi

Use `motoko_status` for capabilities, deployment checks and aggregate engagement
state. Use `motoko_run` for one bounded run on an existing authorized
engagement. MOTOKO owns scope, scanner selection, evidence, recovery and wave
feedback; the Pi host must not open the graph or reproduce its scheduler.

The extension invokes the standalone `motoko-host` CLI through a private local
configuration file. Set `MOTOKO_HOST_EXECUTABLE` and `MOTOKO_HOST_CONFIG` in the
Pi process environment. Both paths must be absolute regular files. The config
must be owner-only; the executable must be owned by the user or root and not
writable by other users. The configuration can select local execution or the
SSH transport with a pinned known-hosts file and explicit identity.

For remote operation, keep the engine and scanner toolbox on the scan host and
let the host adapter start `motoko adapter --stdio` through SSH. The SSH path
uses host-key pinning, no agent, no PTY, no forwarding and bounded disconnect
cancellation. Do not add an HTTP listener or MCP server just to expose the
engine.

Call `doctor` and `rules` before a run, then inspect `stop_reason`, `pending`,
`retry_after_s` and wave feedback. Never blindly repeat `run` after an uncertain
transport failure; read `digest`, `events` and `health` first. Raw evidence and
target-specific paths stay on the engine host.

This package supports Pi's regular extension API. The experimental Pi server
uses a separate facet-plugin API; this package is not an adapter for that API.
Keep bounded wave decisions in the engine and let the host decide when another
authorized run is useful. Do not treat SSH encryption as proof of scanner
egress anonymity or as an access restriction on the host's other tools.
