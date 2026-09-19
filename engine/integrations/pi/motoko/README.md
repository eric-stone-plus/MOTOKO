# MOTOKO for Pi

This package adds two Pi tools:

- `motoko_status` reads capabilities, deployment checks and aggregate state.
- `motoko_run` starts one bounded scan run for an existing authorized engagement.

The extension delegates transport, request validation, response validation and
cleanup to the standalone `motoko-host` package. It does not open the MOTOKO
database and it does not expose individual scanners as model tools.

## Install

Install the Python host client and register this reviewed local package:

```bash
pip install ./engine/integrations/host
pi install ./engine/integrations/pi/motoko
```

Pi must start with these environment variables:

- `MOTOKO_HOST_EXECUTABLE`: absolute executable path to `motoko-host`;
- `MOTOKO_HOST_CONFIG`: absolute, owner-only JSON configuration file.

The executable must be owned by the current user or root, with no group or
world write permission. Both paths must be regular files, not symlinks. The
package targets Pi's regular extension API, tested with 0.85.1 on Linux.
It does not support the separate experimental server facet-plugin API.

The configuration uses the same keys as the Hermes adapter. Local transport
starts the engine as a child process. SSH transport starts
`motoko adapter --stdio` on the scan host with a pinned known-hosts file,
explicit identity, no agent, no PTY and no forwarding. Keep the engine,
runtime state and scanner toolbox on that scan host.

The minimal local JSON configuration contains `transport: "local"`, an
absolute `executable` pointing to `motoko`, and a private 0700 `runtime_root`.
For SSH, set `transport: "ssh"`, a private local `runtime_root`, and fixed
`remote_host`, `remote_executable`, `remote_root`, `known_hosts`, and
`identity_file`. The last two paths are local owner-only files. Select
`egress_mode` explicitly for the engine host; SSH does not route scanner traffic.
These settings are deployment inputs and never tool arguments.

## Operation

Call `motoko_status` with `doctor` and `rules` before a run. Use a finite
budget with `motoko_run`, then inspect `stop_reason`, `pending`,
`retry_after_s` and wave feedback. After an uncertain transport failure, read
`digest`, `events` and `health` before deciding whether to resume.

No HTTP listener or MCP server is required. Pi's optional server and relay
features use a different plugin lifecycle and are not enabled by this package.
The MOTOKO engine remains behind the host-neutral stdio contract and SSH is its
remote transport. Only the adapter response is restricted to metadata; Pi's
other tools and OS permissions are outside that boundary.
