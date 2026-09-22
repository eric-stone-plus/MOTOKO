# Implementation Status Matrix

GRAPH.md is the orchestration contract. This file states, per contract
primitive, what the shipped engine (`engine/`) actually provides. The
engine is a real, working code tree: stdlib-only Python (>= 3.11), zero
runtime dependencies, and a packaging manifest (`pyproject.toml` with a
`motoko` console script).

## Status

| Contract primitive | Contract says | Engine status |
|---|---|---|
| `StateGraph` (one engagement state) | scope, assets, findings, evidence, budget in one state object | **Shipped** — event-sourced entities over SQLite (assets / findings / hypotheses / evidence / services), append-only event log, materialized `entities` view, WAL single-writer |
| node (one instrument or gate) | instruments and gates are nodes | **Shipped** — a rule registry (`engine/core/rules/`: chain / context / scan / tech / vuln) generates hypotheses; hypotheses carry argv-rendered actions |
| conditional edge (scope fail → END) | authorization refusal ends the run | **Shipped prechecks** — label-boundary domain matching, per-IP CIDR checks, redirect-chain and certificate-SAN checks; checked-IP pinning applies to the built-in replay fetcher, external scanners can resolve again |
| `interrupt` (circuit breaker) | destructive/mutating actions pause for the operator | **Not engine-side** — enforced by the operator shell (profile rules + in-session sign-off); engine-side action gating is future work |
| `Send` fan-out (bounded parallel recon) | parallel in-scope recon under host budget | **Bounded serial batches** — per-cycle expansion budget, per-rule backlog caps, reserved category slots; host-level concurrency lives in the operator shell |
| reducer (findings/evidence append-only) | append, never silently overwrite | **Shipped** — findings append with deterministic dedup keys (`duplicate_of` edges); assets merge by (type, value) with fact union; entity kind is frozen after first write |
| checkpointer (resume after disconnect) | engagement recovers | **Shipped** — WAL + unprocessed-observation replay + LLM-proposal recovery pass each cycle |
| `budget` state fields (strix_inflight, nuclei_concurrency, mem floor) | resource floors as graph config | **Partial** — expansion budget and batch caps engine-side; host-resource floors live in the operator shell |
| `halt` states (no-scope / out-of-scope / circuit-breaker / operator-abort) | halt is a graph state | **Partial** — scope refusals are first-class events; a halt state machine is future work |

## What ships beyond the contract

- **Scan-wave feedback** (`engine/core/scan_waves.py`): per-rule run outcomes,
  discoveries and duration are persisted at wave boundaries. Discovery and
  failure rates adjust existing rule priorities within [-30, 15]; duration is
  measured but not scored. Duplicate entities do not earn discovery credit.
  Completed and interrupted wave policy resumes from disk. Cancellation closes
  tool records and saves the partial wave before releasing its writer. This is
  bounded heuristic scheduling, without automatic rule generation or parallel
  resource allocation. Missing parser/producer support remains visible in
  `motoko rules --report`; installed binaries alone do not prove a working chain.
- **Host adapters**: Hermes imports a standalone Python client; Pi invokes its
  `motoko-host` CLI. Both use the same bounded `motoko/1` JSONL protocol over
  local pipes or SSH. Hosts receive aggregate state and pseudonymous references,
  never raw evidence or event payloads. Strict SSH host-key/identity settings,
  finite deadlines and pipe-disconnect cancellation are implemented. Pi has
  sequential run-tool dispatch; engine writer exclusion also spans hosts.
  OpenClaw has no shipped adapter. Messaging gateways remain host components.
- **Engineering audit loop** (`engine/core/loop.py`): a config-driven cycle of
  independent auditors → adjudication → deterministic evaluation,
  with executable ROLLBACK/STOP verdicts. Protocol adapters only
  (openai-chat / anthropic-messages / cli-subprocess); endpoints,
  keys-by-env-name, and `${VAR}`/`~` expansion live in a config file,
  never in code. This is separate from scan execution. The public wheel does
  not contain the development tests; missing or incomplete test measurements
  fail visibly.
- **Seal** (`motoko seal`): turns a finished engagement into a
  product unit — engine commit + checkpointed graph.db +
  `engagement.manifest.json` (sha256, schema version, full census,
  integrity gates). A refused seal never leaves a manifest.
- **Failure forensics** (`engine/core/failure.py`): run-failure taxonomy
  with a recovery pass wired into the orchestrator cycle.
- **Graph health** (`motoko health`): stranded-hypothesis and
  broken-link sweeps that distinguish in-flight work from stalls.

## Reproducibility posture

- Runtime deps: **none** (stdlib only); behavior is pinned by the
  Python version and by the tool manifests, not by pip.
- Config layering: environment variables > an operator-supplied config file
  (`$MOTOKO_CONFIG`; `.gitignore` also covers the in-tree `engine/loop/`
  location) > code defaults derived from the package location. Credentials
  are referenced by environment-variable name and never stored. No absolute
  home paths are hardcoded in the tree.
- The generic engine does not embed scanner revisions: `MOTOKO_TOOLS` points at
  the deployment toolbox and `motoko doctor` reports which binaries resolve.
  The current host's pinned toolbox and Kali image baseline are recorded in
  `engine/core/tools_anchor/kali/kali-container.md`; they are deployment
  evidence, not a universal release promise. The CLI derives owner-local
  Go/Cargo and user-bin search directories for child processes, even when a
  gateway supplies a minimal `PATH`; `MOTOKO_TOOL_DIRS` adds absolute
  directories for non-standard layouts.

## For contributors

The contract is the design intent. The engine is ahead of it on
verification (validators, state machines, evidence chaining, sealing)
and behind it on interrupts, parallel fan-out, and host-resource
budgeting — those are the right places to work. See AGENTS.md.
