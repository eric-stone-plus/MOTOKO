# Implementation Status Matrix

GRAPH.md is the orchestration contract. This file states, per contract
primitive, what the shipped engine (`engine/`) actually provides. The
engine is a real, working code tree: stdlib-only Python (>= 3.11), zero
runtime dependencies, 420+ unit tests, an executable test entry
(`make test`), and a packaging manifest (`pyproject.toml` with a
`motoko` console script).

## Status

| Contract primitive | Contract says | Engine status |
|---|---|---|
| `StateGraph` (one engagement state) | scope, assets, findings, evidence, budget in one state object | **Shipped** — event-sourced entities over SQLite (assets / findings / hypotheses / evidence / access / services), append-only event log, materialized `entities` view, WAL single-writer |
| node (one instrument or gate) | instruments and gates are nodes | **Shipped** — a rule registry (`rules/`: access / chain / context / tech / vuln) generates hypotheses; hypotheses carry argv-rendered actions |
| conditional edge (scope fail → END) | authorization refusal ends the run | **Shipped, stricter** — label-boundary domain matching, per-IP CIDR checks, redirect-chain and certificate-SAN checks, bind_ip pinning closing the DNS-rebinding window |
| `interrupt` (circuit breaker) | destructive/mutating actions pause for the operator | **Not engine-side** — enforced by the operator shell (profile rules + in-session sign-off); engine-side action gating is future work |
| `Send` fan-out (bounded parallel recon) | parallel in-scope recon under host budget | **Bounded serial batches** — per-cycle expansion budget, per-rule backlog caps, reserved category slots; host-level concurrency lives in the operator shell |
| reducer (findings/evidence append-only) | append, never silently overwrite | **Shipped** — findings append with deterministic dedup keys (`duplicate_of` edges); assets merge by (type, value) with fact union; entity kind is frozen after first write |
| checkpointer (resume after disconnect) | engagement recovers | **Shipped** — WAL + unprocessed-observation replay + LLM-proposal recovery pass each cycle |
| `budget` state fields (strix_inflight, nuclei_concurrency, mem floor) | resource floors as graph config | **Partial** — expansion budget and batch caps engine-side; host-resource floors live in the operator shell |
| `halt` states (no-scope / out-of-scope / circuit-breaker / operator-abort) | halt is a graph state | **Partial** — scope refusals are first-class events; a halt state machine is future work |

## What ships beyond the contract

- **Wave-loop** (`motoko/loop.py`): N rounds of multi-auditor →
  adjudicator → deterministic evaluation, with executable
  ROLLBACK/STOP verdicts. Protocol adapters only (openai-chat /
  anthropic-messages / cli-subprocess); endpoints, keys-by-env-name,
  and `${VAR}`/`~` expansion live in a config file, never in code.
- **Seal** (`motoko seal`): turns a finished engagement into a
  product unit — engine commit + checkpointed graph.db +
  `engagement.manifest.json` (sha256, schema version, full census,
  integrity gates). A refused seal never leaves a manifest.
- **Failure forensics** (`motoko/failure.py`): run-failure taxonomy
  with a recovery pass wired into the orchestrator cycle.
- **Graph health** (`motoko graph_health`): stranded-hypothesis and
  broken-link sweeps that distinguish in-flight work from stalls.

## Reproducibility posture

- Runtime deps: **none** (stdlib only); behavior is pinned by the
  Python version and by the tool manifests, not by pip.
- Config layering: environment variables > in-tree live config
  (gitignored) > code defaults derived from the package location.
  No absolute home paths anywhere in the tree.
- The upstream private tree anchors toolbox versions with a manifest
  (git heads + binary hashes); this export carries none of that
  operator state.

## For contributors

The contract is the design intent. The engine is ahead of it on
verification (validators, state machines, evidence chaining, sealing)
and behind it on interrupts, parallel fan-out, and host-resource
budgeting — those are the right places to work. See AGENTS.md.
