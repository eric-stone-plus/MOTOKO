# Implementation Status Matrix

GRAPH.md is the orchestration contract. This matrix states, per contract
primitive, what the private engine implementation actually provides today,
so external contributors do not assume a shipped `StateGraph` app (the
contract file already says it does not ship one — this makes the gap
explicit and inspectable).

| Contract primitive | Contract says | Private engine status |
|---|---|---|
| `StateGraph` (one engagement state) | scope, assets, findings, evidence, budget in one state object | **Equivalent** — event-sourced entities over SQLite (assets / findings / hypotheses / evidence / access kinds, append-only event log) |
| node (one instrument or gate) | instruments and gates are nodes | **Equivalent** — rules generate hypotheses; hypotheses carry actions |
| conditional edge (scope fail → END) | authorization refusal ends the run | **Equivalent, stricter** — label-boundary domain matching, per-IP CIDR checks, redirect-chain and certificate-SAN checks, bind_ip pinning to close the DNS-rebinding window |
| `interrupt` (circuit breaker) | destructive/mutating actions pause for the operator | **Not implemented in the engine** — enforced today by the operator shell (profile rules + in-session sign-off); engine-side action gating is future work |
| `Send` fan-out (bounded parallel recon) | parallel in-scope recon under host budget | **Not parallel** — bounded serial batches today; the origin-level one-in-flight discipline lives in the operator shell |
| reducer (findings/evidence append-only) | append, never silently overwrite | **Partial** — findings/evidence append with dedup keys; assets merge by (type, value) with fact union |
| checkpointer (resume after disconnect) | engagement recovers | **Equivalent** — WAL + unprocessed-observation replay |
| `budget` state fields (strix_inflight, nuclei_concurrency, mem floor) | resource floors as graph config | **Engine-side: not enforced** — load/memory floors live in the operator shell; the engine has an expansion budget but no host-resource gate |
| `halt` states (no-scope / out-of-scope / circuit-breaker / operator-abort) | halt is a graph state | **Partial** — scope refusals are events; a first-class halt state machine is future work |

## What this means for contributors

- The contract is the design intent; the implementation is ahead of it on
  verification (validators, state machines, evidence chaining) and behind
  it on interrupts, parallel fan-out, and resource budgeting.
- Two layers are deliberate: the public repository holds the ontology and
  contracts; live scheduling and campaign state stay in the operator's
  private shell. See AGENTS.md.
