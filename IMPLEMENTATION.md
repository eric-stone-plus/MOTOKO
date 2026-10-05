# Implementation Status Matrix

GRAPH.md is the orchestration contract. This file states, per contract
primitive, what the shipped engine (`engine/`) actually provides. The
engine is a real, working code tree: stdlib-only Python (>= 3.11), zero
runtime dependencies, and a packaging manifest (`pyproject.toml` with a
`motoko` console script).

## Status

| Contract primitive | Contract says | Engine status |
|---|---|---|
| `StateGraph` (one engagement state) | scope, assets, findings, evidence, budget in one state object | **Shipped** — event-sourced store over SQLite: an append-only event log is the source of truth and `entities`, `edges`, `services`, `observations`, `tool_run` and `scope` are materialized views of it, replayable and verified by `motoko events --verify` (WAL single-writer) |
| node (one instrument or gate) | instruments and gates are nodes | **Shipped** — a rule registry (`engine/core/rules/`: chain / context / scan / tech / vuln) generates hypotheses; hypotheses carry argv-rendered actions |
| conditional edge (scope fail → END) | authorization refusal ends the run | **Shipped prechecks** — label-boundary domain matching, per-IP CIDR checks, redirect-chain and certificate-SAN checks; checked-IP pinning applies to the built-in replay fetcher, external scanners can resolve again |
| `interrupt` (circuit breaker) | destructive/mutating actions pause for the operator | **Not engine-side** — enforced by the operator shell (profile rules + in-session sign-off); engine-side action gating is future work |
| `Send` fan-out (bounded parallel recon) | parallel in-scope recon under host budget | **Bounded serial batches** — per-cycle expansion budget, per-rule backlog caps, reserved category slots; host-level concurrency lives in the operator shell |
| reducer (findings/evidence append-only) | append, never silently overwrite | **Shipped** — findings append with deterministic dedup keys (`duplicate_of` edges); assets merge by (type, value) with fact union; entity kind is frozen after first write |
| checkpointer (resume after disconnect) | engagement recovers | **Shipped** — WAL + unprocessed-observation replay + a stranded-hypothesis recovery pass each cycle |
| `budget` state fields (strix_inflight, nuclei_concurrency, mem floor) | resource floors as graph config | **Partial** — expansion budget and batch caps engine-side; host-resource floors live in the operator shell |
| `halt` states (no-scope / out-of-scope / circuit-breaker / operator-abort) | halt is a graph state | **Partial** — scope refusals are first-class events; a halt state machine is future work |

## What ships beyond the contract

- **Scan-wave feedback** (`engine/core/scan_waves.py`): per-rule run outcomes,
  discoveries and duration are persisted at wave boundaries. Discovery,
  failure, empty-wave and duration terms adjust existing rule priorities
  within [-30, 15] — duration scores a bounded log penalty capped at −6,
  empty waves cost −4, and a chain successor earns a small persisted bonus.
  Duplicate entities do not earn discovery credit.
  Completed and interrupted wave policy resumes from disk. Cancellation closes
  tool records and saves the partial wave before releasing its writer. This is
  bounded heuristic scheduling, without automatic rule generation or parallel
  resource allocation. Missing parser/producer support remains visible in
  `motoko rules --report`; installed binaries alone do not prove a working chain.
- **Host adapter**: the opencode seat drives the `motoko` CLI directly —
  read-side status, gated `motoko strix`, `systemctl --user` shepherd control
  and report ingest. A thin TypeScript plugin once carried this surface and
  was removed 2026-10-06; the seat calls the CLI itself. The engine-side
  `motoko/1` JSONL adapter (local pipes or SSH) remains for interface
  collectors: strict SSH host-key/identity settings, finite deadlines and
  pipe-disconnect cancellation are implemented. Hosts receive aggregate state
  and pseudonymous references, never raw evidence or event payloads. Engine
  writer exclusion also spans hosts. The prior seat plugin, standalone
  host client and pi extension were retired 2026-09-28.
- **Engineering audit loop** (`engine/core/loop.py`): a config-driven cycle of
  independent auditors → adjudication → deterministic evaluation,
  with executable ROLLBACK/STOP verdicts. Protocol adapters only
  (openai-chat / anthropic-messages / cli-subprocess); endpoints,
  keys-by-env-name, and `${VAR}`/`~` expansion live in a config file,
  never in code. This is separate from scan execution. The public wheel does
  not contain the development tests; missing or incomplete test measurements
  fail visibly.
  - *Convergence honesty* — two gates keep a round from reporting success it
    did not earn, both machine-decided in `engine/core/loop_evaluate.py`:
    a leg-health quorum (`Q` in the stop rule) parks a round as
    `LEG_QUORUM_UNMET` instead of converging when fewer than a strict
    majority of the configured audit legs reported, because an empty finding
    set otherwise satisfies the convergence predicate on its own; and the
    LAND intake gate fails the round when a confirmed P0/HIGH fix carries no
    `red_command`, since a fix nobody can show was broken cannot be shown to
    have worked. Derivation: `make test` (`TestLegQuorum`,
    `TestConfirmedStatuses`, `test_missing_red_command_fails_the_round`).
  - *Planned, not shipped: the VERIFY beat.* The contract defines
    `verify_budget` (at most N=20 findings verified per round,
    highest-reputation first) and a `verified_true` status as its output.
    The shipped verify beat stamps `verified_true` only on loop findings,
    budget-capped by `loop_evaluate.VERIFY_BUDGET`; no scan finding is ever
    stamped `verified_true`.
    What the loop does stamp is `consensus_confirmed` — two or more audit
    LENSES agreeing, which on one substrate is weaker evidence than
    cross-vendor agreement because the blind spots are correlated. Both
    statuses block convergence equally (`CONFIRMED_STATUSES`), so the split
    corrects the label without loosening the predicate.
- **Event log as an executable claim** (`engine/core/events.py`): the
  append-only log is not merely written, it is readable on its own terms.
  `motoko events <id> --verify` folds the log and gates it — sequence
  continuity, the declared kind vocabulary, each kind's reference domain,
  payload integrity, finding state-machine legality and transition-chain
  continuity, edge parity in both directions, and fold-equals-materialized
  for every sourced table; any violation exits 1. `motoko events <id>
  --rebuild DIR` materializes a NEW database from the log alone, then verifies
  the result — crash recovery run, not asserted. Every writer appends through
  one funnel that refuses an undeclared kind, and one table stays outside the
  log by design (`scan_cache`: a TTL-bounded memo is disposable state, and an
  append-only log must not carry rows meant to expire). Derivation:
  `motoko events <id> --verify --json`; the gates and the
  vocabulary are pinned by the closed `EVENT_KINDS` contract in
  `engine/core/schema.py` and its write gate.
- **Seal** (`motoko seal`): turns a finished engagement into a
  product unit — engine commit + checkpointed graph.db +
  `engagement.manifest.json` (sha256, schema version, full census,
  integrity gates). A refused first seal never leaves a manifest.
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
  the deployment-host notes (`kali-container.md`); they are deployment
  evidence, not a universal release promise. The CLI derives owner-local
  Go/Cargo and user-bin search directories for child processes, even when a
  gateway supplies a minimal `PATH`; `MOTOKO_TOOL_DIRS` adds absolute
  directories for non-standard layouts.

## For contributors

The contract is the design intent. The engine is ahead of it on
verification (validators, state machines, evidence chaining, sealing)
and behind it on interrupts, parallel fan-out, and host-resource
budgeting — those are the right places to work. See AGENTS.md.
