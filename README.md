![MOTOKO](logo/motoko-wordmark.svg)

# MOTOKO

> Shirow Masamune《攻殻機動隊》, Oshii Mamoru *Ghost in the Shell* (1995) —
> prosthetic shells, and the ghost that is not in any of them.

MOTOKO asks the prior question of pentest automation: why does assembling
every scanner still fail to produce an agent — and what kind of remainder
appears when the parts are bound as a graph? Its one engineering claim is
**agent re-orchestration**: existing agents and scanners, bound as a
graph, with gates where a scope check or a human must speak. Each
instrument keeps its own upstream repository and license; a complete agent
is the citation graph, not a vendor directory. The name is a callsign,
not a character.

## What this is

- An **ontology** ([GHOST.md](GHOST.md)), a **re-orchestration contract**
  ([GRAPH.md](GRAPH.md)), and a **working engine** (`engine/`) that
  implements the contract's core: stdlib-only Python (>= 3.11), zero
  runtime dependencies, packaged with a `motoko` console script.
- A **citation map** of the instruments
  ([INSTRUMENTS.md](INSTRUMENTS.md)) — Hermes Agent (MIT), Strix
  (Apache-2.0), Nuclei (MIT), LangGraph (MIT), Kali — none of which are
  vendored, merged, or relicensed here.
- A **research base** ([RESEARCH.md](RESEARCH.md)): a survey of
  military-grade assurance patterns (CISA / NIST / DARPA / NSA / allied
  programs) and the M1–M15 adoption roadmap derived from it.

Be precise about which half ships here: the **scope gate is engine-side
and fail-closed**. The **human interrupt is not** — a destructive-edge
circuit breaker that pauses for an operator is specified in GRAPH.md but
enforced by the operator shell, not by this engine. See the `interrupt`
row of [IMPLEMENTATION.md](IMPLEMENTATION.md) before assuming the engine
refuses anything on its own.

### What this is not

- Not a monorepo of instrument source trees; not a new scanner; not a new
  agent runtime.
- Not a copyrighted character, voice, likeness, or mark. The wordmark in
  `logo/` is original lettering, and the named works are cited for the
  question they pose, the way one cites a film.

## Features

- **Fail-closed scope gate** (`engine/core/scope.py`): label-boundary
  domain matching, per-IP CIDR checks, redirect-chain and certificate-SAN
  checks. The built-in replay fetcher pins the checked IP; external scanners
  can resolve names again after their precheck. An out-of-scope action is
  refused before it runs, and refusals are first-class events.
- **Event-sourced engagement graph** (SQLite): assets, findings,
  hypotheses, evidence, and services over an append-only event
  log, with event and row committed in one transaction (WAL
  single-writer); deterministic dedup keys with `duplicate_of` edges;
  replay and recovery passes rebuild state after a disconnect.
- **Static rule-corpus check** (`motoko rules`): the bundled rule packs
  (chain / context / scan / tech / vuln) are statically checked
  with no target traffic and no LLM — never-firing rules, unresolvable
  tools, unrenderable placeholders, unconsumed chain fields. The
  producer/consumer model is derived from the engine's own source by AST,
  so new parser keys and placeholders are picked up without checker edits.
- **Unrenderable-command defense in depth**: a rule whose placeholders the
  engagement cannot render is never proposed (mint preflight); any
  unrendered placeholder that still reaches fire time is refused by the
  ACT gate, with refusals recorded as first-class events; and the corpus
  check rejects rules that could only ever bootstrap their own trigger.
- **Deterministic validators** (`engine/core/verification/`): the only
  code allowed to promote a finding — pure judgement over an injected IO
  function (replay / DOM / out-of-band canary), with machine-readable
  reason codes. A harness limitation (no browser backend, no asserted
  anonymous egress, DNS not yet pinned) parks a finding with a reason
  instead of burning retries or terminating it. The out-of-band leg has a
  real backend: an interactsh canary manager registers once per
  orchestrator and delivers its payload through the same asserted egress a
  replay uses, so "no canary wired" is a deployment state rather than a
  missing capability.
- **Seal / `--verify`** (`motoko seal`): turns a finished engagement into
  a product unit — engine commit + checkpointed graph.db +
  `engagement.manifest.json` (SHA256, schema version, full census,
  integrity gates). A refused seal leaves no manifest; `--verify`
  reconciles a sealed unit on the consumer side.
- **Adaptive scan waves** (`motoko run --wave-cycles N --max-waves N`):
  discovered facts reopen relevant assets and activate matching rule chains.
  Each wave records rule outcomes and applies bounded priority offsets to
  the next wave. Failures reduce rank; duplicate evidence earns no discovery
  credit. Completed and interrupted wave policy persists across runs. Category reservations and
  serial batches bound dispatch; producer failures block dependent actions.
- **Host adapters and remote operation**: Hermes and Pi share a standalone
  `motoko-host` client. Typed status/run tools call the engine over local pipes
  or encrypted SSH, with pinned host keys, bounded frames and disconnect
  cancellation. Raw evidence stays on the engine host. See [HOSTS.md](HOSTS.md).
- **Engineering audit loop** (`motoko loop`): a config-driven cycle of independent
  auditors → adjudication → deterministic evaluation, with executable
  ROLLBACK/STOP verdicts. Protocol adapters only (openai-chat /
  anthropic-messages / cli-subprocess); endpoints and credentials live in
  a config file that references keys by environment-variable *name*, never
  in code. This audits engineering changes; it is separate from scan waves.
  The public wheel excludes the development test suite, so a missing test
  measurement is reported as a failure rather than a green validation.
- **OPSEC layer** (`engine/core/opsec.py`): WAF sensing, per-origin
  cooldowns, canary/honeypot path guards (robots.txt entries stay
  hard-blocked), one User-Agent per engagement, stealth command variants
  (`--intensity stealth`), and a pid registry with process-group reap.
- **Unified egress policy** (`engine/core/egress.py`): one module decides
  the proxy/direct posture for host tools, container runs, and replay
  fetches — egress is configuration, not operator discipline.
- **Gated agent launches**: `motoko strix` does not spawn the agent
  itself; it delegates to a six-gate launch wrapper (egress assertion,
  DNS preflight, upstream-wired proof) that ships only in the deploy-site
  tree. Without the wrapper the command fails closed.
- **Operator surface**: `motoko doctor` (read-only environment
  self-check), `motoko health` (stranded hypotheses, broken links, parked
  findings by reason), `motoko digest`, `motoko recover` (one-shot
  stranded-hypothesis re-drive).
- **Secrets discipline**: trusted secret placeholders use supported in-memory
  transports. Host credentials are stripped before spawning scanners, and
  unsupported legacy secret arguments are refused. Raw response artifacts
  can still contain discovered secrets; evidence storage is not encrypted.

What the engine does not (yet) do engine-side is tracked honestly in
[IMPLEMENTATION.md](IMPLEMENTATION.md): operator interrupts, bounded
parallel fan-out, and host-resource budgeting live in the operator shell.

## Architecture and layout

| Path | Content |
|---|---|
| `GHOST.md` | Ghost/shell ontology — why the agent is an orchestration |
| `GRAPH.md` | The re-orchestration contract: state, nodes, edges, interrupts |
| `IMPLEMENTATION.md` | Contract primitives vs shipped-engine status matrix |
| `INSTRUMENTS.md` | Upstream citations; the license of each shell |
| `RESEARCH.md` | Military-grade assurance survey + M1–M15 adoption roadmap |
| `engine/core/` | The orchestration engine (stdlib-only Python package `core`) |
| `engine/core/rules/` | Rule packs (JSON): chain / context / scan / tech / vuln |
| `engine/core/parsers/` | Tool-output parsers (nuclei, httpx, katana, sqlmap, strix, …) |
| `engine/core/verification/` | Deterministic validators (replay / dom / oob), plus the interactsh canary manager that supplies the OOB leg's IO |
| `engine/interface/` | Read-only terminal interface (Textual; the `interface` optional extra) |
| `engine/pyproject.toml` | Packaging manifest; provides the `motoko` console script |
| `engine/integrations/` | Standalone host client, Hermes plugin and Pi extension |
| `HOSTS.md` | Host boundaries, remote protocol and installation contract |
| `LICENSE` / `NOTICE` | AGPL-3.0-or-later for original files; instrument attribution |
| `AGENTS.md` | Contributor rules |
| `.github/workflows/smoke.yml` | CI: install + `--help` + `doctor` + rule-pack assertion |
| `logo/` | Project wordmark (master: `motoko-wordmark.svg`, transparent) |

## Install and quick start

```bash
pip install ./engine        # stdlib-only, Python >= 3.11; provides `motoko`
motoko --help

# optional: the read-only terminal interface
pip install './engine[interface]'
motoko                      # opens it; `motoko status` / `motoko watch` stay stdlib

# without installing, from the source tree:
cd engine && python3 -m core --help
```

Three read-only checks to begin with:

```bash
motoko doctor                        # environment self-check: python, tools, config, egress
motoko rules --report                # static corpus check: no traffic, no LLM
motoko seal <engagement-id> --verify # reconcile a sealed engagement against its manifest
```

Command surface: `init · run · digest · query · events · loop ·
ingest-strix · health · seal · recover · doctor · rules · kali · strix`.

State lives in per-engagement SQLite graphs under `MOTOKO_HOME`.
Configuration arrives through environment variables and, for loop
endpoints, a config file in which credentials are referenced by variable
*name* and never stored.

| Variable | Purpose | Default |
|---|---|---|
| `MOTOKO_HOME` | Engagement data root (SQLite graphs, artifacts) | `<motoko_root>/tasks` |
| `MOTOKO_TOOLS` | Toolbox directory holding the instrument binaries | `<motoko_root>/tools` |
| `MOTOKO_TOOL_DIRS` | Optional absolute, `PATH`-separated extra tool directories | unset |
| `MOTOKO_WORDLIST_DIR` | Wordlists for brute-force rules | `~/.motoko/wordlists` |
| `MOTOKO_CONFIG` | Loop endpoint config (auditors + adjudicator) | in-tree `engine/loop/loop.yaml` when present, else `~/.motoko/loop.yaml` |
| `MOTOKO_EGRESS_MODE` | `proxy` = every tool rides the configured egress; unset/`direct` = per-tool policy | unset |
| `MOTOKO_EGRESS_PROXY_TOOLS` | Extra tool names (comma-separated) routed through the egress proxy | `gau` |
| `MOTOKO_UA` | User-Agent for engine probes | a stock browser UA |
| `MOTOKO_REFLECTOR_MODEL` | Enables the optional LLM reflector | unset (reflector off) |
| `MOTOKO_REFLECTOR_PROTOCOL` | Reflector wire (`anthropic` or `openai`) | `anthropic` |
| `MOTOKO_REFLECTOR_BASE_URL` | Reflector endpoint; the provider is an operator decision | unset (reflector off) |
| `MOTOKO_REFLECTOR_KEY_ENV` | *Name* of the env var holding the reflector key | unset (reflector off) |
| `MOTOKO_ALLOW_DIRECT_REPLAY` | Set to `1` to assert the host route is already anonymous, permitting raw-socket replay validation | unset (replay fails closed) |
| `MOTOKO_SECRET_*` | Per-action secrets; argv carries only an `@env:NAME` reference, never the value | — |

Tool resolution (first executable hit wins) is adapted in memory for the
account running MOTOKO, so a gateway with a minimal inherited `PATH` still
sees the pinned toolbox and owner-local installs: caller-supplied dirs →
`~/.local/bin` → `$MOTOKO_TOOLS/bin` → `$MOTOKO_TOOLS/nuclei` → Go bins
(`~/.local/share/go/bin`, `~/.local/go/bin`, `~/go/bin`) → `~/.cargo/bin` →
`PATH`. Set
`MOTOKO_TOOL_DIRS` for additional absolute directories; it never writes a
shell profile or reads credentials. A `tool` value that looks like a path
(`/`, `\`, `..`) is refused outright — actions name a bare binary, never a
path. `motoko doctor` prints which binaries actually resolve.

For an authorized engagement, initialize with both scope and starting assets:

```bash
motoko init example --scope example.invalid --seed https://example.invalid/
motoko run example --max-cycles 20 --wave-cycles 5 --max-waves 4
motoko digest example
```

Replace the reserved example inputs with the approved scope. `waiting` means
work is blocked or cooling down; inspect `retry_after_s` and health before
resuming. `wave_budget` and `cycle_budget` preserve queued work for a later run.
An orchestration exit code of zero does not mean every scanner succeeded.

`<motoko_root>` is derived from the installed package location
(`core.util.motoko_root()`), so on a wheel install the toolbox and data
defaults land beside the interpreter rather than in a source tree. Set
`MOTOKO_TOOLS` and `MOTOKO_HOME` explicitly for any real deployment.

## Documentation

- [GHOST.md](GHOST.md) — prosthetic shells vs ghost: the ontology
- [GRAPH.md](GRAPH.md) — the re-orchestration contract
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — contract vs shipped-engine
  status matrix
- [INSTRUMENTS.md](INSTRUMENTS.md) — the citation map; each shell is a
  different repo
- [RESEARCH.md](RESEARCH.md) — military-grade assurance survey and the
  M1–M15 adoption roadmap

The `engine/` tree ships code, rule packs, and packaging only; its design
docs and test suite are maintained outside this export by policy.

## CI

`smoke` ([.github/workflows/smoke.yml](.github/workflows/smoke.yml)) runs
on every push and pull request, on Python 3.11 / 3.12 / 3.13: a clean
`uv` venv install of `engine/`, `motoko --help`, `motoko doctor`, an
assertion from the *installed* site-packages tree that the rule packs
actually shipped (a floor of 31, matching the current 31-pack corpus — it
guards accidental shrinkage, and a deliberate retirement lowers it on purpose),
and a check that no build artifacts are tracked.

## License

Original files in this repository are under the
[GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.txt)
(AGPL-3.0-or-later). See `LICENSE` and `NOTICE`.

**Cannot be done to instruments:** this ontology cannot relicense Hermes
Agent (MIT), Nuclei (MIT), Strix (Apache-2.0), or LangGraph (MIT). Citing
a shell is not combining it; those instruments keep their own terms,
including commercial use. See `NOTICE`.

## Cultural anchors

- Shirow Masamune《攻殻機動隊》— prosthetic body, cyberbrain, the ghost question
- Oshii Mamoru *Ghost in the Shell* (1995), *Innocence* (2004)
- *Stand Alone Complex* — copies without an original

The default engagement directory is `tasks/`. Existing installations using
`runtime/` should move their active engagements into `tasks/`, or keep an explicit
`MOTOKO_HOME`/`--root` override. Sealed evidence belongs in its campaign archive.

`motoko doctor` checks the full deployment, including audit-loop configuration.
`motoko doctor --scope scan` checks scan-wave dependencies. Host adapters default
to scan scope and return the scope with their counts; they do not inherit model
credentials. A passing doctor and zero HIGH rule findings still require campaign
authorization, an unsealed engagement and verification of the actual outbound route.
