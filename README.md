<p align="center">
  <img src="logo/motoko-wordmark.svg" alt="MOTOKO" width="680">
</p>

# MOTOKO

> Shirow Masamune《攻殻機動隊》, Oshii Mamoru *Ghost in the Shell* (1995) —
> prosthetic shells, and the ghost that is not in any of them

**MOTOKO** is the philosophical and orchestration foundation of a
single-host, IM-commanded pentest composition. It asks the prior question:
*why does assembling every scanner still fail to produce an agent, and what
kind of remainder appears when the parts are bound as a graph?*

It does not prescribe a merged tree. Each shell keeps its own upstream
repository. The name is a callsign, not a character.

The one engineering claim is **agent re-orchestration**: existing agents and
scanners, bound as a graph, with gates where a scope check or a human must
speak. A complete agent is the citation graph, not a vendor directory.
The ghost, if the question is even well-posed, is not in any shell.

Be precise about which half ships here: the **scope gate is engine-side and
fail-closed** (label-boundary domain matching, per-IP CIDR checks,
redirect-chain and certificate-SAN checks, bind-IP pinning). The **human
interrupt is not** — a destructive-edge circuit breaker that pauses for an
operator is specified in [GRAPH.md](GRAPH.md) but is enforced by the operator
shell, not by this engine. See the `interrupt` row of
[IMPLEMENTATION.md](IMPLEMENTATION.md) before assuming the engine will refuse
anything on its own.

- [GHOST.md](GHOST.md) — prosthetic shells vs ghost
- [GRAPH.md](GRAPH.md) — re-orchestration contract (nodes, edges, interrupts)
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — contract vs shipped-engine status matrix
- [INSTRUMENTS.md](INSTRUMENTS.md) — citation map; each shell is a different repo

This repository carries the ontology, the re-orchestration contract,
and the engine that implements the contract's core. The engine is
stdlib-only Python; live scheduling state, operator profiles, engagement
data, and tool binaries are not part of this tree. The IM display name
may wear the callsign; that still does not put a ghost in this repo.

## The Theseus problem

Replace the body, keep the question. Hermes, Strix, Nuclei, Kali,
ProjectDiscovery recon, LangGraph — that is inventory. Inventory does not
authorize itself, does not refuse a destructive edge, and does not hash
evidence. Those remainders are the only places a ghost is even allowed
to appear.

Stand Alone Complex: a pattern can act without a master copy. A MOTOKO run
is that kind of pattern — nodes firing in a graph — not a binary named Motoko.

## Instruments

MOTOKO names the problem and the graph. It does not merge the instruments:

- **Runtime shell** — [Hermes Agent](https://github.com/NousResearch/hermes-agent):
  IM in, tools out. Invoker of the graph, not a node inside it.
- **Offensive cognition** — [Strix](https://github.com/usestrix/strix):
  proof-seeking pentest agent.
- **Reflex and sense** — [Nuclei](https://github.com/projectdiscovery/nuclei),
  ProjectDiscovery recon (katana, subfinder, httpx, and kin), Kali playbooks.
- **Connective tissue** — [LangGraph](https://github.com/langchain-ai/langgraph)
  names nodes, edges, and interrupts so the composition is inspectable.
  Live scheduling today is the operator-profile motoko skill; this repo
  does not ship a compiled graph.

The instruments may be composed on one host. Their licenses and release
cycles remain separate. See [INSTRUMENTS.md](INSTRUMENTS.md) and [NOTICE](NOTICE).

## What this is not

- Not a monorepo of those source trees.
- Not a new scanner and not a new agent runtime.
- Not a copyrighted character, voice, likeness, or mark. The wordmark in
  `logo/` is original lettering.
- Not a license to copy Shirow/Oshii. Named works are cited as a problem,
  the way one cites a film for a question it poses, not as a character to play.

## Layout

| Path | Content |
|---|---|
| `README.md` | This file |
| `GHOST.md` | Ghost/shell ontology; why the agent is an orchestration |
| `GRAPH.md` | LangGraph contract: state, nodes, interrupts |
| `IMPLEMENTATION.md` | Contract primitives vs shipped-engine status |
| `INSTRUMENTS.md` | Upstream citations; license of each shell |
| `engine/core/` | The orchestration engine (stdlib-only Python package `core`) |
| `engine/core/rules/` | Rule packs: `access` / `chain` / `context` / `scan` / `tech` / `vuln` |
| `engine/pyproject.toml` | Packaging manifest; provides the `motoko` console script |
| `LICENSE` | AGPL-3.0-or-later (original files in this repository) |
| `NOTICE` | This work vs cited instruments |
| `AGENTS.md` | Contributor rules |
| `.github/workflows/smoke.yml` | CI: install + `--help` + `doctor` + rule-pack assertion |
| `logo/` | Project wordmark. Master: `motoko-wordmark.svg` (transparent). |

## The tool

```bash
pip install ./engine     # stdlib-only, Python >= 3.11; provides `motoko`
motoko --help
motoko doctor            # environment self-check
```

Command surface: `init · run · digest · query · events · loop ·
ingest-strix · health · seal · recover · doctor · kali · strix`.

State lives in per-engagement SQLite graphs under `MOTOKO_HOME`.
Configuration arrives through environment variables and, for loop endpoints,
a config file in which credentials are referenced by variable *name* and
never stored.

| Variable | Purpose | Default |
|---|---|---|
| `MOTOKO_HOME` | Engagement data root (SQLite graphs, artifacts) | `<motoko_root>/runtime` |
| `MOTOKO_TOOLS` | Toolbox directory holding the instrument binaries | `<motoko_root>/tools` |
| `MOTOKO_WORDLIST_DIR` | Wordlists for brute-force rules | `~/.motoko/wordlists` |
| `MOTOKO_CONFIG` | Loop endpoint config (auditors + adjudicator) | `engine/loop/loop.yaml`, else `~/.motoko/loop.yaml` |
| `MOTOKO_EGRESS_MODE` | `proxy` = every tool rides the configured egress; unset/`direct` = per-tool policy | unset |
| `MOTOKO_EGRESS_PROXY_TOOLS` | Extra tool names (comma-separated) routed through the egress proxy | `gau` |
| `MOTOKO_UA` | User-Agent for engine probes | a stock browser UA |
| `MOTOKO_REFLECTOR_MODEL` | Enables the optional LLM reflector | unset (reflector off) |
| `MOTOKO_REFLECTOR_BASE_URL` | Reflector endpoint; the provider is an operator decision | unset (reflector off) |
| `MOTOKO_REFLECTOR_KEY_ENV` | *Name* of the env var holding the reflector key | unset (reflector off) |
| `MOTOKO_ALLOW_DIRECT_REPLAY` | Set to `1` to assert the host route is already anonymous, permitting raw-socket replay validation | unset (replay fails closed) |
| `MOTOKO_SECRET_*` | Per-action secrets; argv carries only an `@env:NAME` reference, never the value | — |

Tool resolution (first executable hit wins): caller-supplied dirs →
`~/.local/bin` → `$MOTOKO_TOOLS/bin` → `$MOTOKO_TOOLS/nuclei` → `PATH`.
A `tool` value that looks like a path (`/`, `\`, `..`) is refused outright —
actions name a bare binary, never a path. `motoko doctor` prints which
binaries actually resolve.

`<motoko_root>` is derived from the installed package location
(`core.util.motoko_root()`), so on a wheel install the toolbox and data
defaults land beside the interpreter rather than in a source tree. Set
`MOTOKO_TOOLS` and `MOTOKO_HOME` explicitly for any real deployment.

## License

Original files in this repository are under the
[GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.txt)
(AGPL-3.0-or-later). See `LICENSE` and `NOTICE`.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version. Derivatives distributed under the same terms;
no additional restrictions apply.

**Cannot be done to instruments:** this ontology cannot relicense Hermes Agent
(MIT), Nuclei (MIT), Strix (Apache-2.0), or LangGraph (MIT). Citing a shell
is not combining it. Those instruments still allow commercial use under
*their* terms.

## Cultural anchors

- Shirow Masamune《攻殻機動隊》— prosthetic body, cyberbrain, the ghost question
- Oshii Mamoru *Ghost in the Shell* (1995), *Innocence* (2004)
- *Stand Alone Complex* — copies without an original
