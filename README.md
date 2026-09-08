# MOTOKO

> Shirow Masamune《攻殻機動隊》, Oshii Mamoru *Ghost in the Shell* (1995) —
> prosthetic shells, and the ghost that is not in any of them

**MOTOKO** is the philosophical and orchestration foundation of a
single-host, IM-commanded pentest composition. It asks the prior question:
*why does assembling every scanner still fail to produce an agent, and what
kind of remainder appears when the parts are bound as a graph?*

It is a concept in the same sense as [RASHOMON](https://github.com/eric-stone-plus/RASHOMON).
It does not prescribe a merged tree. Each shell keeps its own repository.
The name is a callsign, not a character.

The one engineering claim is **agent re-orchestration**: existing agents and
scanners, bound as a graph, with interrupts where a human or a scope gate
must speak. A complete agent is the citation graph, not a vendor directory.
The ghost, if the question is even well-posed, is not in any shell.

- [GHOST.md](GHOST.md) — prosthetic shells vs ghost
- [GRAPH.md](GRAPH.md) — re-orchestration contract (nodes, edges, interrupts)
- [INSTRUMENTS.md](INSTRUMENTS.md) — citation map; each shell is a different repo

The operational Hermes profile (persona, templates, skills) is **not** this
repository. It lives in the private profile
[eric-stone-plus/hermes-penetrate](https://github.com/eric-stone-plus/hermes-penetrate).
This repo names the composition. That repo is one shell among others.

## The Theseus problem

Replace the body, keep the question. Hermes, Strix, Nuclei, Firecrawl, Kali,
LangGraph — that is inventory. Inventory does not authorize itself, does not
refuse a destructive edge, and does not hash evidence. Those remainders are
the only places a ghost is even allowed to appear.

Stand Alone Complex: a pattern can act without a master copy. A MOTOKO run
is that kind of pattern — nodes firing in a graph — not a binary named Motoko.

## Instruments

MOTOKO names the problem and the graph. It does not merge the instruments:

- **Runtime shell** — Hermes Agent: IM in, tools out. Invoker of the graph,
  not a node inside it.
- **Offensive cognition** — Strix: proof-seeking pentest agent.
- **Reflex and sense** — Nuclei, Firecrawl, Kali playbooks.
- **Connective tissue** — LangGraph: nodes, edges, interrupts, reducers.
- **Operational profile** — hermes-penetrate: scope templates, discipline,
  skill set. A shell, not this ontology.

The instruments may be composed on one host. Their licenses and release
cycles remain separate. See [INSTRUMENTS.md](INSTRUMENTS.md) and [NOTICE](NOTICE).

## What this is not

- Not a monorepo of those source trees.
- Not a new scanner and not a new agent runtime.
- Not a copyrighted character, voice, likeness, or mark. Visual identity
  (logo) is original work, later.
- Not a license to copy Shirow/Oshii. Citation of a named work's *problem*
  is the same move RASHOMON makes with Kurosawa.

## Layout

| Path | Content |
|---|---|
| `GHOST.md` | Ghost/shell ontology; why the agent is an orchestration |
| `GRAPH.md` | LangGraph contract: state, nodes, interrupts |
| `INSTRUMENTS.md` | Pinned citations; license of each shell |
| `NOTICE` | This work vs cited instruments |
| `AGENTS.md` | Contributor rules |

## License

Original files in this repository are under the Apache License 2.0 — the same
family license as RASHOMON and HIGHBALL. See `LICENSE` and `NOTICE`.

That is **not** a GNU license, and it is **not** a non-profit license.

| Want | Actual license | Commercial use | Notes |
|---|---|---|---|
| GNU copyleft, network service | [AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.html) | Allowed | Strongest GNU fit for an IM gateway. Still not "non-profit". |
| GNU copyleft, distribution | [GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.html) | Allowed | Does not reach network-only use. Still not "non-profit". |
| Concept-family default | Apache-2.0 (this repo) | Allowed | Matches RASHOMON / HIGHBALL. |
| Strictly non-commercial | PolyForm Noncommercial 1.0.0 | Forbidden | **Not GNU.** |

**Cannot be done:** "GNU but non-profit." GPL/AGPL freedom 0 includes
commercial use. Adding a non-commercial clause makes the text *not* GPL/AGPL.

**Cannot be done to instruments:** this ontology cannot relicense Hermes Agent
(MIT), Nuclei (MIT), Strix (Apache-2.0), Firecrawl (AGPL-3.0), or LangGraph
(MIT). Citing a shell is not combining it. Firecrawl's AGPL stays on Firecrawl.

## Cultural anchors

- Shirow Masamune《攻殻機動隊》— prosthetic body, cyberbrain, the ghost question
- Oshii Mamoru *Ghost in the Shell* (1995), *Innocence* (2004)
- *Stand Alone Complex* — copies without an original
- [RASHOMON](https://github.com/eric-stone-plus/RASHOMON) — residual ontology;
  MOTOKO's ghost is the remainder no instrument repo can hold
