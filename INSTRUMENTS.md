# Instruments

MOTOKO names the composition. It does not merge instrument source trees.
Each implementing stack keeps its own repository, license, and release cycle.
A complete agent is this citation graph plus [GRAPH.md](GRAPH.md), not a
vendor directory. Shells vs ghost: [GHOST.md](GHOST.md).

Some shells are private. That is intended: the ontology is public; the
prostheses need not be.

## Pinned repositories

| Instrument | Role | Repo | License |
|---|---|---|---|
| MOTOKO (this repo) | Ontology + graph contract | [eric-stone-plus/MOTOKO](https://github.com/eric-stone-plus/MOTOKO) | PolyForm Noncommercial 1.0.0 |
| Hermes Agent | Runtime, IM gateway, graph invoker | [eric-stone-plus/hermes-agent](https://github.com/eric-stone-plus/hermes-agent) | MIT (Nous Research) |
| hermes-penetrate | Operational profile: persona, templates, skills | [eric-stone-plus/hermes-penetrate](https://github.com/eric-stone-plus/hermes-penetrate) | MIT |
| Strix | Autonomous pentest; PoC-validated findings | [eric-stone-plus/strix](https://github.com/eric-stone-plus/strix) | Apache-2.0 |
| Nuclei | Template CVE / misconfig scanner | [eric-stone-plus/nuclei](https://github.com/eric-stone-plus/nuclei) | MIT (ProjectDiscovery) |
| Firecrawl | Self-host crawl → markdown for in-scope recon | [eric-stone-plus/firecrawl](https://github.com/eric-stone-plus/firecrawl) | AGPL-3.0 |
| LangGraph | Graph runtime for this contract | [eric-stone-plus/langgraph](https://github.com/eric-stone-plus/langgraph) | MIT (LangChain, Inc.) |

Upstream projects (unchanged by a private mirror): `nousresearch/hermes-agent`,
`usestrix/strix`, `projectdiscovery/nuclei`, `firecrawl/firecrawl`,
`langchain-ai/langgraph`.

Kali and web-pentest playbooks live inside the penetrate profile, not here.

## How they compose on one host

The control flow is the graph in [GRAPH.md](GRAPH.md). Short form:

1. IM → Hermes gateway invokes the graph (Hermes is outside the graph).
2. `scope` → signed authorization. Empty scope → END.
3. `recon` fan-out → Firecrawl + Katana + subdomain/HTTP probe.
4. `scan` fan-out → Nuclei + port scan + Trivy. Kali playbooks for the rest.
5. Conditional: proof needed → Strix; else → report.
6. `report` → hashed evidence. Destructive edges `interrupt` for IM confirmation.

Firecrawl is recon content, not a vulnerability scanner. Katana is the
security crawler; Firecrawl is the readable-page crawler.

## License boundary

Citation is not combination. See `NOTICE`. Firecrawl's AGPL-3.0 stays on
Firecrawl. Hermes Agent, Nuclei, Strix, LangGraph, and the penetrate profile
stay on their own licenses. This repository does not relicense them.
