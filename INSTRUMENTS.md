# Instruments

MOTOKO names the composition. It does not merge instrument source trees.
Each implementing stack keeps its own repository, license, and release cycle.
A complete agent is this citation graph plus [GRAPH.md](GRAPH.md), not a
vendor directory. Shells vs ghost: [GHOST.md](GHOST.md).

Citations are **upstream**. Operator forks, if any, are out of scope here.

## Upstream repositories

| Instrument | Role | Repo | License |
|---|---|---|---|
| MOTOKO (this repo) | Ontology + graph contract | [eric-stone-plus/MOTOKO](https://github.com/eric-stone-plus/MOTOKO) | PolyForm Noncommercial 1.0.0 |
| Hermes Agent | Runtime, IM gateway, graph invoker | [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) | MIT |
| Strix | Autonomous pentest; PoC-validated findings | [usestrix/strix](https://github.com/usestrix/strix) | Apache-2.0 |
| Nuclei | Template CVE / misconfig scanner | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | MIT |
| Firecrawl | Self-host crawl → markdown for in-scope recon | [firecrawl/firecrawl](https://github.com/firecrawl/firecrawl) | AGPL-3.0 |
| LangGraph | Graph runtime for this contract | [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) | MIT |
| Kali Linux | CLI pentest environment / playbook surface | [kali.org](https://www.kali.org/) | Distro; packages keep their own licenses |

Related ProjectDiscovery tools used as recon nodes, not forked here:
[katana](https://github.com/projectdiscovery/katana),
[subfinder](https://github.com/projectdiscovery/subfinder),
[httpx](https://github.com/projectdiscovery/httpx),
[naabu](https://github.com/projectdiscovery/naabu).

## How they compose on one host

The control flow is the graph in [GRAPH.md](GRAPH.md). Short form:

1. IM → Hermes gateway invokes the graph (Hermes is outside the graph).
2. `scope` → signed authorization. Empty scope → END.
3. `recon` fan-out → Firecrawl + Katana + subdomain/HTTP probe.
4. `scan` fan-out → Nuclei + port scan. Kali playbooks for the rest.
5. Conditional: proof needed → Strix; else → report.
6. `report` → hashed evidence. Destructive edges `interrupt` for IM confirmation.

Firecrawl is recon content, not a vulnerability scanner. Katana is the
security crawler; Firecrawl is the readable-page crawler.

## License boundary

Citation is not combination. See `NOTICE`. Firecrawl's AGPL-3.0 stays on
Firecrawl. Hermes Agent, Nuclei, Strix, and LangGraph stay on their own
licenses. This repository does not relicense them.
