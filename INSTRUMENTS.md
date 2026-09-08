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
| LangGraph | Graph *contract* runtime, if compiled | [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) | MIT |
| Kali Linux | CLI pentest environment / playbook surface | [kali.org](https://www.kali.org/) | Distro; packages keep their own licenses |

Related recon/verify tools used as graph nodes, not forked here:
[katana](https://github.com/projectdiscovery/katana),
[subfinder](https://github.com/projectdiscovery/subfinder),
[httpx](https://github.com/projectdiscovery/httpx),
[naabu](https://github.com/projectdiscovery/naabu),
[uncover](https://github.com/projectdiscovery/uncover),
[dalfox](https://github.com/hahwul/dalfox),
[gowitness](https://github.com/sensepost/gowitness),
[arjun](https://github.com/s0md3v/Arjun),
[trufflehog](https://github.com/trufflesecurity/trufflehog).

## How they compose on one host

The control flow is the graph in [GRAPH.md](GRAPH.md). Short form:

1. IM → Hermes gateway invokes the graph (Hermes is outside the graph).
2. `scope` → signed authorization. Empty scope → END.
3. `recon` → fingerprint (whatweb), OSINT (uncover), crawl (katana),
   names (subfinder / httpx).
4. `scan` → Nuclei + evidence (gowitness, trufflehog) + verify (arjun,
   dalfox). Kali playbooks serial for the rest.
5. Conditional: proof needed → Strix; else → report.
6. `report` → hashed evidence. Destructive edges `interrupt` for IM confirmation.

Katana is the security crawler.

## License boundary

Citation is not combination. See `NOTICE`. Hermes Agent, Nuclei, Strix, and
LangGraph stay on their own licenses. This repository does not relicense them.
