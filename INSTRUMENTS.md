# Instruments

MOTOKO names the composition. It does not merge instrument source trees.
Each implementing stack keeps its own repository, license, and release cycle.
A complete agent is this citation graph plus [GRAPH.md](GRAPH.md), not a
vendor directory. Shells vs ghost: [GHOST.md](GHOST.md).

Citations are **upstream**. Operator forks, if any, are out of scope here.

## Upstream repositories

| Instrument | Role | Repo | License |
|---|---|---|---|
| MOTOKO (this repo) | Ontology + graph contract | [eric-stone-plus/MOTOKO](https://github.com/eric-stone-plus/MOTOKO) | AGPL-3.0-or-later |
| Hermes Agent | Runtime, IM gateway, graph invoker | [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) | MIT |
| Strix | Autonomous pentest; PoC-validated findings | [usestrix/strix](https://github.com/usestrix/strix) | Apache-2.0 |
| Nuclei | Template CVE / misconfig scanner | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | MIT |
| LangGraph | Graph *contract* runtime, if compiled | [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) | MIT |
| Kali Linux | CLI pentest environment / playbook surface | [kali.org](https://www.kali.org/) | Distro; packages keep their own licenses |

### Tools the engine actually drives

Each has a parser under `engine/core/parsers/` and at least one rule under
`engine/core/rules/`. Not forked here; cited upstream.

| Tool | Role | Upstream |
|---|---|---|
| katana | crawl: URL / JS surface | [projectdiscovery/katana](https://github.com/projectdiscovery/katana) |
| subfinder | passive subdomain enumeration (DNS names only) | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| httpx | liveness + fingerprint probe | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| naabu | port scan | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) |
| gau | historical URL mining (wayback / Common Crawl) | [lc/gau](https://github.com/lc/gau) |
| amass | attack-surface mapping | [owasp-amass/amass](https://github.com/owasp-amass/amass) |
| nmap | port and service fingerprint | [nmap/nmap](https://github.com/nmap/nmap) |
| ffuf | path brute-force | [ffuf/ffuf](https://github.com/ffuf/ffuf) |
| arjun | hidden parameter discovery | [s0md3v/Arjun](https://github.com/s0md3v/Arjun) |
| dalfox | XSS verification | [hahwul/dalfox](https://github.com/hahwul/dalfox) |
| sqlmap | SQL injection verification | [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) |
| jsluice | JavaScript analysis | [bishopfox/jsluice](https://github.com/bishopfox/jsluice) |
| curl | single-request probes (robots, canary, actuator) | [curl/curl](https://github.com/curl/curl) |
| trufflehog | secret scanning | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |

### Cited in the graph contract but not driven by this engine

`uncover` ([projectdiscovery/uncover](https://github.com/projectdiscovery/uncover))
and `gowitness` ([sensepost/gowitness](https://github.com/sensepost/gowitness))
appear as optional nodes in [GRAPH.md](GRAPH.md); the shipped engine has no
parser or rule for them yet.

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
