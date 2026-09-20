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
| Pi | Agent shell / lightweight host; typed extension | [earendil-works/pi](https://github.com/earendil-works/pi) | MIT |
| Strix | Autonomous pentest; PoC-validated findings | [usestrix/strix](https://github.com/usestrix/strix) | Apache-2.0 |
| Nuclei | Template CVE / misconfig scanner | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | MIT |
| LangGraph | Graph *contract* runtime, if compiled | [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) | MIT |
| Kali Linux | CLI pentest environment / playbook surface | [kali.org](https://www.kali.org/) | Distro; packages keep their own licenses |
| Tailscale | Optional overlay network carrying the SSH transport | [tailscale/tailscale](https://github.com/tailscale/tailscale) | BSD-3-Clause |

Both hosts are citation-only: the engine requires neither, and
[HOSTS.md](HOSTS.md) is the contract each adapter is measured against.
Tailscale is cited for the same reason — it is one way an operator can put a
private addressing boundary in front of a headless scan host. It is not a
dependency, the engine never invokes it, and nothing in this repository
configures it.

### Tools the engine actually drives

Each has a parser under `engine/core/parsers/` and at least one rule under
`engine/core/rules/`. Not forked here; cited upstream. Nuclei and Strix are
driven by rules too and are cited in the table above.

| Tool | Role | Upstream |
|---|---|---|
| katana | crawl: URL / JS surface | [projectdiscovery/katana](https://github.com/projectdiscovery/katana) |
| subfinder | passive subdomain enumeration (DNS names only) | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| httpx | liveness + fingerprint probe | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| gau | historical URL mining (wayback / Common Crawl) | [lc/gau](https://github.com/lc/gau) |
| amass | attack-surface mapping | [owasp-amass/amass](https://github.com/owasp-amass/amass) |
| nmap | port and service fingerprint | [nmap/nmap](https://github.com/nmap/nmap) |
| ffuf | path brute-force | [ffuf/ffuf](https://github.com/ffuf/ffuf) |
| kr | API route discovery, redirect chains included | [assetnote/kiterunner](https://github.com/assetnote/kiterunner) |
| arjun | hidden parameter discovery | [s0md3v/Arjun](https://github.com/s0md3v/Arjun) |
| dalfox | XSS verification | [hahwul/dalfox](https://github.com/hahwul/dalfox) |
| sqlmap | SQL injection verification | [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) |
| jwt_tool | offline JWT generation for alg=none / JWK-injection probes | [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) |
| wpscan | WordPress core/plugin/theme version and advisory enumeration | [wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) |
| git-dumper | source recovery from an exposed `.git` | [arthaud/git-dumper](https://github.com/arthaud/git-dumper) |
| enum4linux | SMB / Windows enumeration, JSON out | [cddmp/enum4linux-ng](https://github.com/cddmp/enum4linux-ng) |
| jsluice | JavaScript analysis | [bishopfox/jsluice](https://github.com/bishopfox/jsluice) |
| curl | single-request probes (robots, canary, actuator) | [curl/curl](https://github.com/curl/curl) |
| h2csmuggler | cleartext HTTP/2 (h2c) upgrade probe — is smuggling possible here | [assetnote/h2csmuggler](https://github.com/assetnote/h2csmuggler) |
| trufflehog | secret scanning | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |
| interactsh-client | out-of-band callback backend for the OOB validator | [projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) |

One name differs from its package: the rules invoke `enum4linux`, while Kali
ships the enumerator as `enum4linux-ng`, so a container built from it needs
that binary reachable under the name the rules use. `kr` is Kiterunner's own
binary name.

One entry is not a rule tool. `interactsh-client` never appears in a rule's
command line: it is owned by the engine's canary manager
(`engine/core/verification/interactsh.py`), which registers once per
orchestrator, hands a distinct payload to each out-of-band validation, and
delivers it through the same asserted egress a replay uses. A long-lived
poller cannot be a bounded rule action — as one-shot it could only exit on the
timeout — so the session lives with the validator instead.

### Cited in the graph contract but not driven by this engine

`uncover` ([projectdiscovery/uncover](https://github.com/projectdiscovery/uncover))
and `gowitness` ([sensepost/gowitness](https://github.com/sensepost/gowitness))
appear as optional nodes in [GRAPH.md](GRAPH.md); the shipped engine has no
parser or rule for them yet.

`naabu` ([projectdiscovery/naabu](https://github.com/projectdiscovery/naabu))
and `dnsx` ([projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx))
are the other half of that gap: both have a parser (their bare one-per-line
output is read by `engine/core/parsers/lines.py`) but no rule in the shipped
corpus invokes them, so neither produces graph state on its own.

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

One cited tool is not open source in the OSI sense and is worth naming before
anyone ships it: WPScan is dual-licensed under its own Public Source License,
free for non-commercial use and for testing your own systems, with
commercialization requiring a separate commercial license from its authors.
Invoking it as a separate process does not make this repository's license
apply to it, and nothing here is a legal reading — check upstream before
putting it in a paid service. Its vulnerability data also comes from an API
with a free daily request allowance; without a token the tool still reports
versions and components, which is exactly the inventory half the engine's
parser reads.
