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
| Security Agent | Reference architecture for a single-agent planning/execution loop | [wr0ld/security-agent](https://github.com/wr0ld/security-agent) | Upstream terms; reference only |
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

### Reference architecture: `wr0ld/security-agent`

MOTOKO reviewed commit `1b039e9ed509de6f5dceb065d27d659109e7a223`
(`2026-08-05`) on 2026-09-21. The review was read-only; no source was copied
and the project is not a dependency. Its useful shape is a small control loop:
parse or resume state, plan a bounded action batch, execute one action at a
time, synchronize durable facts, and route again. It also separates control
state, checkpoints, long-lived facts, vulnerability records, raw artifacts,
and telemetry instead of putting every lifecycle into one model context.

MOTOKO adopts those mechanisms in its own terms where they fit: the
event-sourced `graph.db` is the durable engagement state, hypotheses and scan
waves are the bounded action queue, `motoko/core` performs execution-time
scope and tool checks, and loop bundles retain round evidence before any
truncation. Finding identity and evidence references stay governed by the
MOTOKO graph and seal rules. The host adapters expose aggregate state over
`motoko/1`, never the reference project's web runtime or raw artifact store.

The orchestration decision remains MOTOKO-specific. Its six deterministic
beats (`SYNC → VALIDATE → EXPAND → PRIORITIZE → ACT → REFLECT`) own scheduling;
the reflector and audit loop can propose hypotheses or priorities but cannot
transition findings. `motoko loop` separately runs lens-differentiated audit
legs, adjudication, and deterministic evaluation. LangGraph/LangChain is not
the shipped orchestration substrate, and MOTOKO does not turn into a single
LLM planner: scope gates, rule predicates, cooldowns, budgets, writer leases,
and the deterministic evaluator remain authoritative. These boundaries keep
the reference's useful feedback loop without importing its dependency stack,
web lifecycle, or model-controlled scheduler.

### Version matrix

The following versions were checked on 2026-09-22. They describe the pieces
that are installed or exported together; they are not a promise that the
scanner binaries in `MOTOKO_TOOLS` share one release cycle.

| Component | Version or revision | Source of truth | Status |
|---|---|---|---|
| Hermes Agent | `0.21.3` | Hermes checkout `pyproject.toml` | gateway runtime |
| Hermes MOTOKO plugin | `1.2.0` | `engine/integrations/hermes/motoko/plugin.yaml` | deployed byte-identical |
| `motoko-host` | `1.1.0` | `engine/integrations/host/pyproject.toml` | plugin dependency |
| MOTOKO engine | `0.7.0` | `engine/pyproject.toml` | engine package |
| Pi MOTOKO package / skill | `1.0.0` | `package.json` / `SKILL.md` | package release line |
| Security Agent reference | `1b039e9ed509de6f5dceb065d27d659109e7a223` | upstream commit | reviewed reference |
| Strix | deployment-selected | host deployment manifest and `strix --version` | doctor compares source and deployed bytes |
| Kali recon image | `2026.3` (`20260919`) | `engine/core/tools_anchor/kali/kali-container.md` | active host snapshot; rebuild before treating as a pin |

The Hermes plugin and host versions are deliberately bumped together: the
plugin requires the matching `motoko-host` release. The Pi package stays on
its own release line because its manifest is consumed by Pi, not by the
Hermes plugin. Strix is intentionally deployment-selected: the engine records
and reports a source/deployed mismatch through `doctor` rather than exporting
one host's tool revision as a public requirement.

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
