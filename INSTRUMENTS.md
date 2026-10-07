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
| Pi | Agent shell / lightweight host (retired seat line, 2026-09-28) | [earendil-works/pi](https://github.com/earendil-works/pi) | MIT |
| Codewhale | Terminal coding agent / host (live seat line, 2026-10-07) | [codewhale-hq/Codewhale](https://github.com/codewhale-hq/Codewhale) | MIT |
| Security Agent | Reference architecture for a single-agent planning/execution loop | [wr0ld/security-agent](https://github.com/wr0ld/security-agent) | Upstream terms; reference only |
| Strix | Autonomous pentest; PoC-validated findings | [usestrix/strix](https://github.com/usestrix/strix) | Apache-2.0 |
| Nuclei | Template CVE / misconfig scanner | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | MIT |
| Firecrawl | Web scrape/crawl/JS-render (self-host stack; research-fetch lane, not a scan instrument) | [firecrawl/firecrawl](https://github.com/firecrawl/firecrawl) | AGPL-3.0 |
| LangGraph | Graph *contract* runtime, if compiled | [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph) | MIT |
| Kali Linux | CLI pentest environment / playbook surface | [kali.org](https://www.kali.org/) | Distro; packages keep their own licenses |
| Tailscale | Optional overlay network carrying the SSH transport | [tailscale/tailscale](https://github.com/tailscale/tailscale) | BSD-3-Clause |

Cited host instruments are citation-only: the engine requires no host, and
[HOSTS.md](HOSTS.md) is the contract host adapters are measured against.
Tailscale is cited for the same reason — it is one way an operator can put a
private addressing boundary in front of a headless scan host. It is not a
dependency, the engine never invokes it, and nothing in this repository
configures it.

### Tools the engine actually drives

Each has a parser under `engine/core/parsers/` and at least one rule under
`engine/core/rules/`. Not forked here; cited upstream. Nuclei is driven by
rules too; Strix is operator-launched (`motoko strix`) and never
rule-ignited. The table lists the principal driven tools — `graphw00f`,
`uncover` and `dnsx` are equally rule-driven (parser + rule in-tree).

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

`gowitness` ([sensepost/gowitness](https://github.com/sensepost/gowitness))
appears as an optional node in [GRAPH.md](GRAPH.md); the shipped engine has
no parser or rule for it yet.

`naabu` ([projectdiscovery/naabu](https://github.com/projectdiscovery/naabu))
is the other half of that gap: it has a parser (its bare one-per-line output
is read by `engine/core/parsers/lines.py`) but no rule in the shipped corpus
invokes it, so it produces no graph state on its own. (`uncover` and `dnsx`
were in this gap until `R-RECON-UNCOVER-001` / `R-RECON-DNSX-001` landed;
both are now rule-driven like the table's tools.)

## How they compose on one host

The control flow is the graph in [GRAPH.md](GRAPH.md). Short form:

1. The agent seat invokes the graph by driving the `motoko` CLI (the seat
   is outside the graph).
2. `scope` → signed authorization. Empty scope → END.
3. `recon` → fingerprint (whatweb), OSINT (uncover), crawl (katana),
   names (subfinder / httpx).
4. `scan` → Nuclei + evidence (gowitness, trufflehog) + verify (arjun,
   dalfox). Kali playbooks serial for the rest.
5. Conditional: proof needed → Strix; else → report.
6. `report` → hashed evidence. Destructive edges `interrupt` for operator
   confirmation.

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
MOTOKO graph and seal rules. The codewhale seat exposes the read-side CLI
surface; the engine-side `motoko/1` adapter (interface collectors) carries
aggregate state, never the reference project's web runtime or raw artifact
store.

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
| MOTOKO engine | `0.7.0` | `engine/pyproject.toml` | engine package |
| opencode seat | retired 2026-10-08 (last noted build `0.0.0-main-202610052203`, 2026-10-06) | former seat drove the `motoko` CLI directly; a thin plugin once carried this surface and was removed 2026-10-06 | retired |
| codewhale seat | seat package 2026-10-07 | verb-gated unsandboxed wrappers over the `motoko` CLI; the host default shell sandbox defeats the strix shim's process walk and strips engine environment | live seat adapter |
| Security Agent reference | `1b039e9ed509de6f5dceb065d27d659109e7a223` | upstream commit | reviewed reference |
| Strix | deployment-selected | host deployment manifest and `strix --version` | doctor compares source and deployed bytes |
| Kali recon image | `2026.3` (deploy-host snapshot tag) | deploy-host environment (`MOTOKO_KALI_IMAGE`) | active host snapshot; rebuild before treating as a pin |

The prior seat plugin, standalone host client and Pi extension were
retired 2026-09-28. The opencode seat (2026-09-28 through 2026-10-08) is
retired. The live seat is codewhale (since 2026-10-07); it drives the
`motoko` CLI directly. The thin TypeScript plugin that briefly carried
the opencode surface was removed 2026-10-06. Strix is intentionally deployment-selected: the engine records
and reports a source/deployed mismatch through `doctor` rather than exporting
one host's tool revision as a public requirement.

## License boundary

Citation is not combination. See `NOTICE`. Nuclei, Strix, and
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
