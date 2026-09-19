# RESEARCH.md — Military-Grade Assurance: External Survey and Adoption Roadmap

- Research date: 2026-09-18. External data (repository metrics, versions,
  catalog snapshots) is as of 2026-09-17/18; figures that drift with
  upstream carry their own timestamps.
- Source: an internal review, condensed and redacted for this public tree.
  The review itself was read-only: it changed no files and cloned nothing.
- Material scope: **lawful public sources only**. Leaked-tooling class
  material (Vault 7 / Shadow Brokers and kin) was not fetched, not read,
  and is not adopted. In an engine whose premise is authorized-only
  operation with auditable, sealable evidence, a technique that cannot
  prove its provenance is a liability, not an asset. Where a technique is
  worth having, it is taken from a source that may lawfully publish it
  (ATT&CK / CAPEC / ScubaGear / the AIxCC-CGC open-source CRSes), so the
  manifest can state its origin.
- Acceptance: see the stamp at the bottom of this file.

## 0. One-line conclusion

**"Military-grade" does not mean more exploits.** Every genuinely
military-grade project covered here is graded on **assurance, provenance,
and adjudication** — not on capability. The engine's mechanism layer
already lives on that axis (event sourcing, capability-object isolation,
static corpus checking, a fail-closed posture). What is missing is three
things that can be shown externally: a standardized assessment artifact
(OSCAL SAR), a machine-readable authorization object (ROE-as-data), and
independent rescoring that never trusts an agent's self-report (the AIxCC
scoring pattern). All three are days of work away, because the foundation
already exists.

## 1. Fusion verdicts for three upstream libraries

### 1.1 `zhaoxuya520/reverse-skill` — MIT

Metrics at research time: 36,289 stars / 5,013 forks / 142 commits /
12 contributors / v1.0.1; last push 2026-09-03 (GitHub `pushed_at`).

**Fusion layer: governance, not content.** The upstream design is three
tiers — routing rules, an executable case-init/scope gate, then scenario
skills with tools — plus a timeline and an Evidence→Finding→Path report
with a field-journal for precedent reuse.

| Layer | Upstream implementation | Value | Verdict |
|---|---|---|---|
| Authorization gate | `case-init` produces `scope.md` with `auth.status: granted\|pending\|denied`, `basis: written_contract\|bug_bounty_scope\|ctf_public\|own_system\|lab_only`, `in_scope`/`out_scope`, `network_profile`, and `signoff.ready_for_act` (auth granted AND assets non-empty AND not offline-without-sample). A `case-guard` re-checks before any action and exits 2 when not ready; its `-Force` compatibility flag cannot bypass the hard gate (upstream issue #135, independently reproduced) | Highest | Adopt the pattern: scope as an executable file, hashed into the seal manifest, read by the launch path |
| Precedent layer | `field-journal/` precedent files (auth / reverse / pentest) plus an index consulted before routing; precedents are a lazy layer, loaded only when the agent hesitates | Medium | Adopt as an agent-facing pitfall journal |
| Governance docs | `scope-contract.md` (no scope → read-only, no active probing), `role-map.md` (explicitly no multi-agent server; one agent wears role prefixes on timeline tags), append-only timeline (existing time blocks must not be edited; every entry carries a `decision_delta` and `carry_forward_refs`), `evidence-finding-path.md`, `skill-supply-chain.md` (threat table: poisoned skills, `curl\|bash`, MCP blind trust, prompt injection in skill bodies, scope drift, skill-stack overload) | High | Adopt as standing doctrine; the supply-chain checklist becomes the admission gate for any future skill import |
| Routing layer | `routing.json`: 45 rules with bilingual `must`/`mustAll`/`exclude` regexes, global priority, `fallbackId`; a `master-route` scorer; a 175-case routing benchmark run in CI on Windows + Ubuntu | Low | **Not adopted as a router.** The upstream contract is imperative (the agent must execute the router, open only the PRIMARY skill, and not preload); the host runtime here loads skills by scan-and-inject, so a transplanted router would be a gate no model can invoke. The routing-benchmark idea — a regression set of "input phrase → expected skill" — is worth stealing |
| Content layer | ~40 skills plus references; a payloader corpus of 3.68 MB (72.7% of the import volume); a reverse-engineering toolchain cluster (ida / ghidra / r2 / binary-ninja / dotnet / go-rust / js / protocol / mobile) | Medium | Keep, with category splits and a doctrine overlay |

**Not fused:** `CTF-Sandbox-Orchestrator/` (42 competition sub-skills,
**GPLv3**, separate LICENSE — would pollute the export);
`burp-mcp-full/` (commercial-tool dependency); the Codex-adapter plugin
(host-specific).

**MCP boundary:** 16 of 43 modules name concrete MCP servers (`ida-mcp`,
`burp-mcp`, `js-reverse-mcp`/`jshookmcp`, dnSpy MCP, `binary-ninja-mcp`,
`ghidra-mcp`, `r2mcp`, `xquik-mcp`, `mcp-kali-server`/`metasploitmcp`).
Upstream policy is external, opt-in, never auto-registered; automatic
installation is limited to a version-pinned bootstrap manifest that CI
fails on unpinned versions. That is structurally the same opt-in pattern
this engine uses for external legs, and the doctrine carries over. Note:
upstream issue #134 identifies the `README_AI` "execute section 0
immediately" auto-bootstrap as an abuse vector in itself — **that
auto-execution contract is not copied.**

### 1.2 `Rheinmetall/tacticalapi` — EPL-2.0

gRPC `.proto` contracts; 2 commits / 22 stars / 6 forks.

**Fusion layer: contract patterns, not the proto.**

- **Closed enumerations enforced at the contract layer.** A `oneof` in
  `types.proto` is a compile-time closed set. The transferable answer to
  "where should a closed vocabulary be enforced": **at load time, not at
  report time.**
- **Contract-first, version-anchored consumption.** The README recommends
  `git submodule add` so downstream tracks contract updates. The engine's
  seal manifest recording `engine_commit` is a stronger form of the same
  idea (it anchors the implementation, not only the contract) — ahead
  here, nothing to change.
- **Not fused:** the gRPC/C++ transport stack (irrelevant to a Python
  orchestrator).

### 1.3 `Rheinmetall/onboardapi` — dual-licensed

8 commits / 46 stars / 103 `.rmodel` files; `ddkit`/`rmodel-api` are not
public. **Fusion layer: three concepts and one release model. Zero code.**

**License correction (three earlier reviews and their synthesis all missed
this):**

- The `.rmodel` interface definitions are EPL-2.0, but the precompiled
  runtime is **proprietary EULA-RME-SDK-1.0**, distributed only via
  Releases. "EPL-2.0, no license-pollution problem" was factually wrong
  for this repository.
- **Both READMEs carry an export-control clause**: "Use, distribution,
  and import of this software may be subject to export control, sanctions,
  and other applicable laws".
- EPL-2.0 is weak-reciprocal. The public export of this repository keeps
  its own license (AGPL-3.0-or-later, see `LICENSE`); it must not switch
  to EPL "to align with military-grade".
- The actual pollution risk this round was low (concepts absorbed, no code
  moved; the cited `.rmodel`/`.proto`/README files sit on the EPL side).
  But that conclusion was asserted, not derived. **For any future
  external-repository review, the license audit is the first section of
  the brief, not a footnote.**

Adopted concepts:

| Item | Upstream | Verdict |
|---|---|---|
| Docs generated from a single spec source | `.rmodel` → ddkit-generated docs, with PlantUML sequence diagrams embedded as the interaction contract | Narrow adoption: generate the tool registry from the rule corpus, with a drift check in CI; a whole-file generator is deferred and must carry trigger conditions (an existence-only drift check cannot catch content rot) |
| Liveness contract | Watchdog: connection lost → `IsRemoved=true` → consumer data explicitly invalidated | Adopted narrowly: merge paths must check the terminal state of a tool run before trusting its output; no standalone wave — a synchronous executor has no in-flight observations, and a full validity column is schema churn |
| Closed class vocabulary | Type closure at the `.rmodel` level (the tacticalapi `oneof` lesson) | Adopted: the loader rejects unknown classes; the vocabulary is derived, not hand-maintained |
| Multi-dimensional boolean finding status | Status × IsSuppressed × IsAcknowledged × IsAutoAcknowledged, plus an envelope `IsRemoved` | Deferred, with explicit triggers (active verification queue >30–50, ≥2 coexisting park reasons, or an override need). The engine already carries a 10-state ladder with reason-coded `verification_blocked`. `IsRemoved` must never become a hard delete |
| Sequence diagrams | `@startuml` embedded in `.rmodel` comments | Deferred: GitHub renders mermaid, not PlantUML; triggers must be split per diagram purpose |
| **Release model** | Open interface / closed runtime + SPDX per-file headers + a digital twin (Python examples and demo command presets — develop and test against the contract without the closed runtime) | **Adopted:** the public tree should carry replay fixtures generated from sealed evidence, so an external contributor can develop and test against the contract without executing any tool. This is the same artifact as M4 below, put to a second use |

Explicitly not moved (reviewed and confirmed): the gRPC/C++ transport; the
`.rmodel` DSL (JSON suffices at this corpus scale); and the
"documentation model decoupled from the wire format" anti-pattern —
confirmed by the onboardapi README itself ("the `.rmodel` data model is
for documentation purposes only and does not reflect the actual interface
used on the communication layer"). The engine's SQLite graph is the truth,
which is better.

## 2. Military-grade patterns (US + allied + autonomous frameworks)

> Honest environmental bookkeeping: from the research environment, `*.mil`
> DNS did not resolve (`public.cyber.mil`, `p1/repo1/registry1.dso.mil`,
> `darpa.mil`, `cybercom.mil`), `nsa.gov`/`media.defense.gov` returned edge
> 403s, and `web.archive.org` timed out. Anything not directly consulted
> for that reason is marked **unverified** in §5 rather than cited from
> memory.

### 2.1 United States: 12 absorbable patterns

| # | Project | Org | License | Pattern | One transferable idea |
|---|---|---|---|---|---|
| 1 | [ScubaGear](https://github.com/cisagov/ScubaGear) | CISA | CC0-1.0, active, 2,670★ | PowerShell collection → OPA/Rego verdicts → HTML/JSON/CSV; 73 `.rego` files, 181 unified verdict records | The unified verdict record `{PolicyId, Criticality, Commandlet[], ActualValue, ReportDetails, RequirementMet}` — see §2.1.1 |
| 2 | ScubaGear [`.regal/config.yaml`](https://github.com/cisagov/ScubaGear/blob/main/.regal/config.yaml) | CISA | CC0 | Naming conventions written as regex + `level: error`; every suppression carries a written, attributable in-file reason | The mature form of a corpus checker: lint rules as data, waivers with owners |
| 3 | [OSCAL 1.2.3](https://github.com/usnistgov/OSCAL) (2026-08-07) | NIST | Fully open; Metaschema XML as the single source → JSON Schema + XSD + bidirectional XSLT | assessment-results: findings / observations / risks / reviewed-controls / back-matter | The government-recognizable artifact — see §2.1.2 |
| 4 | [STIG Manager](https://github.com/NUWCDIVNPT/stig-manager) | US Navy NAVSEA + SAIC | MIT (client excepted), © 2020-2026 US Federal Gov | Collections = Assets × STIGs × Reviews; `.ckl`/`.cklb`/XCCDF import; OpenAPI 3.0.1; Accept/Reject review flow | **Content hash as rule identity**: when DISA ships a new release, only rules whose check content changed need re-review — upgrades a ratchet from "count must not regress" to "conclusions auto-inherit when content is unchanged" |
| 5 | [CGC `ti-api-spec.txt`](https://github.com/CyberGrandChallenge/cgc-release-documentation/blob/master/ti-api-spec.txt) (`draft-darpa-ti-api-01`) | DARPA | Public | "The Team Interface is the CRS's only mechanism to provide input to the CFE": POST {CBs, POVs, IDS rules} / GET {status, feedback, consensus evaluation} | **The narrow waist**: rather than surrounding an agent with gates, give it one API and put the gates on the API. The agent never reaches the target; it posts structured artifacts the engine adjudicates independently |
| 6 | [AIxCC open archive](https://archive.aicyberchallenge.com/) + [scoring-pipeline](https://github.com/AIxCyberChallenge/scoring-pipeline) | DARPA | All 7 finalist CRSes open source; scoring-pipeline MIT | Scores recomputed after the fact from the audit event log (`audit-<round>.jsonl` → ordered plugin chain → Postgres → re-run PoV/patch evaluation → dedup → `rescore_passed/failed/errored`) | An event-sourced engine is naturally adapted: **never trust an agent's self-report**; an independent consumer scores the same event stream |
| 7 | [Fuzzing Brain](https://arxiv.org/abs/2509.07225) (repo moved o2lab → [fuzzingbrain](https://github.com/fuzzingbrain), redirect live) | AIxCC finalist | Apache-2.0, active | Pipeline `analyze → build fuzzers → direction planning → sp-generate → sp-verify → pov → triage → verify → report`; "nothing that hasn't crashed a real build is reported"; JSON task files pin every reference to a commit; delta scanning; `pov/patch/harness` task types; REST + MCP; `--budget <usd>` | Anti-hallucination = execution verification, and spend is capped with the actual value recorded (public example: 14.6 minutes, $2.14, cap $20). The paper self-reports 28 vulnerabilities found incl. 6 unknown 0-days, 14 patched, 4th place in the final |
| 8 | [SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) Appendix B ROE template | NIST | Public domain | 1.1 Purpose / 1.2 Scope ("actions and expected outcomes") / 1.3 Assumptions & Limitations / 1.4 Risks + mitigations / 2.1 Personnel / 2.2 Schedule (**authorized hours**) / 2.3 Test Site (**authorized source locations** + denied areas) / 2.4 Test Equipment (**a method for distinguishing tester systems from target systems**) | **Authorization should be a data structure.** §2.4 is also the standards basis for "every event names the actor that produced it" |
| 9 | [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) + [KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) (1,713 entries, `catalogVersion 2026.09.16`) + [SSVC](https://github.com/CERTCC/SSVC) | NIST / CISA / CERT-CC | Public domain | One call returns `cvssData{vectorString, baseScore, baseSeverity}` + `cpeMatch[].criteria` (CPE 2.3) + `weaknesses[]{source,type,value}` (multiple attributions preserved — CWE conflicts are normal) + `cisaExploitAdd/cisaActionDue/cisaRequiredAction/knownRansomwareCampaignUse/forensicTriage` + `ssvcV203.options` | No need to join four sources; SSVC's `/data/{csv,json}` is **decision-table-as-data** — severity mapping should be a testable table, not inline `if`s |
| 10 | [Big Bang](https://github.com/DoD-Platform-One/bigbang) | DoD Platform One | GitHub is a **mirror** of `repo1.dso.mil` (anonymous readability **unverified**) | Core in five classes (Service Mesh / Policy Enforcement / Logging / Monitoring / Runtime Security); "at least one of each class or it is not a valid installation"; BBTOC governance | A doctor should be a **validity predicate**, not a WARN list: name a minimal core set; missing any class means unhealthy |
| 11 | [Mitigating-Web-Shells](https://github.com/nsacyber/Mitigating-Web-Shells) and the [nsacyber](https://github.com/nsacyber) org (39 repos) | NSA | `NOASSERTION` | Guidance and runnable detectors in the same repo (that repo's main language is YARA); [HIRS](https://github.com/nsacyber/HIRS)/[paccor](https://github.com/nsacyber/paccor) (Apache-2.0)/[RIM-Tool](https://github.com/nsacyber/RIM-Tool) = a TPM supply-chain attestation trio; [seabee](https://github.com/NationalSecurityAgency/seabee) = policy-based access control hardening eBPF tooling against privileged attackers | **Every prose discipline ships with a machine-checkable detector**; paccor + RIM-Tool + HIRS is the complete "signed reference manifest vs actual state" paradigm; seabee is the model for constraining privileged components |
| 12 | [Caldera](https://github.com/apache/caldera) (now Apache) + [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (MIT, 12,549★) | MITRE→ASF / Red Canary | Apache-2.0 / MIT | Caldera: thin core + ~18 plugins, TTP corpus consumed from external projects, not vendored. ART: `input_arguments{description,type,default}` + `dependencies[{prereq_command,get_prereq_command}]` + `executor{command,cleanup_command,elevation_required}`; index CI-generated and re-checked every PR | The **corpus-discipline trio** — typed inputs with defaults / prerequisite checks / cleanup commands |

Two **negative findings** that are equally military-grade lessons:

- `github.com/fbi` is not the FBI (12 unrelated Chinese web projects,
  2017–2023); `github.com/FBIGov` is an empty shell. The FBI's real public
  surface is [fbi.gov](https://www.fbi.gov/investigate/cyber): IC3
  (Recovery Asset Team, "over a billion dollars frozen"), CyWatch (7×24
  watch floor), NCIJTF (30+ co-located agencies), a deployable Cyber
  Action Team, and flashes carrying IOCs/TTPs. **Lesson: pin tools by hash
  and verify provenance; never trust a plausible-looking namespace.**
- [cisagov/bad-practices](https://github.com/cisagov/bad-practices) (CC0,
  211★) is "a negative catalog of exceptional risk";
  [cisagov/pen-testing-findings](https://github.com/cisagov/pen-testing-findings)
  (archived, 257★) is a finding taxonomy distilled from real assessments.
  Both are CC0 and usable directly as seed content.

#### 2.1.1 Why the ScubaGear verdict record is worth copying near-verbatim

```rego
tests contains {
  "PolicyId":      "MS.TEAMS.1.1v1",
  "Criticality":   "Should",
  "Commandlet":    ["Get-TeamsMeetingPolicyRest"],
  "ActualValue":   MeetingsAllowingExternalControl,
  "ReportDetails": ReportDetailsArray(Status, MeetingsAllowingExternalControl, String),
  "RequirementMet": Status
} if { ... }
```

Five properties, each mapping to a gap:

1. **`Commandlet` is data provenance** — every verdict names the tool call
   that produced its facts. Rule gating here consumes facts but does not
   record which tool produced them.
2. **`Criticality` is normative strength, not severity** — measured values
   `Shall` / `Should`, plus explicitly declared `Shall/Not-Implemented`
   and `Should/Not-Implemented`: **checks a tool cannot evaluate are
   declared, never silently dropped.** That is the fail-closed posture
   expressed *inside the corpus* (load time) rather than in a report
   (report time). Absolute counts drift with upstream main: 85 Shall /
   84 Should with 12 declared Not-Implemented at research time
   (2026-09-17), re-measured 56/69/6 at acceptance time (2026-09-18).
3. **PolicyId carries a version** (`MS.TEAMS.1.1v1` / `1.2v2`) — the
   version is part of the identity, which is what makes a ratchet
   meaningful. An unversioned rule ID cannot say whether a historical
   conclusion is stale (→ M2).
4. **Intermediate sets are named by condition** — facts are inspectable
   and unit-testable independently of verdicts.
5. **Per-control unit tests** (`Testing/Unit/Rego/...` plus a shared
   assertion library).

Additionally, SCuBA controls are already mapped to SP 800-53 rev5
(FedRAMP High baseline), with an integration CSV and inline ATT&CK
mappings in every baseline document. The mapping layer has already been
productized by a federal agency.

#### 2.1.2 OSCAL Assessment Results: field-level mappability

v1.2.3 JSON Schema (draft-07, 86 definitions), structure in brief:

```
assessment-results   REQUIRED: uuid, metadata, import-ap, results[]
├─ metadata          REQUIRED: title, last-modified, version, oscal-version
│                    + props[]{name,ns,value,class,group,remarks} / document-ids[]
├─ import-ap.href    → the Assessment Plan
├─ results[]         REQUIRED: uuid, title, description, start, reviewed-controls
│  ├─ start/end      DateTimeWithTimezone (timezone required)
│  ├─ observations[] REQUIRED: uuid, description, methods[], collected
│  │  ├─ methods[]   ENUM: EXAMINE | INTERVIEW | TEST | UNKNOWN
│  │  ├─ subjects[]  subject-uuid + type ENUM component|inventory-item|location|party|user|resource
│  │  ├─ relevant-evidence[]  REQUIRED description
│  │  └─ origins[]   → actors[]{type: tool|assessment-platform|party, ...} + related-tasks[]
│  ├─ risks[]        status ENUM open|investigating|remediating|deviation-requested|deviation-approved|closed
│  │  └─ characterizations[].facets[]{name,system,value} — system ∈ {cve.mitre.org, first.org/cvss v3.0|v3.1|v4-0, ...}
│  ├─ findings[]     REQUIRED uuid,title,description,target
│  │  └─ target      type ENUM statement-id|objective-id; status ENUM satisfied|not-satisfied|pass|fail|other
└─ back-matter.resources[]  rlinks[]{href, media-type, hashes[]} — "a URL-based pointer to an
   external resource with an optional hash for verification and change detection";
   hash = value + algorithm ∈ SHA-224/256/384/512, SHA3 family
```

Mapping verdicts (the details below are where naive mappings fail):

- **`finding.target.type` in base OSCAL is only `statement-id |
  objective-id`** — a finding points at a control statement or assessment
  objective, not at a host. Host/service attribution goes through
  `observation.subjects[]` and `finding.origins`. A naive direct mapping
  hits that wall; the correct mapping is: engine finding → OSCAL
  observation (subjects → assets) + OSCAL finding (target → the control
  objective this assessment exercised).
- **The verification families align with `observation.methods[] =
  EXAMINE|INTERVIEW|TEST|UNKNOWN`** — the same three verbs as SP 800-53A
  and SP 800-115 ("testing, examination, interviewing"). Adopting this
  vocabulary aligns with three standards at once.
- **The seal manifest aligns with
  `back-matter.resources[].rlinks[].hashes[]` + `hash.algorithm`**
  (SHA-256 is in the allowed set); `engine_commit` goes to
  `metadata.props[]` under a private `ns`, or to `document-ids[]`.
- **Tool provenance aligns with `origins.actors[]{type:"tool"}` +
  `related-tasks[]`** — the standard's native answer to "which parser
  produced this".
- **CVSS/CVE are first-class** (`characterizations.facets[].system`) — no
  custom props needed.
- **OSCAL 1.2.3 ships a Mapping model** (`mapping → map{relationship,
  sources[], targets[], confidence-score, coverage{...}} →
  mapping-item{type,id-ref}`, plus `gap-summary{unmapped_controls[]}`) — a
  mapping standard with built-in confidence and self-declared gaps. A
  "finding → CCI → 800-53 → ATT&CK" cross-table should be emitted in
  this form, not as a hand-rolled table.
- Offline control text: `usnistgov/oscal-content` publishes SP 800-53 rev5
  JSON **with both profiles and pre-resolved profile catalogs** —
  consumers need no resolver. That courtesy is worth copying.
- Single signed result container: SCAP **ARF** (Asset Reporting Format)
  packages report + inputs + provenance — the standards-body equivalent
  of a seal manifest. On the SBOM side, SCAP **SWID** or SPDX/CycloneDX
  can describe the pinned tool inventory.

### 2.2 Allied and other nations: 8 absorbable patterns

| # | Project | Country / org | License | Pattern | One transferable idea |
|---|---|---|---|---|---|
| 1 | [AssemblyLine](https://github.com/CybercentreCanada/assemblyline) (+ base / core / v4-service) | Canada CSE | **MIT** (Crown copyright), 537★ | Service = container + **declarative manifest** (`accepts`/`rejects` regexes, `stage` FILTER/EXTRACT/CORE/SECONDARY/POST/REVIEW, `timeout`, `docker_config{cpu,ram,allow_internet_access}`, typed `submission_params`, signed `update_config`, `uses_tags` capability flags); one runtime method `ServiceBase.execute(request)`; API → Filestore+Redis → Dispatcher (schedule built by stage) → services **long-poll the Service Server API** (deliberate isolation: untrusted services never touch core infrastructure); Dispatcher state is non-persistent, restart = full rerun | **A heuristic must be declared in the manifest** (`heur_id`/`score`/`max_score`/`signature_score_map`) before it can fire; the server-side `HeuristicHandler` **recomputes** scores, **rejects unknown `heur_id`s**, and **zeroes the score when every fired signature is safelisted**. Thresholds are configuration data (info 0 / suspicious 300 / highly 700 / malicious 1000 / safe −1000) → M12 |
| 2 | AssemblyLine **cache keys** | Canada CSE | MIT | `sha256 . service_name . vVersion . cCONF[. e]`, `CONF = base62(md5(tool_version + service_config + submission_params + ignore_salt)[:16])`; a random salt is injected on `ignore_cache` or `partial` → partial/untrusted results never poison the cache | Finding cache keys should be (target, tool, tool version, parser version, **corpus hash**, scan parameters); partially verified findings are never cacheable; digests become reproducible |
| 3 | [DFIR ORC](https://github.com/DFIR-ORC/dfir-orc) (448★) + [config](https://github.com/DFIR-ORC/dfir-orc-config) | France ANSSI | LGPL-2.1 / Licence Ouverte 2.0 | Mothership + WolfLauncher scheduler; external and embedded tools packed into one configured binary (`ToolEmbed`); everything runs inside a Windows **Job Object**; artifacts compressed into the archive as they are produced, temp files deleted immediately; design motto "whatever it takes, whatever happens, DFIR ORC will strive to provide valid output files in a predetermined amount of time"; declarative XML with per-tool budgets (`MaxSampleCount`/`MaxTotalBytes`/`MaxPerSampleBytes`, magic-number predicates, `optional` commands so one tool's failure does not void the run) | **Two machine-readable run records**: the **Outline** (execution context: versions, `dfir_orc_id`, timestamps, command line, output/temp dirs, process/env/user context) and the **Outcome** (per-command start/end, IO counts, process/memory peaks, archive name+size+per-file listing). The strongest evidence-integrity design in public material — the generalized form of a seal manifest: separate identity/context from per-action results, and hash both the engine and every tool binary |
| 4 | [MISP](https://github.com/MISP/MISP) + [misp-objects](https://github.com/MISP/misp-objects) + [MISP-rfc](https://github.com/MISP/MISP-rfc) | Belgium (Belgian Defence / NATO context) | Core **AGPL-3.0**; database **CC0-1.0 OR AGPL-3.0** dual | Event → templated Object → typed Attribute → Relationship/Galaxy + Tag (taxonomy) + Warninglist/Noticelist; each layer has an IETF-style RFC (RFC-2119 MUST/SHOULD); **186 taxonomies / 225 warninglists / 432 object templates**; correlation is first-class (per-attribute `disable_correlation`); `misp-stix` bidirectional MISP↔STIX with ACS Marking round-trip | **Object template = the standard answer for a closed vocabulary**: one JSON file per term, validated against a schema (`additionalProperties: false`, `required` **and** `requiredOneOf`, closed enums for meta-category / ~180 core types / 16 categories, integer `version` + stable `uuid` per item); **adding a vocabulary term = a JSON-only PR, no code change**; documentation generated from the JSON. Take the CC0 leg; never vendor the AGPL core |
| 5 | [OpenCTI](https://github.com/OpenCTI-Platform/opencti) (10,011★) | Filigran (FR) | **CE Apache-2.0 / EE proprietary**, decided per file header ("If no such header is provided, the file belongs to the Community Edition under Apache 2.0") | STIX 2.1-based ontology with extensions; GraphQL API; every knowledge item links to a primary source with confidence and first/last-seen; connectors (Apache-2.0) are a **closed type enum** (`EXTERNAL_IMPORT / INTERNAL_IMPORT_FILE / INTERNAL_ENRICHMENT / INTERNAL_ANALYSIS / INTERNAL_EXPORT_FILE / STREAM`) with **scope registration**, liveness ping, and a queue consumed by `opencti-worker`; markings/TLP are data used as row-level access control | Connector closed-enum + scope registration + liveness ping + queue = the ready-made contract template for attaching external legs |
| 6 | [Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers) | TheHive Project | **AGPL-3.0** (TheHive 5 has gone commercial/source-available) | A **flavor JSON manifest** beside every analyzer: `name/author/`**`license` (per-analyzer!)**`/version/description`, **`dataTypeList` (the routing gate)** , `command`, `baseConfig`, flavor selector, **typed `configurationItems[]{name,description,type,multi,required}`**, `registration_required`/`subscription_required` | The ready-made shape of a **parser manifest**: self-describing, routable, license-auditable (a per-parser `license` field is free license hygiene). Copy the schema shape only; vendor no AGPL analyzer code |
| 7 | [ACSC ISM as OSCAL](https://github.com/AustralianCyberSecurityCentre/ism-oscal) | Australia ASD/ACSC | **CC-BY-4.0** | The entire Information Security Manual published as OSCAL: `ISM_catalog.{json,xml,yaml}`, `version: 2026.09.4`, **26 groups / 1,192 controls**, ISM-specific properties via OSCAL `props`; profiles per classification (NON_CLASSIFIED … TOP_SECRET) **and** per Essential Eight maturity (`ISM_E8_ML1/ML2/ML3`), each with a resolved-profile-catalog | **Best find of the survey**: (a) the E8 maturity model really is published as data (ML1 profile ≈6 KB, resolved ≈150 KB, ML3 ≈329 KB); (b) it demonstrates "which subset of the catalog applies at this assurance level" — the OSCAL **profile-over-catalog** two-layer structure → gate selection should be a profile-style data file resolving against a gate catalog, not hardcoded checks. CC-BY-4.0, artifacts reusable |
| 8 | [NCSC Device Security Guidance Configuration Packs](https://github.com/ukncsc/Device-Security-Guidance-Configuration-PackS) (468★, © Crown 2025) + [schema-genie](https://github.com/ukncsc/schema-genie) + [lme](https://github.com/ukncsc/lme) (703★, retired, handed to [cisagov/lme](https://github.com/cisagov/lme)) | UK NCSC | Apache-2.0 | Platform guidance published as machine-readable Intune / Jamf / Google Workspace policy packs, **sharded by threat model** ("counter commodity threats at OFFICIAL"); `schema-genie` induces XSD from an XML corpus and statically lints OpenAPI docs; the logging guidance is question-driven ("which questions must logs answer when an incident happens?") → retention → field-existence validation → time-source sync → centralized collection (encrypted, one-way flow) → **liveness detection (alert when a periodic test event is NOT ingested)** → 6–12 month review | (a) Guidance as machine-readable policy packs sharded by threat model — gate profiles should shard by engagement type the same way; (b) `schema-genie` = the induce-schema-from-corpus paradigm, a ready-made idea for parser contracts; (c) the logging guidance is itself a prose-form validator + digest specification — "liveness detection" and the onboardapi Watchdog are two independent inventions of the same concept |

**Others (short):**

- **Germany BSI**: the IT-Grundschutz-Kompendium is published as XML
  (annual editions + change documents + an ISO 27001 cross-reference
  table; requirement IDs are stable addresses like `SYS.3.2.2.A1`). A
  community conversion (`Vorgebirge/IT-Grundschutz`) splits requirements
  into single-modal-verb sub-requirements and computes cosine-similarity
  deltas against the previous edition — a neat "requirement identity
  across versions" trick. Official GitHub is `BSI-Bund` (20 repos:
  `Stand-der-Technik-Bibliothek` CC-BY-SA, `secvisogram` MIT CSAF editor,
  `ConformXpert` EUPL-1.2 CRA assessment). GSTOOL is closed-source
  commercial; there is no open version.
- **NATO CCDCOE**: the Tallinn Manual (3.0 in preparation) self-declares
  as "a non-binding academic work … not the legal position of any state or
  international organization"; Locked Shields publishes after-action
  reports (e.g. `LockedShields12_AAR.pdf`) — the closest public thing to
  "range scenarios as data", but prose PDFs. **No machine-readable CCDCOE
  ROE artifact was found.**
- **ENISA**: candidate certification schemes are drafted by Ad-Hoc WGs and
  become EU law via Implementing Acts (EUCC done; EUMSS / EU Digital
  Wallet in consultation). ETL 2025 analyzes 4,875 incidents but publishes
  as PDF — the taxonomy lives in prose, not a registry.
- **NIS2**: Directive (EU) 2022/2555 Art 23(4) mandates tiered deadlines
  (early warning ≤24h stating whether malicious/cross-border; incident
  notification ≤72h with severity/impact/IoCs; final report ≤1 month;
  progress reports for ongoing incidents), but Art 23(11) only says the
  Commission *may* specify formats via implementing acts — **NIS2 does not
  mandate a structured report format**. Adopted Reg (EU) 2024/2690 covers
  Art 21(2) risk management measures and Art 23(3) significance criteria
  (financial loss > EUR 500,000 or 5% of turnover, whichever is lower;
  trade-secret exfiltration; death or health damage) — genuinely
  machine-checkable predicates, but about reporting, not authorization.
- **Estonia**: `ria-ee` = X-Road (MIT; marked unmaintained, upstream has
  taken over) + X-Road-opmonitor (operational monitoring of the national
  data-exchange layer — a production telemetry/audit data model).
  Contract-first per-service WSDL/Swagger + a mandatory per-message audit
  log is the shape a seal manifest wants.
- **European defence primes' public repos reveal a pattern**: Rheinmetall
  has 4 public repos (§1.3). [Helsing](https://github.com/Helsing-ai) has
  13, almost all Apache-2.0 Rust and unusually "meta" — `sguaba` (513★,
  hard-to-misuse rigid-body transform types = correctness by construction
  at the type layer), `buffrs` (protobuf package management), `dson`
  (δ-based CRDT), `yadr` (lint and extract architecture decision records
  from code), `jtd-derive` (derive JSON Typedef schemas from Rust types),
  `pyaddlicense` (license-header enforcement). Saab has 8 small repos,
  mostly MIT test-time tools. **Common pattern: open interface / closed
  runtime / contract-first / digital-twin testability / SPDX per-file
  headers / correctness built into types and lints rather than review
  comments.** `yadr` (Apache-2.0) is free value: architecture decisions
  as data.

### 2.3 Autonomous frameworks and LLM pentest agents: measured capability bounds

**Caldera (Apache-2.0) is the closest public analogue**, and the honest
comparison is:

- Where Caldera is stronger: ability YAML with ATT&CK technique
  annotations and `#{trait}` **fact interpolation**; payloads/uploads/
  cleanup; parsers with **`source/edge/target` relation mapping** (e.g.
  katz: `domain.user.name -has_password-> domain.user.password`); one link
  generated per fact-combination variant, scored by fact share (facts
  start at 1 point; **0 = blacklist**); planners as bucket state machines
  with custom `LogicalPlanner` support; **`rules` = firewall-like
  ALLOW/DENY regexes over fact values, with subnet matching** —
  planning-time egress control.
- Where this engine is stronger: a **static corpus checker with an
  AST-derived producer/consumer model and a ratchet**; a scope guard with
  fail-closed gates; category-reserved prioritization, per-rule backlog
  caps, and three-strike retirement; **event-sourced SQLite** (event and
  row in one transaction, full snapshots, replayable) versus shutdown-time
  file dumps; **seal / `--verify` / SHA256 / `engine_commit` manifests**.
- Security note: Caldera has CVE-2025-27364 (RCE) — upgrade to v5.1.0+.

**Worth stealing from Caldera**: fact interpolation; the parser
`source/edge/target` relation edges; the `dependencies` + `cleanup`
corpus discipline; ALLOW/DENY fact rules as planning-time scope control
(complementary to the egress policy layer). **Not worth stealing**: the
variant explosion (one link per fact combination — needs a score ceiling
first) and the persistence model.

**Other frameworks:**

- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (MIT,
  12,549★, 1,878 atomics): the **defaults + prereq + cleanup trio** plus
  CI (`validate-atomics`, GUID/doc generators, **generated docs and badges
  re-checked and committed every PR**) — corpus-as-code in full.
- [Infection Monkey](https://github.com/guardicore/monkey) (**GPL-3.0**):
  Agent + Island C&C, all telemetry converging on the Island; exploiters
  covering Log4Shell/RDP/SSH/SMB/WMI; propagation map + security report +
  ATT&CK mapping. **Mostly dormant since v2.3.0 (2023-09)**, last push
  2025-05, no official successor seen. GPL — ideas only.
- OpenBAS → [OpenAEV](https://github.com/OpenAEV-Platform/openaev)
  (renamed at v2.0.0): **Apache-2.0 CE + proprietary EE, not AGPL**.
  Scenario/simulation scheduling of **injects** (timed or conditional),
  each with **expectations** (prevention/detection/vulnerability/
  human-response) for posture scoring; **"expectations drift"** — existing
  injects are flagged stale when injector contracts evolve (a good
  corpus-checker idea). Exercise management, not autonomous pentest.
- [Buttercup](https://github.com/trailofbits/afc-buttercup) (Trail of
  Bits, **AGPL-3.0**, archived): K8s/helm microservices; an orchestrator
  state machine; **`mock_competition_api` replays unscored rounds =
  deterministic reruns from recorded tasks**; Langfuse/OTEL for LLM
  observability.
- [RoboDuck](https://github.com/theori-io/aixcc-afc-archive) (Theori):
  agent-tree architecture; an honest cost warning ("can easily spend
  $1,000 or more in under an hour") controlled by a per-role model-map
  TOML; an Agent Log Viewer rendering the agent tree, full conversations,
  tool calls, and **per-message time and dollar cost**; `SERIALIZE_AGENTS`
  snapshots for offline replay; nightly eval → S3 → InfluxDB;
  `round_sim.py` variable-speed round replay.
- [PentAGI](https://github.com/vxcontrol/pentagi) (MIT, ~24.7k★): Go +
  GraphQL microservices; **PostgreSQL + pgvector** stores every command
  and output; optional Graphiti/Neo4j knowledge graph; Flow→Task model.
  Cross-run memory is genuinely valuable for regression-scan dedup.
- [hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT):
  **unified run limits (rounds/tokens/$/wall-clock)** + **ground-truth
  checked success detection** (a hallucinated "got root" scores nothing) +
  a planner/executor use case (persistent strategic planner, memoryless
  tactical executor) + a reusable privesc benchmark. It already ships the
  run-limit mechanism M9 wants — evaluate reuse before building.
- [Strix](https://github.com/usestrix/strix) (PyPI `strix-agent` 1.6.2,
  Apache-2.0): multi-agent "Graph of Agents" (recon/exploit/post-exploit),
  **verifies findings by executing PoCs**, browser agent + MCP tooling,
  local dashboard, a separate benchmarks repo. Its execute-PoC
  verification and M12's server-side recompute are the same principle.

**Benchmarks and measured success rates** (this decides what to expect
from LLM legs):

| Benchmark | Scale | Best result | Exposed limit |
|---|---|---|---|
| [Cybench](https://cybench.github.io/) (Stanford, [arXiv:2408.08926](https://arxiv.org/abs/2408.08926), ICLR'25) | 40 professional CTFs (HTB 17 / Sekai 12 / Glacier 9 / HKCert 2) + subtasks | Unguided Claude 3.5 Sonnet **17.5%**, GPT-4o **12.5%** (guided 17.5%); o1-preview subtask best 46.8% | **Tasks whose human first-solve time exceeds 11 minutes are never solved unguided** — the bottleneck is long-horizon planning, not tool calling. (The often-cited "14%→24%" is from the superseded v1 abstract; cite with care.) Used by US/UK AISI for pre-deployment testing |
| [NYU CTF Bench](https://nyu-llm-ctf.github.io/) ([arXiv:2406.05590](https://arxiv.org/abs/2406.05590), NeurIPS'24 D&B) | 200 tasks | Best combo (SWE-agent + GPT-4o) ≈**16%** (paper figure; today's leaderboard is empty — **not re-verified**) | Multi-step exploit chains fail; automatic planning is the bottleneck |
| [InterCode-CTF](https://intercode-benchmark.github.io/) (Princeton, [arXiv:2306.14898](https://arxiv.org/abs/2306.14898)) | 100 simplified picoCTF, sandboxed bash | GPT-4 **37%** | No real network targets = pure sandbox-to-reality gap |
| [PentestGPT](https://arxiv.org/abs/2308.06782) (**correct id 2308.06782** — frequently miscited as 2308.06690, an unrelated combinatorics paper) | HackTheBox-derived | **+228.6%** task completion over the GPT-3.5 baseline | The Reasoning/Generation/Parsing three-module split exists to fight context loss; the exposed limit is "LLMs can do subtasks but lose the integrated scenario state" — exactly what an event-sourced graph repairs |
| CybORG ([arXiv:2108.09118](https://arxiv.org/abs/2108.09118)) / CybORG++ ([2410.16324](https://arxiv.org/abs/2410.16324)) / CyGIL ([2109.03331](https://arxiv.org/abs/2109.03331)) | RL environments | — | "Cybersecurity Gym" as a named artifact is unverifiable; these three RL environments are the nearest verifiable kin |
| "PentestBench" | — | — | **No such benchmark found** (two ≤1★ GitHub repos) — treat as nonexistent |
| Surveys | — | — | "A Survey of LLM-Driven Penetration Testing: Taxonomy, Co-Evolution, and Open Challenges", [arXiv:2607.02605](https://arxiv.org/abs/2607.02605) (2026-07, 81 papers 2023–26, four-stage architecture evolution toward RLVR agents); companion SoK "Agentic Security", [arXiv:2608.21423](https://arxiv.org/abs/2608.21423) |

**Engineering conclusion from the benchmarks:** frontier models unguided
on real CTFs sit at 12–18%, and the bottleneck is long-horizon planning
and state integration, not tool calling. That is empirical backing for
this engine's architecture: state lives in an event-sourced graph (not in
the agent's context window), planning lives in a deterministic
orchestrator (not in an LLM), and LLM legs are restricted to proposing
structured artifacts — the correct engineering response to a 17.5%
ceiling.

### 2.4 High-assurance engineering: the part a Python orchestrator can afford

| Pattern | Measured cost | Fit |
|---|---|---|
| **seL4** | Functional correctness ≈ **20 person-years** ([SOSP'09, doi 10.1145/1629575.1629619](https://dl.acm.org/doi/10.1145/1629575.1629619)); verified kernel ~10–16k SLOC; AArch64 confidentiality completed 2026-08 | **Not adopted** (person-decade scale). **Adopt the process**: executable specification, refinement, **tests traceable to spec items** |
| **AWS S3 ShardStore** ([SOSP'21, Bornholt et al.](https://www.amazon.science/publications/using-lightweight-formal-methods-to-validate-a-key-value-storage-node-in-amazon-s3)) | **Prevented 16 production issues**; maintainable by non-FM experts | **The realistic template**: split correctness into independent properties and pick the cheapest tool per property — TLA+/TLC bounded model checking for crash consistency, P-style reference models, **property-based differential testing against an executable reference model**, Jepsen-style crash testing |
| TLA+/TLC | Days | A bounded model of the launch-gate ordering + planner FSM — catches gate-order races |
| Hypothesis `RuleBasedStateMachine` | **Hours** | Rule-sequence-driven operations asserting invariants on the SQLite graph. Best cost/benefit alongside the existing unit suite |
| FSM exhaustive transition enumeration | Tiny (itertools over states × events) | The finding state machine's states + transition table can be covered **completely** |
| Differential testing (ShardStore / AIxCC pattern) | Medium | An independent reimplementation scoring the same event log = M4 |
| Symbolic execution of the rule evaluator (angr) | Medium, poor ROI | **Not adopted** — property-based testing wins outright at this corpus scale |

**The three cheapest high-value additions**: (a) stateful Hypothesis
testing against graph invariants (hours); (b) exhaustive transition-table
coverage of the finding state machine (tiny); (c) a TLA+ bounded model of
the gate ordering (1–2 weeks — a model checker covers *ordering* races
that a scenario self-test matrix cannot).

## 3. Adoption roadmap: M1–M15

Ordering principle: seams and corpus first, then the military-grade layer.
About half of these items are acceptance criteria added to work already in
flight, not new fronts. ★ marks the top six by cost/benefit
(M12, M4, M2, M1, M9, M8).

| # | Adoption | Source | Engine subsystem | Cost / benefit |
|---|---|---|---|---|
| **M1** ★ | **Unified verdict record**: every rule action and parser output normalized to `{rule_id, normative_strength: Shall\|Should\|May, provenance_tool, actual_value, verdict, not_implemented}`; checks that cannot be evaluated are declared `Not-Implemented`, never silently dropped | ScubaGear Rego (CC0) | Rule corpus + parser layer | Medium / **very high** — moves the fail-closed posture from report time into the corpus |
| **M2** ★ | **Content hash as rule identity + conclusion inheritance**: hash each rule's gate/action text; on corpus change, only findings produced by rules whose content hash changed are invalidated; the rest auto-inherit | STIG Manager (MIT, US Navy) | Corpus + CI ratchet | Small / **high** — the ratchet becomes a staleness check |
| **M3** | **Closed class vocabulary as JSON Schema**: `additionalProperties: false` + closed enums per classification field + `required` **and** `requiredOneOf` + integer `version` + stable `uuid` per item + CI validator + **docs generated from data**; a new term is a JSON-only PR | MISP object templates (**take the CC0 leg**) | Vocabulary work | 1–2 days / **high** |
| **M4** ★ | **Re-adjudication from sealed evidence**: a replay command recomputes every finding from the same event stream with an independent consumer, **rerunning no tools**; scores never trust agent self-reports | AIxCC scoring-pipeline (MIT) + CGC replay + Buttercup `mock_competition_api` | Validator + seal/manifest | Days / **very high** — an event-sourced engine is naturally adapted; doubles as the §1.3 digital-twin equivalent |
| **M5** | **OSCAL Assessment Results 1.2.3 as the digest format**, CI-validated against the published JSON Schema. Mapping per §2.1.2 (findings → observations with subjects; methods → EXAMINE\|INTERVIEW\|TEST\|UNKNOWN; seal → back-matter hashes; `engine_commit` → metadata props; tool provenance → origins.actors) | NIST OSCAL | Digest/report + seal | Medium / **high** — the most externally presentable flag of "military-grade" |
| **M6** | **NVD enrichment as typed fields**: one call for `cvssData{vectorString,baseScore,baseSeverity}` + `cpeMatch[].criteria` + `weaknesses[]{source,type,value}` (multiple attributions kept) + KEV fields + `ssvcV203.options`; severity via an **explicit decision table (CSV/JSON)**, not inline `if`s | NVD API 2.0 / KEV / SSVC | Parser + validator + digest | Small / high |
| **M7** | **ATT&CK technique ID per finding** (pinned to a STIX 2.1 release, with MITRE's required attribution line) + D3FEND countermeasure references; the cross-table is emitted as an **OSCAL Mapping** (with `confidence-score` and `gap-summary.unmapped_controls[]`) | MITRE ATT&CK / D3FEND / OSCAL Mapping | Digest/report | Medium / high — a mapping with built-in confidence and self-declared gaps is more honest than a hand-rolled table |
| **M8** ★ | **Authorization as data (ROE object)**: fields from SP 800-115 Appendix B (purpose / scope{actions, expected_outcomes} / assumptions / limitations / risks[]+mitigations / personnel[] / schedule{authorized_hours} / **authorized_source_locations[]** / denied_areas[] / test_equipment[] + the tester-vs-target distinction method); structure from ACSC ISM-OSCAL's catalog/profile two layers (a gate catalog + profiles selecting which gates apply at which assurance level and engagement type); produced case-init style; consumed by the launch gates and the seal manifest | SP 800-115 App.B + ACSC (CC-BY-4.0) + reverse-skill (MIT) + DFIR-ORC Outline | Launch gates + doctor + seal | Medium / **highest** — the step from "authorized-only by prose" to "authorized-only by predicate". **The only truly original component of this plan**: no national program has published a penetration-authorization object (MISP sharing groups / STIX TLP / OpenCTI markings are *dissemination control*, not attack authorization; the Tallinn Manual self-declares non-binding; NIS2 mandates deadlines, not formats; CAF is PDF-only; IT-Grundschutz is a control catalog, not a scope grant) — and it is assembled entirely from permissively licensed precedents |
| **M9** ★ | **Budget gate**: wall-clock + token + **USD** caps per launch; the cap is configuration, the actual value is an event; over-cap fails closed | Fuzzing Brain ("$2.14 actual / $20 cap / 14.6 min") + hackingBuddyGPT unified run limits | Launch gates | Small / **high** |
| **M10** | **Doctor as a validity predicate** (a named minimal core set; missing any class = unhealthy, not a WARN list) + **AssemblyLine-style cache keys** `(target, tool, tool version, parser version, corpus hash, params)`, with a random salt on `partial` so partial results never poison the cache | Big Bang + AssemblyLine (MIT) | Doctor + digest | Small / high |
| **M11** | **Parser manifests**: one JSON per parser carrying `dataTypeList` (**routing gate**: which asset/finding classes the parser may produce), typed `configurationItems[]{name,type,required}`, and a **per-parser `license` field** | Cortex-Analyzers (**schema shape only — no AGPL code vendored**) | Parser layer | Small / high — structurally kills the "tool without parser" class: a tool whose manifest declares no outputs cannot be registered into a rule |
| **M12** ★ | **Declare-then-recompute heuristics**: a parser may not emit a class/severity its rule did not declare; the engine **recomputes** severity; when every fired signature is safelisted/ruled_out the score **zeroes**; unknown `heur_id`s are rejected | AssemblyLine `HeuristicHandler` (MIT) + Fuzzing Brain "nothing that hasn't crashed a real build is reported" + Strix execute-PoC verification | Validator | Medium / **very high** — the anti-hallucination gate for LLM legs; MIT-licensed, so the reference code can be studied directly |
| **M13** | **The assurance trio**: (a) Hypothesis `RuleBasedStateMachine` against graph invariants (hours); (b) exhaustive coverage of the finding state machine's transition table (tiny); (c) a TLA+/TLC bounded model of the gate ordering + planner FSM (1–2 weeks). **Explicitly not**: seL4-grade proofs, angr symbolic execution | ShardStore / seL4 process / TLA+ | Tests + state machine + launch gates | Small–medium / high — the non-adoptions are recorded so they are not re-proposed |
| **M14** | **Corpus-discipline trio + planning-time scope rules**: per rule, typed `input_arguments{description,type,default}`, `dependencies[{prereq_command,get_prereq_command}]`, `cleanup_command`, with a CI validator (`validate-atomics` style); plus **ALLOW/DENY fact rules (regex + subnet match, last-match-wins) as planning-time egress control** | Atomic Red Team (MIT) + Caldera (Apache-2.0) | Rule corpus + the egress policy layer | 1–2 days + ~1 day / high |
| **M15** | **Negative catalog**: make "never allowed" patterns data (`0.0.0.0/0`, `-p1-65535`, `hydra -L`, `rockyou`, `curl \| bash`, over-threshold concurrency) — **every prose discipline paired with a detector**; seed content from [cisagov/bad-practices](https://github.com/cisagov/bad-practices) (CC0) and [cisagov/pen-testing-findings](https://github.com/cisagov/pen-testing-findings) (archived, CC0) | NSA "guidance and detectors in one repo" + CISA | Corpus checker + skill-tree lint | Small / high |

**Phase 3 (external legs — only after M1/M8/M9/M12):** the attach
contract for PentAGI / hackingBuddyGPT upgrades to: any external leg posts
structured artifacts through **one narrow-waist API** (the CGC `ti-api`
pattern), carrying the ROE object (M8) + budget caps (M9) + unified
verdict records (M1), and is **scored independently from the event log**
(M4/M12). Shannon stays unintegrated (AGPL-3.0 contamination; a white-box
workflow that needs a source repo, mismatched with the engine's black-box
engagement model; no egress hook).

## 4. Explicitly not adopted (recorded to prevent re-proposal)

| Item | Reason |
|---|---|
| Rust rewrite | The corpus check runs in 0.22 s; the orchestrator is IO-bound; SQLite is C; the tools are already Go/Rust native. The trigger conditions (corpus check >5 s) are two orders of magnitude away. Note: CSE is rewriting AssemblyLine's Dispatcher/Ingester/Service Server in Rust ([assemblyline-rust](https://github.com/CybercentreCanada/assemblyline-rust)) — that is a thousands-of-files-per-second malware-analysis pipeline, not the same problem as a small rule-corpus orchestrator |
| gRPC/C++ transport stack, `.rmodel` DSL | Irrelevant to a Python orchestrator; JSON suffices at this corpus scale |
| seL4-grade interactive proofs, angr symbolic execution of the rule evaluator | Person-decade scale / poor ROI (property-based testing wins at this corpus size) |
| Vendoring any AGPL/GPL code | MISP core, AIL-framework, cve-search, TheHive, Cortex(-Analyzers), DFIR-ORC, Infection Monkey, Buttercup, `stix-ncsccommon`, BSI `Stand-der-Technik-Bibliothek` (CC-BY-SA), `CTF-Sandbox-Orchestrator` (GPLv3): **schema shapes and ideas only** |
| Rheinmetall runtime library / inspector | Proprietary EULA-RME-SDK-1.0 + export-control clauses |
| EPL-2.0 as the public export's license | EPL is weak-reciprocal; the export keeps its current license (AGPL-3.0-or-later) rather than switching "to align with military-grade" |
| Leaked tooling (Vault 7 / Shadow Brokers class) | Not fetched, not read, not adopted. Technique that cannot prove its provenance is a liability in an authorized-only, evidence-hygiene engine |
| reverse-skill's `routing.json` as a router | Imperative contract vs scan-inject host — a gate no model can invoke (§1.1) |
| `README_AI`'s "execute section 0 immediately" auto-bootstrap | Upstream issue #134 identifies it as an abuse vector in itself |

## 5. Credibility statement

**Consulted directly, with URLs:** the three upstream repositories of §1
(GitHub API + raw + codeload tarballs, including both Rheinmetall LICENSE
texts in full and reverse-skill's `case-init` / `scope-contract.md` /
`routing.json` / `master-route`); ScubaGear's Rego and `.regal` config;
OSCAL v1.2.3 assessment-results and mapping JSON Schemas; STIG Manager /
Vulcan READMEs; CGC `ti-api-spec.txt`; the AIxCC archive site and
scoring-pipeline / competition-api / Fuzzing Brain (incl.
arXiv:2509.07225); the NIST pages for SP 800-115 / 800-53 / 800-53A /
800-160v2r1; NVD API 2.0 and the KEV JSON as fetched; SSVC; ATT&CK
terminology and D3FEND 1.6.0; AssemblyLine's four repos at source level
(`odm/models/service.py`, `common/result.py`, `common/heuristics.py`,
`common/caching.py`, `dispatching/schedules.py`); DFIR-ORC docs and config
XML; the MISP RFCs and misp-objects schema; OpenCTI licensing and
connector enums; a Cortex-Analyzers flavor manifest instance; the ACSC
ism-oscal tarball; the BSI Grundschutz publication page and the BSI-Bund
org; an actual enumeration of the ukncsc org; CCDCOE/ENISA/NIS2 primary
texts (EUR-Lex).

**Not verified (must not be cited as sources):** the body text of any DISA
STIG/CCI/CKM/Gold Disk/ACAS document (`public.cyber.mil` DNS unreachable
from the research environment — corroborated only indirectly via Vulcan
and STIG Manager READMEs); whether DoD Iron Bank / Repo1 is anonymously
readable; DoD Zero Trust RA / DevSecOps RA / CRWS BoK / CDAO; NSA ESF, the
K8s hardening guide, and the software-memory-safety CSI
(`media.defense.gov` 403); Cybercom doctrine (DNS unreachable — usable as
a conceptual frame only, **not as an engineering source**); CMU SEI OCTAVE
(site revamp 404); Sandia/LLNL/ORNL ranges; CAPEC/CWE body text and
license terms; WALKOFF's LICENSE text; ComplianceAsCode's
`disa`/`stigid`/CCI field naming; AIxCC final rankings beyond "7
finalists" and Fuzzing Brain's self-reported fourth; CRUMBS (GitLab
requires login); `github.com/microsoft/Cybersecurity-LLM-Agents` (API
404/rate-limited); most Singapore/Japan/Korea/India/Israel/Estonia-CR14
items. **"Facebook+GCHQ, PLDI 2019, network-protocol formal verification"
is refuted and must not be cited**: all 76 PLDI'19 papers were enumerated
(DOI prefix `10.1145/3314221`); no such paper exists.

## 6. Acceptance stamp

- **Two independent read-only swarm acceptance rounds passed**
  (2026-09-18). The review's claims were re-derived by parallel
  independent verifiers whose evidence standard was local re-runs, source
  file:line reads, and upstream primary sources (GitHub API+raw,
  standards-body originals). Verdict: the verifiable claims reproduce
  (including the hard numbers and line-level citations), no fabrication
  was found, and the recorded flaws are count/attribution/caliber-level
  and move no conclusion. A second, separate acceptance round covered the
  companion engineering work driven by this research.
- **Nine errata** were recorded against the source review and are applied
  in this document:
  1. One "19 vs 14 commits" divergence argument was invalid — a shallow
     clone made 14 a truncation artifact; the stronger evidence is 19
     same-content/different-hash commit pairs with an empty merge-base.
  2. A section reference in the companion review's header line pointed at
     the wrong document section.
  3. One internal corpus-health metric had been quoted without its
     measurement caliber (ratchet scope vs full report scope); calibers
     are now stated wherever such numbers are used.
  4. Four count corrections in the companion review (a skill-count
     breakdown, a never-imported component count, a pattern
     line/directory count, a tracked-file count); every total was
     unaffected.
  5. Two internal path references corrected (a launch script's location;
     the engine package's in-tree entry point, `python3 -m core`).
  6. Version drift on three external data points, applied here:
     reverse-skill's last push is 2026-09-03 (not 2026-09-17); the Fuzzing
     Brain repository moved organizations (o2lab → fuzzingbrain, redirect
     live); ScubaGear's `Criticality` counts drift with main (research
     time 85/84 with 12 declared Not-Implemented; acceptance time
     56/69/6).
  7. Two latent/premise annotations: one described parser-coverage gap is
     currently latent (no consuming rule); one token-burn pattern
     presupposes an optional reflector flag; one self-blocking risk is
     hypothetical on the current corpus.
  8. One incidental claim in the companion review does not hold (a cause
     was claimed to be recorded where it was not).
  9. Two claims are not statically verifiable and are treated as
     unverifiable rather than cited as fact (an operational burn-rate
     figure; a never-executed negative assertion).
- **Data timestamps:** upstream snapshots 2026-09-17 (repository metrics;
  KEV `catalogVersion 2026.09.16`) and acceptance re-measurements
  2026-09-18.
