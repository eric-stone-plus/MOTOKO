# Graph

MOTOKO's only new claim is **re-orchestration**: existing agents and scanners
already work; the missing piece is a graph that binds them, with interrupts
where a human or a scope gate must speak. The ghost question — whether a self
is present once every prosthesis is named — is [GHOST.md](GHOST.md). This file
is only the connective tissue.

This is not a new scanner and not a new agent runtime. Hermes remains the
operator-facing invoker. Strix remains the proof-seeking pentest agent.
Nuclei and Kali remain tools. LangGraph is the instrument that *names*
nodes, edges, and interrupts so the composition is inspectable. Live
scheduling on the operator host is the motoko skill in the Hermes
profile shell; this file is still the contract, not a shipped
`StateGraph` app.

The implementing library is cited in [INSTRUMENTS.md](INSTRUMENTS.md)
(LangGraph, MIT). This file is the contract. It does not vendor that tree.

## Why a graph

A linear playbook hides the real control flow: authorization can refuse the
whole run; recon can fan out; a destructive edge must pause; validation is
optional; the operator may re-enter from IM at any interrupt.

Those are graph facts:

| LangGraph primitive | MOTOKO use |
|---|---|
| `StateGraph` | One engagement state: scope, assets, findings, evidence, budget |
| node | One instrument or one gate |
| conditional edge | Scope fail → END; proof needed → Strix; else → report |
| `interrupt` / `interrupt_before` | Circuit breaker: destructive or mutating action |
| `Send` fan-out | Parallel in-scope recon/scan, bounded by host budget |
| reducer | Findings and evidence append; they never silently overwrite |
| checkpointer | Engagement recovers after IM disconnect |

Hermes gateway is the **invoker**. It is outside the graph. IM messages enter
as graph input; they are not a node.

## State

One engagement, one state object. Fields are facts, not chat.

```text
scope        : signed authorization, or empty
assets       : in-scope hosts / URLs / CIDRs already observed
findings     : append-only (id, CWE, CVSS, evidence hash, verdict)
evidence     : append-only (path, sha256, timestamp)
budget       : strix_inflight, nuclei_concurrency, mem_available
halt         : none | no-scope | out-of-scope | circuit-breaker | operator-abort
```

No scope in state → the graph may not call a probe node.

## Nodes

```text
                    ┌──────────┐
   IM / Hermes ───► │  invoke  │  (not a node)
                    └────┬─────┘
                         ▼
                    ┌──────────┐
                    │  scope   │  authorization
                    └────┬─────┘
                     empty│    │signed
                          ▼    ▼
                        END   recon
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
          whatweb           katana         pd-recon
         (fingerprint)   (URL / JS)    (subfinder /
                         uncover          httpx)
              └────────────────┬────────────────┘
                               ▼
                             scan
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
            nuclei         gowitness /      arjun /
                           trufflehog       dalfox
              └────────────────┬────────────────┘
                               ▼
                        needs proof?
                         │         │
                        yes        no
                         ▼         │
                       strix       │
                         │         │
                         └────┬────┘
                              ▼
                     kali (serial) → report
                              ▼
                             END
```

Circuit breaker is an **interrupt**, not a node that improvises. Any edge that
would write, exploit, escalate, delete, or DoS hits `interrupt` and waits for
the operator on IM. Resume is explicit. There is no default-yes.

Out-of-scope asset discovered mid-recon: conditional edge to `halt`, not a
pivot.

A name from recon is not an asset until it matches signed scope
(registrant / ASN / explicit seed). Sibling names on the same parent TLD
that belong to other tenants (cloud customers of a seed) stay out.

## Verify edges

These are graph facts, not host folklore:

- `dalfox` consumes XSS candidates (CWE-79 / titled XSS) from scan or Strix.
  It is not a generic URL probe. No candidate → skip the node.
- `searchsploit` consumes whatweb fingerprints. No fingerprint → skip.
- Directory bust is one node per asset: gobuster *or* ffuf, not both.
- `subfinder` takes DNS names, not IPv4.
- `uncover` is optional intel. No provider output → skip, do not fail.

## Host bounds as graph config, not folklore

These are compile-time *kinds* of limit, not folklore:

- Strix node: small parallel budget, shared with any other consumer of
  the same LLM key
- Nuclei node: moderate CPU-bound concurrency
- Kali node: serial on host networking
- Memory / load floor: if the floor is breached, the graph interrupts
  instead of starting another heavy node

Exact numeric caps live with the operational profile, not here.

## What this file does not do

- It does not ship a Python `StateGraph` app. Wiring lives with the host when
  you compile it against the LangGraph shell.
- It does not replace Hermes, Strix, or Kali playbooks.
- It does not add a MOTOKO skill tree. Skills stay in the profile shell; the
  graph calls them as nodes.

## License

LangGraph is MIT (LangChain, Inc.), upstream `langchain-ai/langgraph`.
This graph contract is original MOTOKO text (PolyForm Noncommercial 1.0.0).
Citing LangGraph is not combining it into this ontology's license.
