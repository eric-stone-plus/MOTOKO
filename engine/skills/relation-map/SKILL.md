---
name: relation-map
description: Build an evidence-backed relationship map for a case — entities, co-mention leads derived from collected observations, and investigator-declared relations with citations — rendered as JSON, Mermaid, Graphviz and an evidence table. Use after a name sweep, not as a substitute for evidence.
---

# Relationship map

Use the engine checkout's relation-map tool (`relation-map.py`) to turn
collected observations into a relationship map. A public checkout ships this
method, not the tool. The map is a working aid: a co-mention edge means two names
appeared on the same page, which is a lead, not a relationship; a declared
edge is the investigator's assertion and carries the citations that back it.
Never present a co-mention as a tie, never present an unasserted declared edge
as sourced, and never treat a name match as an identity assertion.

1. Collect first. Run `social-profile` Stage 1 (the name sweep; one sweep per
   name, evidence in the campaign repo). The map is derived from those
   observation files — the tool records each input's sha256 so the map can be
   re-derived and checked later. Native-search and crawl-client hits are leads,
   not observations; re-observe them with the sweep before they enter the map.
2. Write the tracked entity list: a plain text file with one name per line
   (`#` comments allowed), or JSON — either a bare list of names, or
   `{"entities": [{"name": ..., "type": ..., "aliases": [...]}]}` with
   `name` required and `type` free-form (e.g. person/org/account/wallet;
   default `unknown`). Aliases are
   how transliterations and trade names attach to one entity; a name or alias
   listed twice is refused (ambiguous matching is worse than no matching).
   Entity ids are assigned in sorted-name order, so ids are stable across
   runs.
3. When you already have asserted relationships with sources (a court filing,
   a corporate registry, a news report), add a relations file: JSON
   `{"relations": [{"source": ..., "target": ..., "type": "owns", "basis":
   ..., "evidence": [{"ref": "case-1", "url": ...}]}]}`. Source and target
   resolve against entity names and aliases; an endpoint that resolves to
   nothing is added as `unlisted` with a warning; a relation without evidence
   is recorded as `unasserted` and warned about — never silently dropped.
4. Build:

   ```bash
   python3 relation-map.py build \
     --entities entities.txt \
     --observations /path/to/campaign/evidence/name-search/<run>/observations.json \
     --relations relations.json \
     --out /path/to/campaign/evidence/relation-map/<date>
   ```

   `--observations` repeats; `--relations` is optional; `--out` must not
   exist yet and must sit outside the MOTOKO tree. The recommended location
   is the campaign repo's evidence lane.
5. Read the outputs: `relations.json` (schema `motoko-relation-map/1` — every
   edge with its evidence refs, every entity with mention counts, by-engine
   breakdown, and first/last seen), `relations.mmd` (Mermaid: dashed edges
   are co-mention leads, solid edges are declared), `relations.dot`
   (Graphviz, same convention), `README.md` (the edge and entity evidence
   tables, warnings, and the exact rebuild command), and `SHA256SUMS`.
   Warnings are part of the result: unlisted endpoints, merged duplicates,
   and unasserted edges are listed there and in the README.
6. Verify before citing: `python3 relation-map.py verify --dir
   <map-dir>` re-reads the recorded inputs, re-derives the map, and compares.
   `reproducible: true` (exit 0) means the artifact still matches its inputs;
   a mismatch is exit 1; a missing input is reported as `reproducible: null`
   — unknown, not verified. Verify also checks the recorded `tool_sha256`:
   a map sealed by a DIFFERENT tool revision is exit 1 — rebuild and reseal
   it rather than citing it. Run verify from the same directory the inputs
   were recorded in, or use absolute input paths at build time.

The output is deterministic: the same inputs render byte-identical output
with the generation time pinned by `SOURCE_DATE_EPOCH` (unset = wall clock),
which is what makes the verify comparison meaningful.

Limits: refusals (missing or malformed inputs, duplicate names, self-relation,
an existing `--out`, a map inside the MOTOKO tree) exit 2; a verify mismatch
exits 1; success exits 0. Co-mention evidence is capped at 20 refs per edge
with the full count kept. The map counts rows, not articles, and it does not
dedupe across observation files: pass each file once; if you pass more than one
lane, merge by identity for counts and keep the raw files for the map. A row
with neither title nor snippet is dropped silently, so keep the title or
snippet on every observation. The tool never fetches anything: it reads local
files only, so all network discipline stays with the collection step. No
installation is required — stdlib-only, runs from the engine checkout.
