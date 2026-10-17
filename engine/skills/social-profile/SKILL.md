---
name: social-profile
description: Build one authorized person's public-source profile in two stages — sweep public search, news, encyclopedia and article indexes for the name (plus narrowing terms), using the seat's native search for discovery and the keyless sweep as the evidence backbone, then inspect public profile candidates for the handles those leads surface — recording every candidate as campaign-local evidence. Use for broad lead collection and passive public-profile review in casework, not identity resolution or private-data access.
---

# Person profile observations

Two collection stages, one discipline. A name match and a handle match are both
leads for manual review: neither identifies a person, neither establishes that
two mentions are the same individual, and neither proves a relationship between
people who appear together. Do not infer sensitive traits, retrieve private
profiles, bypass access controls, or feed matches into the asset graph as
identity assertions.

## Shared preconditions

1. Reuse the existing in-session authorization and read the campaign's scope
   record when present. If the name, the handle, or the intended use is outside
   that grant, obtain the missing scope before collection. A reference records
   a grant; it does not create one.
2. Use the campaign git root, outside the shipped MOTOKO source tree, for
   evidence; the checkout's gitignored `tasks/` workspace is local-only and
   acceptable (it never enters git and never ships). The declared egress lane
   covers the keyless sweep, and Stage 2 only where that tool honors the
   forwarding variable and the echo check. For those, set the deployment's
   `MOTOKO_EGRESS_MODE=lane`, the HTTPS forwarding
   variable (`https_` + `prox` + `y`, assembled from parts),
   `MOTOKO_EGRESS_ECHO_URL` (HTTPS, plain IP response), and
   `MOTOKO_EGRESS_EXPECT_IP`. The collecting process verifies its own exit IP
   through the echo before the first request. Do not print lane credentials.
3. The seat's native search and any page fetch through the seat are not routed
   through that lane. The request leaves the host on the seat's own network
   path; the search provider sees the query, the requesting address, and a
   short hint taken from the session context. Use native search for
   non-identifying discovery unless the grant covers that disclosure; run
   person identifiers through the lane-backed sweep. A page fetch may be served
   by the provider or by a direct request, and you cannot tell which; treat it
   as a possible direct contact with the target. Record which backend received
   which query and which path fetched each page.
4. Report `blocked`, `failed`, and `unknown` separately from `empty`: an empty
   result is not an absence, and a blocked source is not a clean sweep. Never
   label a partial sweep a clean result.
5. Time-anchor every assertion. A profile is a snapshot of what the public
   indexes held on the collection date, not a standing fact: the subject may
   have changed employer, city, or handle since.

A campaign skeleton and a fictional worked example live in
`templates/campaign/`; copy the skeleton into the campaign repository and keep
its `profile.md` a lead working document.

## Stage 1 — the name sweep and discovery

The keyless sweep is the evidence backbone: it is the only name-search surface
here that writes byte-hashed observations, and its output is what the relation
map consumes. The seat's native search tool (`websearch`) and, where the
deployment provides one, a self-hosted crawl client (`fcrawl search`) are
discovery surfaces: their hits are leads, not observations, until the page is
fetched and the mention is re-observed by the sweep.

**Native search.** One query returns at most five results, each with a title,
URL, a summary, and a publication time when the index has one. It exposes no
relevance or authority score. The query is capped at 128 characters and the
service refuses a longer one; it does not truncate. An empty result is a
successful "no results" answer, not an error; a rate limit, an authentication
failure, or a timeout is an error and must be recorded as `blocked` or
`failed`, never as empty. A content switch returns full page text instead of
summaries and can produce a very large response; use it only for a page you
will actually read.

**Self-hosted crawl client.** Where the deployment provides one, its search is
a second request path, not a multi-engine aggregator: the current stack queries
a single public web index that overlaps the sweep's web engine, so agreement
between the two is not independent corroboration. Its news and image source
switches may degrade to a web search, its recency filter is unreliable, and its
result bound is not a yield. Its empty result is ambiguous: an upstream block
and a genuine zero can look the same. Classify it from the client's own stack
log when the deployment exposes one, matching the exact query term and a UTC
time window; otherwise record `unknown`, never `empty`. Its `scrape` verb is a
retrieval fallback for a page the seat's fetch cannot render. The client runs
on the host path, not the lane.

**One plan, rendered per backend.** Write the intent once — the name or phrase,
up to four narrowing terms, the language market, and the date window — then
render it for each backend. The native query is a short operator-bearing phrase
of at most 128 characters; the sweep takes the name and qualifiers as flags;
the crawl client takes a broad phrase. Record the exact rendered query for each
backend. If the native rendering exceeds 128 characters, drop the date window
first, then the least discriminating qualifier, and record what was dropped;
never truncate silently. Run every backend that is up: the ladder is for
coverage, not agreement.

**Merge leads, not evidence.** A candidate seen by two backends is one lead with
two provenance notes, not two findings. Identity is the URL for stable links,
and (title, account or publisher, date) for signed or expiring wrappers; two
rows that share only a title are two articles. Record which backend and which
rendered query surfaced each lead. Agreement is not corroboration when the
backends share an upstream index. A native or crawl hit stays a lead until the
page is fetched and the mention is re-observed by the sweep.

Run the engine checkout's name-sweep tool (`name-search.py`; stdlib-only, no
install step). It runs a bounded sweep across a fixed set of keyless public
endpoints and records what each returned as candidate mentions. A public
checkout ships this method, not the tool — without the script, run the same
queries by hand with the same discipline.

1. Run `name-search.py doctor` and `name-search.py engines` offline first.
   `engines` lists the engine ids, hosts, and per-engine caveats; collection
   accepts exact ids, never substring selectors.
2. Sweep one name with up to four narrowing terms (for example a city,
   employer, or year — anything that disambiguates without presuming an
   identity):

   ```bash
   name-search.py search --name "PUBLIC_NAME" \
     --qualifier "NARROWING_TERM" --campaign-dir /path/to/campaign-repo \
     --authorization-ref 'session grant or campaign record reference'
   ```

   The language market defaults from the name's writing system (Han → zh-CN,
   kana → ja, hangul → ko, Cyrillic → ru, Arabic → ar, Thai → th, else en);
   `--lang` pins it explicitly (supported values are listed on refusal). A
   Han-only Japanese name maps to zh-CN — pass `--lang ja` for those.
   `--engine` narrows the sweep (`all` re-admits non-default engines);
   `--max-items` bounds rows kept per response; `--pages` (1-5) follows a
   query into deeper result pages on the engines that paginate. Prefer several
   sweeps with different qualifier sets over one wide sweep: each lands as its
   own evidence run and the deadline is per run.
3. Read the returned evidence path (`evidence/name-search/<run>/observations
   .json` plus `SHA256SUMS`). Each observation carries the engine, the query
   id, the page, the rank as returned, title, URL, snippet, publisher when the
   engine provides one, fetch time, and the sha256 of the response bytes it
   was parsed from. The same file carries `candidates`: one row per article,
   merging the observations that share it, with every query id and engine that
   surfaced it — review that view first and keep `observations` as the
   per-response audit trail. Identity is the URL for engines with stable
   links, and (title, account, date) for sogou, whose article links are
   per-search signed wrappers; two rows that share only a title are two
   articles (two Wikidata entities can share a label).

Engine notes (measured 2026-10-17): `sogou-weixin` is the highest-yield engine
for zh-CN names — school and employer traces live in WeChat posts by
student-union and department accounts, which the open web indexes usually
miss; its `source` field carries the account name (for example
`法语系研会@bfsu`). `bing-web` fabricates plausible filler items for a query
with no matches, so every FEED engine (`bing-web`, `bing-news`, `gnews`,
`sogou-weixin`) drops each item that does not carry the queried name and
records the drop count — treat `items_dropped > 0` as evidence of that
behavior, not as filtering noise. `bing-news` is out of the default set: its
RSS endpoint 302s to the homepage for every query, so select it explicitly
only to re-test. The name match is whitespace-normalized and, for non-CJK
scripts, anchored on word boundaries of any script (a two-letter name like
`Li` must not match inside "public", and `Иван` must not match inside
`Иванов`); CJK names match as substrings, and script variants are exact — a
traditional-script page does not match a simplified query (the reviewer
bridges that, not the filter). Every engine's rows must carry the name, the
two lookup engines included: the Wikipedia search API matches fuzzily (a live
sweep for a name with no article returned 50 unrelated pages), so the same
filter applies there. `gnews` links are Google aggregator wrappers; the
publisher rides the `source` field. `sogou-weixin` article links carry
expiring tokens — cite title + publisher + fetch time, and treat the link as
perishable. DuckDuckGo HTML, Baidu, and Mojeek measured blocked through the
lane and are not included (the crawl client's host-path search is a separate
path; it does not make DuckDuckGo a lane-cleared sweep engine).

Pagination and recency, measured live 2026-10-17: only `sogou-weixin` (`page`)
and `wiki` (`sroffset`) actually paginate. bing ignores `first`, gnews and
wikidata have no page parameter, and sogou's `tsn` recency parameter returns
zero cards even for a high-volume name — read the `published` dates in the
observations instead of filtering at the source.

Limits are enforced: sequential requests with a one-second spacing, one GET
per (query, engine, page) cell, no redirects/retries/cookies, 512 KiB per
response, at most 30 kept rows per response by default (`--max-items` up to
100), and a 300-second overall deadline. A plan that cannot fit the deadline
at ~4.5 s/request is refused before the first request (reduce `--pages`,
qualifiers, or engines); a page with no items at all ends that query's paging
(a page whose items were all dropped keeps paging — the wiki API matches
fuzzily). A 429 or a bot challenge stops that engine's remaining queries and
records the skip; other engines continue. Exit 0 means every selected engine
completed (including legitimately empty results); 1 means at least one engine
was blocked or failed; 2 means preflight refused/failed, or the 300-second
deadline aborted the sweep (nothing is written — split the sweep and re-run).

The keyless sweep's observations are the input to the `relation-map` skill:
track the names worth pursuing, then build the evidence-backed relationship map
from those observations rather than from memory. Record the discovery backends,
their rendered queries, and the leads they surfaced in `profile.md`; do not add
them to the sweep's request or observation counts.

## Stage 2 — handle and profile candidates

Use `motoko-social-profile` for an authorized public handle. A matching handle
is a candidate for manual review; it does not identify a person or establish
that accounts belong to the same individual.

The wrapper performs unauthenticated public-page GETs. It has no login,
screenshots, OCR, browser, arbitrary URL, custom cookie, or bulk-name mode.
Public-page collection still makes requests visible to the selected sites.

1. Run `motoko-social-profile doctor` and
   `motoko-social-profile sites --contains github.com` offline. Inspect the
   complete URL templates and choose exact site IDs. `--contains` only filters
   the display; collection accepts IDs, never substring selectors or `all`.
2. Collect one handle with up to ten sites:

   ```bash
   motoko-social-profile collect --username PUBLIC_HANDLE \
     --site EXACT_SITE_ID --campaign-dir /path/to/campaign-repo \
     --authorization-ref 'session grant or campaign record reference'
   ```

3. Read the returned evidence path. Report `candidate`, `unknown`, and `failed`
   separately. Upstream percentages are heuristic rule-match rates, not
   identity probabilities. Unknown is not evidence of absence. Report blocked,
   unfollowed redirects, throttled, and failed observations without retrying
   around them. Evidence records source/data/adapter/dependency hashes and
   per-page response digests; raw pages, biography, contact fields, and cookies
   are not retained.
4. Review every `candidate` before treating it as a lead: a generic shell whose
   title is the platform's own name (a login wall) and that names the handle
   only in the URL is a false positive; a profile page names the handle in its
   title or metadata. Record the review with the candidate.

Limits are enforced: sequential requests, one GET per selected site plus at
most two same-service normalization hops (a bare host to its `www.` form, a
`mobile.` host to the bare one, Twitter to `x.com`, or an added trailing
slash; the scheme, query and path stay), no other redirects or retries, 2 MiB
per page, and a 90-second overall deadline. A 429 stops the remaining
requests. Exit 0 means observations completed (including unknowns); 1 means
some collection failed; 2 means preflight refused/failed. Expired deadlines
produce no completed report. Never label them a clean result.

If absent, install from the engine checkout with
`python3 core/tools_anchor/social_analyzer/install.py --skill-dir <skill root>`
(git and uv required; `MOTOKO_SKILL_DIR` may name the root instead). The
skill root belongs to the seat/host — the engine carries no default. It
creates an external pinned checkout plus an isolated Python environment,
the CLI, and the skill link into that root. The engine keeps its stdlib
runtime. The source remains on its upstream AGPL-3.0 license; it is not
vendored. Do not run the raw upstream CLI: it disables TLS verification,
widens site selection by substring, and retries. Update pins only with source
review and the offline tests in the private suite (`test_social_profile.py`).

## Choosing the stage, and the rules that span both

- Start with the lane-backed name sweep when you have a person's identifier.
  It surfaces the mentions that name the handles worth inspecting; do not
  guess handles before it. Native search is for non-identifying discovery
  unless the grant covers the provider disclosure (see the shared
  preconditions).
- Move to the handle sweep with the handles the leads actually surface, and
  with the sites those leads make relevant. A handle hit is a candidate, never
  the person.
- A co-mention is a shared page, not a tie. A candidate is a lead, not an
  identification. Unknown is not absence. Say which of the three you have.
- Keep every claim time-anchored and cite the evidence path, the source, and
  the fetch time — links rot, and a profile without dates goes stale silently.
