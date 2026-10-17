---
name: chain-analysis
description: Read public on-chain data for an authorized address set — address → label → cluster → evidence chain — from public explorer APIs, the OFAC SDN export, and court filings only, never a self-built index. Use for passive public-source investigation; clustering results are leads, not facts.
---

# Chain analysis: address → label → cluster → evidence chain

Read one authorized address set from public sources and record what each source
says, with its citation and fetch time. This skill is a reading path, not a
toolchain: it queries public endpoints per address, reads court and sanctions
records, and keeps every claim attached to the source that made it. Clustering
produces leads for review; it never produces facts about ownership. The output
is an evidence chain a second analyst can re-walk, not a verdict.

Public-page and public-API collection still makes requests visible to the
endpoints queried. Route it through the deployment's declared egress lane as
for any collection; this skill adds no direct-dial path of its own.

## Capability surface

Public sources only:

- **Public explorer / API endpoints** (mempool.space and equivalents;
  blockchair-style address endpoints). Per-address reads: transaction history,
  funding sources, balances. Unauthenticated GETs, no key, no login.
- **The OFAC SDN export** (`SDN.XML`, published by Treasury) — the sanctions
  layer. Cross-check it with `scripts/sdn-addresses.py --input SDN.XML --json`,
  which parses the published file; the script never re-derives or fetches it.
- **Court filings and official announcements** (complaints, forfeiture
  dockets, DOJ/Treasury press releases). Only these can carry an ownership or
  custody assertion with legal weight; quote the paragraph number and docket.
- **Third-party analytics entity pages** — secondary labels only; every one is
  self-reported, and each use must carry its own URL and fetch time.

Not in the capability surface: **a self-built index of the chain.** No crawling
the blockchain into a local database, no bulk address ingestion, no
"all addresses of entity X" datasets. An index is a standing claim about every
address in it; this skill only ever makes dated claims about the addresses it
was asked about.

## Clustering heuristics, and their failure modes

Each heuristic produces a lead. Record the observation (txids, windows,
counts) next to the lead, never only the conclusion.

- **Common spending (co-spend).** Two outputs spent together in one transaction
  suggest one controller; an address with a public notation plus others that
  co-spent with it is a stronger form of the same lead. *Failure modes:*
  exchanges and services co-spend on behalf of many users; CoinJoin and other
  collaborative transactions; batched sweeps by custodians; mining pools
  consolidating payouts. The FBI's own example uses co-spend ("co-spent with
  that address, demonstrating shared ownership", complaint footnote 9) — treat
  the same observation as an inference and keep the txids.
- **Same-batch / similar funding patterns.** Addresses funded in the same
  window by the same sources, or showing the same source mix, group as one
  candidate cluster. *Failure modes:* an exchange's withdrawal batching pays
  thousands of unrelated users in one transaction; mining pools pay many
  workers in one round; airdrops and faucets. "Similar funding patterns" in a
  complaint is a summary label, not a published algorithm — do not present a
  quantitative version of it as the author's method.
- **CEX deposit/withdrawal linkage.** Following funds into or out of known
  exchange wallets, or matching deposit/withdrawal pairs, links an address to
  an account holder. *Failure modes:* deposit addresses rotate per user and
  per deposit; internal exchange transfers are invisible on chain; "indirect
  transfers" through unhosted intermediaries (complaint footnote 8)
  deliberately break the direct edge; a deposit address is the exchange's, not
  the depositor's.
- **Third-party entity labels.** A public analytics entity ("this cluster is
  X") is a lead with a source. *Failure modes:* unverifiable self-reported
  method, staleness, undocumented overlap with other clusters.

## Discipline (rules)

1. **Clustering produces leads, not facts.** A cluster is a hypothesis with
   evidence attached; write it as a candidate, never as an identification.
2. **Every label carries a source.** No label, name, or attribution enters the
   output without the source that made it and its date.
3. **Cross-check against the OFAC list.** Run every address of interest through
   `scripts/sdn-addresses.py` against the current SDN export. A match and a
   miss are both recorded with the export's publication date; neither is a
   verdict beyond the sanctions layer.
4. **Never let a single source become a conclusion.** One filing, one
   explorer, one analytics entity — each is a source, not a finding. Where
   sources disagree or are silent, say so; do not average them.
5. **Every output row carries {source, fetch time, citation}.** Source is the
   URL or file plus its own publication/version date; fetch time is when the
   analyst retrieved it; citation is the paragraph, entry uid, txid, or block
   height inside the source. A row missing any of the three is not an output.

## Worked reading path: the "thirteen clusters" framing

The 2025 EDNY Prince Group forfeiture complaint (United States v.
Approximately 127,271 BTC, No. 1:25-cv-05745-BMC, E.D.N.Y., Doc. 1, filed
2025-10-14, https://www.justice.gov/usao-edny/media/1416291/dl) is the worked
example. The steps below reproduce its framing from the public record and mark
exactly where the public record stops.

1. **Fix the address set from the court record.** Complaint ¶44: the funds
   "was stored across 25 cryptocurrency addresses in unhosted wallets
   controlled and personally tracked by Chen (the 'Chen Wallets')", followed
   by a table; Attachment A repeats the list. Extraction check: the ¶44 table,
   the ¶46 cluster table, and Attachment A each carry exactly 25 addresses and
   the three sets are equal. (The ¶44 amounts sum to ≈127,271.15 BTC against
   the action's "approximately 127,271 bitcoin".)
2. **Read the funding labels.** ¶45: the addresses "were primarily funded by
   two categories of sources: (1) cryptocurrency mining, including addresses
   associated with Lubian and Warp Data; and (2) indirect transfers from
   wallets at centralized cryptocurrency exchanges…". Footnote 8 defines
   "indirect transfers" as transfers that "passed through unhosted
   intermediary wallets". ¶47 a–m gives the per-cluster primary pattern, and
   footnote 9 gives two observable forms: a "Lubian.com" notation on chain
   plus co-spend, and a funding-mix check ("only 30% funded by newly mined
   cryptocurrency" against the more than 80–90% typical for mining
   operations).
3. **Read the clustering claim.** ¶46: "FBI cryptocurrency analysts have
   determined that the addresses composing the Chen Wallets can be grouped
   into thirteen clusters of one or more addresses ('Cluster Index-1' through
   'Cluster Index-13') ... with addresses within the same cluster exhibiting
   similar funding patterns." The accompanying table partitions the same 25
   addresses into the 13 clusters. The "25 vs 13" figures are the same set in
   two views — an address count and a cluster count — not a conflict.
4. **Cross-check the sanctions layer.** Fetch the SDN export, run
   `scripts/sdn-addresses.py --input SDN.XML --json`, and match the address
   set. Observed 2026-10-16 against the 2026-10-15 publication: the CHEN, Zhi
   entry (uid 55505, program TCO) carries 29 digital-currency addresses, and
   none of the complaint's 25 addresses appears anywhere in the export. That
   zero intersection is a finding about two different datasets — a sanctions
   list and a forfeiture record — not a contradiction of either.
5. **Spot-check chain reality, read-only.** Public explorer API, e.g.
   `https://mempool.space/api/address/<address>`. Observed 2026-10-16 for the
   ¶50 destination `34Jpa4Eu3ApoPVUKNTN2WeuXVVq1jzxgPi` (≈11,115.83 newly
   mined BTC in ≈1,477 transactions, 2020-04-24 to 2020-12-28): 1,566
   transactions, 1,416,739,250,939 sats received, fully spent. The explorer's
   aggregate is a lifetime view; the complaint's table is a December-2020
   snapshot — record both with their dates instead of forcing equality.
6. **Treat third-party labels as leads.** Public analytics entity pages label
   clusters by their own methods; cite the entity page and fetch time, never
   adopt the label as fact. Boundary example: the labeling source's own
   analysis (https://info.arkm.com/research/us-government-btc-seizure-lubian-chen-zhi-pig-butchering,
   fetched 2026-10-16) states "The exact method by which the BTC came into
   U.S. custody is still unclear" — even the analyst closest to the case draws
   the line there.

**What this reading path does NOT claim.** It does not reproduce the FBI's
partition: the complaint names the clusters but publishes no clustering method
beyond "similar funding patterns" and the two footnoted observations, so an
independent analyst cannot claim the same 13-cluster index. It does not
establish ownership or identity from clustering. It does not claim the
complaint addresses are OFAC-listed (measured: zero overlap) — and their
absence from the list does not exculpate either. It does not claim how or when
the United States obtained control of the funds; ¶58 states custody, not
mechanism. It does not adjudicate competing narratives about the 2020
movement — those are cited claims in dispute, not adopted facts.

## Boundaries and refusals

- **Refuse identity assertions from clustering alone.** "Address X belongs to
  person Y" needs a court, sanctions, or official source that names it — and
  even then the output cites the source rather than laundering it into an
  observation.
- **Refuse to present a cluster count as stable truth.** Cluster boundaries
  move with the heuristic and the address set; a count is one partition on one
  date, not a property of the entity.
- **Refuse to treat OFAC presence or absence as proof of anything beyond the
  sanctions layer.** A refusal from `sdn-addresses.py` (exit 2) is a failed
  read, not an empty result: fix the input before citing the list.
- **Refuse to build an index.** No bulk ingestion, no local chain database,
  no standing "addresses of X" set. Queries stay per-address and dated.
- **Refuse to fill gaps.** Where the record is silent — e.g., the mechanism by
  which seized funds entered custody — the output says "not stated in the
  record". An explicit blank is a finding; an inferred fill is a defect.
- **Refuse to strip provenance.** An output row without source, fetch time,
  and citation is not an output, whatever its content.
