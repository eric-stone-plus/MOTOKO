# Person profile (lead working document) — John Smith

> Fictional example. The person, the accounts, the dates and the numbers are
> invented; only the shape is the skill's.

- Authorization / case: example grant, 2024-03-01
- Collection: 2024-03-01 09:00–10:10 UTC, 6 sweeps (140 requests),
  96 observations
- Evidence: `evidence/name-search/<run>/observations.json` (each run carries
  `SHA256SUMS`); relation map: `evidence/relation-map/20240301-example/`
- Discipline: this file is a lead working document, not an identification.
  A name hit is not the same person; a co-mention is not a relation; unknown
  is not absence.

## 1. Intelligence face (as of 2023, operator-provided)

| Dimension | Claim | Public-source check |
| --- | --- | --- |
| Education | Graduated from a foreign-language faculty | **Partial**: a 2022 graduation notice lists the name (see section 2.1); the degree date is inferred |
| Employment | A translation role at a state-owned enterprise, then a telecom vendor | Not found |
| Posting | An overseas posting in a French-speaking country | Not found |
| Interest | Ballet | Not found (a same-name novel mentions ballet — section 3, entry 3) |

Identifiers (operator-provided, 2024-03-01): `example_handle`; `+86 138****0000`.

## 2. Verified public traces

### 2.1 A graduation notice (the only strong trace)

- Source: a university department's article account, published 2022-05-20
- Hit: the name in the defence schedule, with a translation-track thesis title
- Inference (labelled): a master's student in the translation track, graduating
  around mid-2022 — consistent with the intelligence face
- Fields not attributable to the person: the supervisor and the committee names
  appear before the entry and may belong to the previous candidate

## 3. Same-name collisions (>= 3 distinct people)

| # | Entity | Date | Source | Note |
| --- | --- | --- | --- | --- |
| 1 | A volunteer at a mountain-rescue event | 2018 | an event account | same name, no link |
| 2 | A product manager at a hardware vendor | 2018 | a vendor account | same name, no link |
| 3 | A character in a serialized novel | 2021 | a fiction account | the only ballet co-mention; noise |

## 4. Negative conclusions (equally important)

- Employment, posting and interest: zero traces tied to the person across the
  keyless sweep's five default engines (search, news, encyclopedia, entity
  index, article index), four narrowing-term sets, two pages per paginating
  engine.
- Variant round: the traditional spelling returned a legitimate empty; the
  romanized spelling returned two same-name encyclopedia pages only.
- Identifier round: the handle and the phone number, as narrowing terms,
  returned zero observations; all rows came from the bare-name query.
- Handle sweep (8 exact sites): one candidate, four unknown, three failed. The
  candidate was withdrawn on review: the anonymous page's title is the
  platform's own name and the handle appears only in the URL/config (a login
  shell, not a profile page). Unknown and failed are not absence.
- Latest date tied to the person: 2022-05-20; after that only same-name noise.
- "No trace" = no public record in these indexes, not that the fact is false.

## 5. Confidence

- High: the 2022-05-20 notice lists the name in the translation track.
- Medium: the graduation date (inferred from the notice).
- Low / unproven: the employment trajectory, the posting, the interest.
- Not connected (same name): section 3, entries 1–3.
- Not connected (handle): `example_handle` — operator-provided and
  semantically consistent, with no public-source evidence.

## 6. Next anchors (by value)

1. The notice's full text (a browser session) → supervisor, defence date,
   committee.
2. The department's historical articles (class rosters, exchange lists).
3. The employer's public activity reports (volunteer, sports, posting).
4. Time after 2023: new traces, with a new operator-provided anchor.

## 7. Method and limits

- This example shows the keyless-sweep lane only. A run that also used native
  discovery records those queries as leads, not observations; the sweep counts
  above are unchanged.
- `name-search.py` v2: five default engines, two pages on the paginating ones,
  a per-run deadline and request budget; every run writes its evidence
  directory.
- `motoko-social-profile`: one handle, up to ten exact site IDs, one GET per
  site plus at most two same-service normalization hops, 2 MiB per page.
- The article index's links are signed and short-lived; the source full text
  was not retrieved (the link redirects to an anti-bot page).
- "Verified" = a public source supports the claim; "not found" = the
  intelligence face claims it but no public source records it; inferences are
  labelled.
