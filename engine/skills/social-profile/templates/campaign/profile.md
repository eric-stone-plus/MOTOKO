# Person profile (lead working document) — PUBLIC_NAME

- Authorization / case: <grant reference, date>
- Collection: <start>–<end> UTC, <N> sweeps (<M> requests), <K> observations
- Discovery backends: <native search, self-hosted crawl client, or none>;
  their hits are leads, not observations.
- Evidence: `evidence/name-search/<run>/observations.json` (each run carries
  `SHA256SUMS`); relation map: `evidence/relation-map/<run>/`
- Discipline: this file is a lead working document, not an identification.
  A name hit is not the same person; a co-mention is not a relation; unknown
  is not absence.

## 1. Intelligence face (as of <date>, operator-provided)

| Dimension | Claim | Public-source check |
| --- | --- | --- |
| Education | <claim> | <verified / partial / not found> |
| Employment | <claim> | <...> |
| Posting | <claim> | <...> |
| Interest | <claim> | <...> |

Identifiers (operator-provided, <date>): <handle>; <phone>. Record them, then
check them only through the public indexes (see section 4); never use them to log in
or to query private services.

## 2. Verified public traces

### 2.1 <the strongest trace>

- Source: <platform, account>, published <date>
- Hit: <the name as recorded>
- Inference (labelled as inference): <...>
- Fields not attributable to the person: <...>

## 3. Same-name collisions (>= <N> distinct people)

| # | Entity | Date | Source | Note |
| --- | --- | --- | --- | --- |

## 4. Negative conclusions (equally important)

- <dimension>: zero traces tied to the person — <scope, date>
- <variant round>: <result>
- <identifier round>: <result>
- Latest date tied to the person: <date>; after that only same-name noise.
- "No trace" = no public record in these indexes, not that the fact is false.

## 5. Confidence

- High: <...>
- Medium: <...>
- Low / unproven: <...>
- Not connected (same name): <...>
- Not connected (handle): <...>

## 6. Next anchors (by value)

1. <...>

## 7. Method and limits

- <tools, engines/backends, page limits, exit semantics>
- <discovery backends, their rendered queries, and what stayed a lead>
- <blocked sources and why>
- <what "verified" and "not found" mean here>
