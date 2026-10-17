# Campaign skeleton

Copy this directory into a campaign repository and fill it as the casework
proceeds. The skeleton is deliberately empty: every file below is a shape, and
the worked example (`example-profile.md`) is fictional.

A campaign is a git repository of its own. It never ships with the engine, and
its identifiers stay out of the shipped tree.

## Layout

    <campaign>/
      profile.md                       the lead working document
      evidence/
        name-search/<run>/             one stage-1 sweep per run
          observations.json
          SHA256SUMS
        social-profile/<run>/          one stage-2 handle sweep per run
          observations.json
          SHA256SUMS
        relation-map/<date>-<case>/    the co-mention map and its assertions

The tools create every run directory and write the two files in it; keep them
as written. One sweep per qualifier set. The run id carries the UTC timestamp.

## Reproduce

    name-search.py search --name "PUBLIC_NAME" \
      --qualifier "NARROWING_TERM" --campaign-dir <campaign> \
      --authorization-ref 'session grant or campaign record reference'

    motoko-social-profile collect --username PUBLIC_HANDLE \
      --site EXACT_SITE_ID --campaign-dir <campaign> \
      --authorization-ref 'session grant or campaign record reference'

    relation-map.py verify --dir <campaign>/evidence/relation-map/<run>

## Conventions

- The campaign root is the root of its own git repository; `evidence/` is a
  real directory, never a symlink.
- A name hit, a handle hit and a co-mention are leads, never identifications:
  the profile records them as leads with a date and a confidence.
- Time-anchor every assertion; a profile is a snapshot of what the public
  indexes held on the collection date.
- Report `blocked`, `failed` and `unknown` separately from `empty`; a partial
  sweep is never a clean result.
- Keep the operator's identifiers (phone numbers, handles, account names) out
  of any document that leaves the campaign.
