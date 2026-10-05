---
name: social-profile
description: Inspect public profile candidates for one authorized username on explicitly selected sites, using pinned Social Analyzer heuristics and campaign-local evidence. Use for passive public-source investigation, not private-profile access or identity correlation.
---

# Social profile observations

Use `motoko-social-profile` for an authorized public handle. A matching handle
is a candidate for manual review; it does not identify a person or establish
that accounts belong to the same individual. Do not infer sensitive traits,
retrieve private profiles, bypass access controls, or feed matches into the
asset graph as identity assertions.

The wrapper performs unauthenticated public-page GETs. It has no login,
screenshots, OCR, browser, arbitrary URL, custom cookie, or bulk-name mode.
Public-page collection still makes requests visible to the selected sites.

1. Reuse the existing in-session authorization and read the campaign's scope
   record when present. If the requested handle/sites are outside that grant,
   obtain the missing scope before collection. A reference records a grant;
   it does not create one.
2. Run `motoko-social-profile doctor` and
   `motoko-social-profile sites --contains github.com` offline. Inspect the
   complete URL templates and choose exact site IDs. `--contains` only filters
   the display; collection accepts IDs, never substring selectors or `all`.
3. Use the campaign git root, outside the MOTOKO source tree, for evidence.
   Set the deployment's `MOTOKO_EGRESS_MODE=lane`, `https_proxy`,
   `MOTOKO_EGRESS_ECHO_URL` (HTTPS, plain IP response), and
   `MOTOKO_EGRESS_EXPECT_IP`. The collecting process checks its own lane
   route immediately before requests. Do not print lane credentials.
4. Collect one handle with up to ten sites:

   ```bash
   motoko-social-profile collect --username PUBLIC_HANDLE \
     --site EXACT_SITE_ID --campaign-dir /path/to/campaign-repo \
     --authorization-ref 'session grant or campaign record reference'
   ```

5. Read the returned evidence path. Report `candidate`, `unknown`, and `failed`
   separately. Upstream percentages are heuristic rule-match rates, not
   identity probabilities. Unknown is not evidence of absence. Report blocked,
   redirected, throttled, and failed observations without retrying around them.
   Evidence records source/data/adapter/dependency hashes and per-page response
   digests; raw pages, biography, contact fields, and cookies are not retained.

Limits are enforced: sequential requests, one GET per selected site, no
redirects/retries, 512 KiB per page, and a 90-second overall deadline. A 429
stops the remaining requests. Exit 0 means observations completed (including
unknowns); 1 means some collection failed; 2 means preflight refused/failed.
Expired deadlines produce no completed report. Never label them a clean result.

If absent, install from the engine checkout with
`python3 core/tools_anchor/social_analyzer/install.py` (git and uv required).
It creates an external pinned checkout plus an isolated Python environment,
the CLI, and this seat's discoverable skill link. The engine keeps its stdlib
runtime. The source remains on its upstream AGPL-3.0 license; it is not vendored.
Do not run the raw upstream CLI: it disables TLS verification, widens site
selection by substring, and retries. Update pins only with source review and
the offline tests in the private suite (`test_social_profile.py`).
