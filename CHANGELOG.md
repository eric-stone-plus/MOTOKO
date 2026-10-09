# Changelog

Notable changes to this public repository. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The engine version
is the package version in `engine/pyproject.toml`; the engine tree is a
one-way export from its source tree, so engine changes appear here as
exported.

## [Unreleased]

### Changed

- The terminal interface is retired: `motoko` with no command prints the
  one-shot read-only status snapshot, `motoko watch --once` is the
  findings-watchdog sweep (bare `watch` and `motoko interface` are
  refused), and the `interface` packaging extra is gone — the status path
  stays stdlib-only.
- The CI language-policy guard also scans `engine/` and tracked file
  names, and refuses to pass when a scan cannot complete; it runs with a
  read-only token, per-job timeouts, and cancels superseded runs.
- The `motoko/1` status frame keeps unknown counts unknown: an engagement
  whose graph could not be read reports `null` queue and in-flight totals
  instead of a fabricated zero, so a host renders "unknown" rather than
  "nothing queued".
- The NOTICE asserts the Required Notice explicitly as an AGPLv3 §7(b)
  additional term; no other section-7 additional terms are asserted.
- The engine wheel declares AGPL-3.0-or-later as a PEP 639 license
  expression, with project URLs and classifiers in its metadata.
- The public export surface names the engine capability skills: they live
  under `engine/skills/<name>/` and travel with the engine export (the
  social-profile installer depends on them), replacing a blanket
  "no skills here" rule in AGENTS.md.
- The social preview image is served from the Pages site itself: `web/og.png`
  is added and og:image points at the Pages URL instead of
  raw.githubusercontent.com.

## [0.7.0] - 2026-10-08

First tagged public snapshot: the engine package (`core-engine` 0.7.0,
console script `motoko`), the ontology and contract documents, the citation
map, the research survey, and the landing page.
