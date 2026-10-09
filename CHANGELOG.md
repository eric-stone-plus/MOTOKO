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
  names, and refuses to pass when a scan cannot complete.

## [0.7.0] - 2026-10-08

First tagged public snapshot: the engine package (`core-engine` 0.7.0,
console script `motoko`), the ontology and contract documents, the citation
map, the research survey, and the landing page.
