---
name: exposure-selfcheck
description: Scan the operator's own host and workspace, read-only, for the operational exposures that de-anonymise an engagement — listening services on non-default ports, agent session artifacts, messaging-client config paths, and world-readable evidence directories. Use at engagement start and at wrap-up; it is a local self-check, not a target scan.
---

# Operational-artifact exposure self-check

Run the engine checkout's exposure self-check tool (`exposure-selfcheck.py`;
stdlib-only) before an engagement's first probe and again at wrap-up. It reads the local host only: it makes no
network request, writes nothing, and never opens a credential file. No
target authorization, scope record or egress lane is involved — it touches
nothing outside this machine. Its output is safe to paste into the
engagement record, because no credential value can appear in it.

A public checkout ships this method, not the tool — without the script, run
the same checks by hand.

The check exists because a leaked session record plus a service left open on
a non-default port de-anonymised an operator once. Both classes are in
scope, alongside the local artifacts that carry them:

- **listener** — the listening TCP sockets (`ss -tlnp`). A non-default port
  is reported; a wildcard or interface bind raises the severity, because
  that is the shape a remote host can reach. Loopback on a default port
  stays silent.
- **artifact** — agent session state directories (`.claude`, `.codex`,
  `.gemini`), `CLAUDE.md` context files, session/transcript-shaped files,
  and `.git` remotes that point at a public forge host.
- **im-config** — the EXISTENCE of known messaging/notification client
  config paths. This surface is a path check only: no client config is
  opened, and every finding says so. These stores hold the account and
  message state that links identities across engagements.
- **permissions** — report/evidence-shaped directories (`reports/`,
  `evidence/`, `obs/`, `intel/`, `findings/`, `campaign-*`) whose mode bits
  are world-readable or world-traversable.

Run it:

    python3 exposure-selfcheck.py             # scan the home
    python3 exposure-selfcheck.py --root DIR  # scan a workspace

Exit 0 means no findings; exit 1 means at least one finding — including a
check that could not run, because "could not determine" is reported, never
treated as clean; exit 2 is a usage error. Findings print worst-first as
`[SEVERITY] [surface] subject — why; fix: <the remedy>`, followed by one
summary line with per-severity and per-surface counts.

1. At engagement start, run it before the first launch and before campaign
   material lands in the workspace. Work the HIGH findings first: bind an
   ad-hoc service to loopback or stop it, and move or clean agent session
   state out of the tree the engagement will use.
2. Record the run's root and summary in the engagement's own record. The
   wrap-up comparison is only as good as the start baseline.
3. At wrap-up, run it again over the same root. A finding that appeared
   during the engagement is operational-artifact drift: it names state that
   must migrate out or be cleaned before the unit is sealed or exported.
4. Treat `im-config` findings as a decision, not a defect: the check proves
   the store exists and nothing more. Decide deliberately whether that
   linkage risk belongs on an engagement host.

Limits: this is a local, single-host existence-and-mode check. It does not
read file contents (the one exception is `.git/config` remote URLs, from
which only the remote name and host are printed), does not validate
credentials, does not scan the network, and does not fix anything — every
finding carries the remedy for the operator to apply. The messaging-path
list is a known-name list, not a discovery scan; extend it in the script
when a new client matters.
