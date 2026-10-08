# Security policy

## Reporting a vulnerability

Report vulnerabilities in MOTOKO through GitHub's private vulnerability
reporting on this repository (Security → Report a vulnerability). Do not open
a public issue for an unfixed vulnerability.

Include what you can: the version or commit, the deployment shape (engine
host, seat, adapter), reproduction steps, and the impact you believe it has.

## Scope

In scope, for example:

- scope-gate bypasses — an action that runs outside the declared scope, or a
  refusal that can be evaded;
- secret handling — an argv, log, or evidence path that exposes a
  `MOTOKO_SECRET_*` value or a host credential;
- egress-policy bypass — a tool or replay fetch that leaves through an
  undeclared route;
- parser command injection — tool output that can inject argv or shell
  tokens;
- evidence integrity — a seal or event-log verification that passes over
  tampered data.

Out of scope:

- findings that require an already-compromised operator account;
- operator misconfiguration of scope, egress posture, or tool binaries;
- the cited instruments themselves — report those upstream (see
  `INSTRUMENTS.md`).

## Disclosure

There is no bounty and no response-time guarantee; reports are triaged
against the current tree as time allows. Please allow a fix or mitigation to
land before public disclosure.

## Supported versions

The `main` branch and the latest tagged release receive fixes. The `engine/`
tree is a one-way export from its source tree: a fix lands upstream and is
re-exported.
