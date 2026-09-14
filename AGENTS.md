# AGENTS.md — MOTOKO contributor rules

MOTOKO is a public research and specification repository. Committed work
must be reproducible from the repository and free of credentials, personal
machine paths, private endpoints, engagement evidence, or host-specific
infrastructure.

Prose — documentation, docstrings, comments, identifiers — is English. Two
narrow exceptions are functional data, not prose, and must stay in the
language they match against:

- Detection signatures that match a localized response, e.g. the WAF
  block-page titles and canary path tokens in `engine/core/opsec.py`.
  Translating them silently disables the detection.
- Prompt templates delivered to a model in the operator's working language,
  e.g. the audit/adjudication prompts in `engine/core/loop.py`. Translating
  them changes runtime behaviour.

Never encode in a comment: a vendor or model identity, an operator or
deployment hostname, a jurisdiction or network-posture detail, a real target
or engagement observation, an internal incident/round identifier, or a
reference to a document that is not in this tree. Describe the invariant the
code enforces, not the engagement that motivated it.

## Contribution rules

- Preserve the separation between the ontology and the instruments it cites.
  Instruments retain their own authority, licenses, and repositories.
- The graph in GRAPH.md is the orchestration contract. Do not replace it with
  a second informal playbook, and do not vendor LangGraph source here.
- Do not vendor instrument source trees into this repository.
- Do not relicense cited instruments. License changes, if any, apply only to
  original files in this repository.
- Do not add an operational Hermes profile (SOUL.md, skills, live config) here.
  That is a separate shell, not this ontology. Do not cite operator
  profile paths or engagement evidence, and do not carry over an internal
  review attribution (who or which model found something) - state the
  invariant the code enforces instead.
- Cite upstream repositories only. Do not cite operator forks.
- Preserve contributor identity. Agent-authored commits use the agent's
  GitHub-linked Git author identity rather than the human operator or only a
  co-author trailer; human-authored commits retain the human author.
