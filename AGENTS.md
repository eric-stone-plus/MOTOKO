# AGENTS.md — MOTOKO contributor rules

MOTOKO is a public research and specification repository. Committed work
must be reproducible from the repository and free of credentials, personal
machine paths, private endpoints, engagement evidence, or host-specific
infrastructure.

Prose — documentation, docstrings, comments, identifiers — is English. Four
narrow exceptions are functional data or citation, not prose, and must stay in
the language they carry meaning in:

- Detection signatures that match a localized response, e.g. the WAF
  block-page titles and canary path tokens in `engine/core/opsec.py`.
  Translating them silently disables the detection.
- Prompt templates delivered to a model in the operator's working language,
  e.g. the audit/adjudication prompts in `engine/core/loop.py`. Translating
  them changes runtime behaviour.
- Hand-authored rule-pack data: the `name` and `then.hypothesis` fields under
  `engine/core/rules/`. A rule's `then.hypothesis` becomes the generated
  hypothesis's `statement`, so it reaches the digest and the wave-loop bundle;
  translating it changes what a model reads, not just what a file says.
- Cited original-language titles, e.g. `《攻殻機動隊》` in `README.md` and
  `GHOST.md`, where the English title is given alongside it.

Operator-facing report scaffolding is prose and is English — e.g. the
`markdown()` header and labels in `engine/core/graph_health.py`. That method has
exactly one caller (`motoko health`, which prints it); the wave-loop consumes
`HealthIssue.to_dict()` instead, so report formatting is display-only and never
carries meaning into a prompt.

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
