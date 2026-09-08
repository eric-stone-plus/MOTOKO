# AGENTS.md — MOTOKO contributor rules

MOTOKO is a public research and specification repository. Committed work
must remain English, reproducible from the repository, and free of credentials,
personal machine paths, private endpoints, or host-specific infrastructure.

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
  profile paths or campaign evidence.
- Cite upstream repositories only. Do not cite operator forks.
- Preserve contributor identity. Agent-authored commits use the agent's
  GitHub-linked Git author identity rather than the human operator or only a
  co-author trailer; human-authored commits retain the human author.
