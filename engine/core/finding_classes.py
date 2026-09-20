"""The finding-class registry — what the engine owes a class after confirmation.

`rulecheck` derives which classes the parsers and the `on_hit_class` wire can
produce, and 27 of the 45 it found had no rule gating on them. Every one of
those rows said the same thing ("add a chain/verification rule ONLY if a
follow-up action exists in this engine — the finding may be terminal by
design"), which is a question handed back to whoever reads the report, 27 times
per run. A report that asks the same question forever is how a gap stays open
for three waves.

So the answer is recorded once, per class, and the checker reads it:

* ``wired`` — a rule gates on the class; the follow-up exists and is in the
  corpus. Derived state, recorded so the registry stays a complete map.
* ``terminal`` — a confirmed hit IS the deliverable. Either no further probe
  would add anything (a default credential that authenticated, a CVE nuclei
  named), or the follow-up needs a channel this engine has never had — the
  post-execution side that retired the whole `access` pack, or a second identity
  for IDOR. Nothing is missing; the row was noise.
* ``follow_up_expected`` — a follow-up action EXISTS in this engine and no rule
  wires it. This is the only real coverage gap, and it stays MEDIUM.

The class SET is never hand-written: `rulecheck` derives it by AST from the
parsers and the corpus, and `audit()` refuses a produced class this table does
not know. That is the point of a registry over a report — a new `_CLASS_MAP` row
or a new `on_hit_class` fails loudly here and forces the disposition question at
the moment someone can still answer it, instead of silently joining a list
nobody reads.

Two directions of drift are checked, because only one of them is a defect:

* a produced class with no disposition — UNKNOWN, the loud one;
* a disposition for a class nothing produces any more — STALE, quiet, and the
  expected result of retiring a rule or a parser row (the `access` classes left
  this way). Stale entries are removed, not kept as history: git is the history.
"""

from __future__ import annotations

from collections.abc import Iterable

TERMINAL = "terminal"
FOLLOW_UP_EXPECTED = "follow_up_expected"
WIRED = "wired"

DISPOSITIONS = frozenset({TERMINAL, FOLLOW_UP_EXPECTED, WIRED})

_REGISTRY: dict[str, tuple[str, str]] = {
    "auth.jwt": (WIRED, "gated by R-TECH-JWT-001 (which extracts {token}) and "
                        "by R-CHAIN-JWT-ALG-NONE, which renders it into the "
                        "alg-none chain"),
    "auth.jwt_bypass": (WIRED, "declared by R-TECH-JWT-001 and matched by the "
                               "`auth.jwt` gate that R-CHAIN-JWT-ALG-NONE fires "
                               "on"),
    "exposure.actuator_env": (WIRED, "declared by R-TECH-SPRING-001 and "
                                     "followed by R-CHAIN-ACTUATOR-HEAPDUMP "
                                     "into the heapdump"),
    "exposure.git": (WIRED, "gated by R-TECH-GIT-001, which drives git-dumper"),
    "exposure.swagger": (WIRED, "gated by R-TECH-SWAGGER-001, which enumerates "
                                "the documented endpoints"),
    "fingerprint.graphql": (WIRED, "matched by R-TECH-GRAPHQL-001's `graphql` "
                                   "gate"),
    "info_disclosure.hidden_param": (WIRED, "declared by R-TECH-PARAM-001 and "
                                            "gated by R-VULN-HIDDEN-PARAM-001 — "
                                            "the {param} bridge that carries "
                                            "arjun's find into sqlmap/dalfox"),
    "lfi.basic": (WIRED, "matched by R-VULN-LFI-001's `lfi` gate, whose "
                         "declared follow-up is lfi.rce"),
    "lfi.rce": (WIRED, "declared by R-VULN-LFI-001 as the follow-up of the "
                       "`lfi` gate it also matches"),
    "misconfig.graphql_introspection": (WIRED, "declared by R-TECH-GRAPHQL-001 "
                                               "and matched by its own "
                                               "`graphql` gate"),
    "open_redirect.basic": (WIRED, "matched by R-VULN-REDIRECT-001's "
                                   "`open_redirect` gate, which chases the "
                                   "leaked token through {oob}"),
    "sqli": (WIRED, "gated by R-VULN-SQLI-VERIFY-001, which drives sqlmap"),
    "sqli.confirmed": (WIRED, "declared by R-VULN-SQLI-VERIFY-001 and matched "
                              "by its own `sqli` gate"),
    "ssrf.basic": (WIRED, "matched by R-VULN-SSRF-CHAIN-001's `ssrf` gate, "
                          "which renders the confirmed injection point via "
                          "{ssrf_url}/{ssrf_param}"),
    "ssrf.cloud_imds": (WIRED, "declared by R-VULN-SSRF-CHAIN-001 and matched "
                               "by its `ssrf` gate"),
    "xss.confirmed": (WIRED, "declared by R-VULN-XSS-VERIFY-001 and matched by "
                             "its `xss` gate; dalfox candidates reach the DOM "
                             "validator"),
    "xss.postmessage": (WIRED, "matched by R-VULN-XSS-VERIFY-001's `xss` gate"),
    "xss.reflected": (WIRED, "gated by R-VULN-XSS-VERIFY-001, which drives "
                             "dalfox"),

    # -- terminal: a confirmed hit is the deliverable ---------------------
    "api.hidden": (TERMINAL, "an undocumented endpoint that answered is the "
                             "finding; what follows depends on its auth model, "
                             "which is operator work"),
    "auth.bypass": (TERMINAL, "authentication was bypassed — the read-proof is "
                              "the deliverable (the internal doctrine non-destructive verification)"),
    "auth.default_creds": (TERMINAL, "credentials that authenticated need no "
                                     "second proof, and the internal doctrine makes any further "
                                     "credential work zero-tolerance"),
    "auth.token_leak": (TERMINAL, "spending the leaked token needs a SECOND "
                                  "identity, which is engagement configuration "
                                  "this engine has no slot for — the same "
                                  "missing piece that retired "
                                  "R-VULN-IDOR-001"),
    "cloud.imds": (TERMINAL, "an execution-environment fact about the scanning "
                             "host, not target evidence: the curl parser's "
                             "local mode deliberately mints no finding, so "
                             "R-CTX-CLOUD-001's on_hit_class cannot be "
                             "credited and its value is the recorded probe"),
    "cve": (TERMINAL, "a named CVE on a fingerprinted service is the report "
                      "line; exploitation is out of scope by doctrine"),
    "deserialization": (TERMINAL, "the OOB callback confirms it, and what "
                                  "follows is code execution inside the target "
                                  "— a channel this engine has never had"),
    "exposure.debug": (TERMINAL, "a reachable debug endpoint is the finding"),
    "fingerprint": (TERMINAL, "context for the report, not a vulnerability"),
    "idor.confirmed": (TERMINAL, "proving the object reference is cross-tenant "
                                 "needs a second identity — see auth.token_leak"),
    "info_disclosure.key": (TERMINAL, "key material found is reported and "
                                     "rotated by the operator; the engine never "
                                     "spends it (the internal doctrine)"),
    "info_disclosure.sensitive_file": (TERMINAL, "the file answered; reading "
                                                 "further is exfiltration, "
                                                 "which the internal doctrine forbids"),
    "info_disclosure.smb": (TERMINAL, "SMB enumeration lands on the lateral "
                                      "side of a line this engine does not "
                                      "cross (no execution channel)"),
    "misconfig.cors": (TERMINAL, "a reflected origin with credentials is the "
                                 "whole finding"),
    "misconfig.security_header": (TERMINAL, "absence of a header needs no "
                                            "confirmation step"),
    "misconfig.tls": (TERMINAL, "testssl-shaped facts are terminal by nature"),
    "other": (TERMINAL, "nuclei's fall-through label: it exists so an unmapped "
                         "template is visible, not so a rule can gate on it. A "
                         "class here is a signal to extend _CLASS_MAP"),
    "path_traversal": (TERMINAL, "CWE-22 from the strix mapper; the traversal "
                                  "itself is the finding and the LFI chain "
                                  "already covers the follow-up worth doing"),
    "rce": (TERMINAL, "the OOB callback is the proof; running anything further "
                      "inside the target is forbidden (the internal doctrine, no persistent damage)"),
    "secret.leak": (TERMINAL, "the end of the heapdump chain — the secret is "
                              "reported, never used"),
    "smuggling.h2": (TERMINAL, "an accepted h2c upgrade is the precondition "
                               "finding; actually tunnelling through it is "
                               "operator-driven"),
    "ssti.suspected": (TERMINAL, "the OOB callback confirms template execution, "
                                 "which is where this engine stops"),
    "vuln.cve_reported": (TERMINAL, "strix's CVE line, same reasoning as "
                                    "`cve`: a named CVE against a "
                                    "fingerprinted service IS the report line"),
    "vuln.strix_confirmed": (TERMINAL, "an agent-confirmed vuln arrives already "
                                       "verified; re-probing it doubles the "
                                       "noise for no new fact"),

    # -- follow_up_expected: the action exists, the rule does not ---------
    "exposure.backup": (FOLLOW_UP_EXPECTED,
                        "trufflehog3 is installed and parsed, and a retrieved "
                        "backup/archive is exactly what it reads — no rule "
                        "hands one to it"),
    "info_disclosure.schema": (FOLLOW_UP_EXPECTED,
                               "a disclosed schema names parameters that arjun "
                               "and kr can then probe; the {param} bridge "
                               "already carries the result into sqlmap/dalfox"),
    "misconfig.api_docs": (FOLLOW_UP_EXPECTED,
                           "the strix-mapper label for the same surface "
                           "exposure.swagger covers, so R-TECH-SWAGGER-001's "
                           "gate could consume it with one added value"),
}


def disposition(cls: str) -> tuple[str, str] | None:
    """``(disposition, why)`` for one class, or None when unregistered."""
    return _REGISTRY.get(str(cls or ""))


def why(cls: str) -> str:
    """The recorded reason, for a report row. Empty when unregistered."""
    entry = _REGISTRY.get(str(cls or ""))
    return entry[1] if entry else ""


def is_terminal(cls: str) -> bool:
    return (_REGISTRY.get(str(cls or "")) or ("",))[0] == TERMINAL


def expects_follow_up(cls: str) -> bool:
    return (_REGISTRY.get(str(cls or "")) or ("",))[0] == FOLLOW_UP_EXPECTED


def registered() -> dict[str, tuple[str, str]]:
    """A copy of the table, for reports and for the drift audit."""
    return dict(_REGISTRY)


def audit(produced: Iterable[str], gated: Iterable[str] = ()) -> dict[str, list[str]]:
    """Compare the derived class set against the registry.

    ``produced`` is rulecheck's derived set (parsers plus the on_hit_class
    wire); ``gated`` is the subset some rule actually consumes. Returns
    ``unknown`` / ``stale`` / ``mismatch``:

    * unknown — produced and unregistered. The loud one: whoever added the
      parser row or the on_hit_class owes a disposition, and until they give
      one the checker keeps asking in the report.
    * stale — registered but nothing produces it. The expected result of
      retiring a rule or dropping a parser row; delete the entry (git keeps the
      reason).
    * mismatch — registered ``wired`` but no rule gates on it, or gated but not
      registered ``wired``. This is the registry drifting out of sync with the
      corpus, which is the failure mode a hand-maintained map has and a derived
      one must not.
    """
    produced_set = {str(c) for c in produced if c}
    gated_set = {str(c) for c in gated if c}
    unknown = sorted(produced_set - set(_REGISTRY))
    stale = sorted(set(_REGISTRY) - produced_set)
    mismatch = []
    for cls in sorted(produced_set & set(_REGISTRY)):
        kind = _REGISTRY[cls][0]
        if cls in gated_set and kind != WIRED:
            mismatch.append(f"{cls}: a rule gates on it but the registry says "
                            f"{kind}")
        elif cls not in gated_set and kind == WIRED:
            mismatch.append(f"{cls}: registered wired but no rule gates on it")
    return {"unknown": unknown, "stale": stale, "mismatch": mismatch}
