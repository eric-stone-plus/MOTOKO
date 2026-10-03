"""graphw00f — the engine behind a GraphQL endpoint, and nothing that is not the target.

An asset that already carries a GraphQL fact says "this endpoint speaks
GraphQL" and nothing more: `tech contains graphql` comes from an httpx header
guess and `fingerprint.graphql` from a nuclei template match. `graphw00f`
answers the next question — which endpoint of the host actually serves it, and
which engine sits behind it — and `R-TECH-GRAPHQL-001`'s deeper templates are
engine-specific, so that name is the fact they need.

Shapes are taken from the pinned checkout, never from a live run: no binary is
executed to produce them and no fixture here was captured over a socket.
`tools/web/graphw00f` is pinned by `core/tools_anchor/manifest.json`; at that
commit `version.py` reads `VERSION = '1.2.1'`, there is no `--json` flag, and
`main.py` prints exactly these lines:

* `print(headers)` — a Python dict *repr*, not JSON (`conf.HEADERS` is
  `{'User-Agent':'graphw00f'}`, which `-u` overrides);
* `print(draw_art())` — a ~20-line ASCII banner whose footer carries the tool's
  own version and author;
* detect mode: `[*] Checking <target>` for each wordlist endpoint, then either
  `[!] Found GraphQL at <target>` or `[x] Could not find GraphQL anywhere.`
  followed by `sys.exit(1)`;
* fingerprint mode: `[*] Attempting to fingerprint...`, then either
  `[*] Discovered GraphQL Engine: (<name>)` wrapped in `bcolors.OKGREEN`
  (`\\033[92m`) with `[!] Attack Surface Matrix: <ref>`,
  `[!] Technologies: <a, b, c>` and `[!] Homepage: <url>`, or
  `[x] Nothing was found :-(`;
* `print(bcolors.ENDC + '[*] Completed.')`.

`-o` writes CSV (`url,detected_engine,timestamp`) to a *file*, which the engine
never captures, so the stdout transcript above is the only channel this parser
reads.

Four choices are deliberate, because each would otherwise be silent:

1. no assets. The finding's url is the endpoint that answered, and ingest
   already mints a frontier asset for a finding url that is not on the graph;
   a second asset for the same endpoint would be a duplicate node;
2. `Homepage:` (the engine vendor's site) and `Attack Surface Matrix:` (a
   third-party repository) are recognised and deliberately NOT stored. Neither
   is a target: minting the `Homepage:` URL as an asset would put a vendor
   domain on the frontier, and the boot chain would attack it;
3. a fingerprint with no url anywhere is dead-lettered, not emitted. A finding
   without a url parks as `wont_test` at ingest — a row that looks like a
   decision nobody made — so the evidence stays a dead letter instead;
4. `execution_succeeded` accepts exit 1 only for the tool's own negative
   verdict. A clean "no GraphQL here" exits 1 by design, and counting that as a
   failure would burn a strike on every asset whose `tech` fact was a false
   positive; a missing scheme, a rejected url, an interactive quit and a
   traceback all exit 1 too, and all stay failures.
"""

from __future__ import annotations

import re

from . import Parser, register

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# detect mode names the endpoint that answered; fingerprint-only mode does not.
_FOUND_AT = re.compile(r"^\[!\]\s+Found GraphQL at\s+(\S+)\s*$")
_FOUND = re.compile(r"^\[!\]\s+Found GraphQL\.?\s*$")
_ENGINE = re.compile(r"^\[\*\]\s+Discovered GraphQL Engine:\s*\(([^)]+)\)\s*$")
_TECHS = re.compile(r"^\[!\]\s+Technologies:\s*(.+?)\s*$")
# Recognised, then dropped: a third-party reference and a vendor site (choice 2).
_MATRIX = re.compile(r"^\[!\]\s+Attack Surface Matrix:\s*\S+\s*$")
_HOMEPAGE = re.compile(r"^\[!\]\s+Homepage:\s*\S+\s*$")
# The tool's own answers. `Nothing was found` is a fingerprint verdict, so a run
# that reached it still detected an endpoint.
_NOT_FOUND = "[x] Could not find GraphQL anywhere."
_NO_ENGINE = "[x] Nothing was found :-("
# Runs that ended without a verdict about the target (main.py's own exits).
_ABORTED = ("URL is missing a scheme", "does not seem right.", "Quitting.")
_TRACEBACK = "Traceback (most recent call last):"
_DEAD_LEN = 300


@register
class Graphw00fParser(Parser):
    tool = "graphw00f"

    def execution_succeeded(self, exit_code, stdout, stderr, action):
        """Accept exit 1 only when the tool reached its own negative verdict.

        Called for a non-zero exit alone (0 is accepted before the parser is
        consulted), so every branch below is a failure code.
        """
        if exit_code == 0:
            return True
        if exit_code != 1:
            return False
        text = _ANSI.sub("", stdout or "")
        if not text.strip() or _TRACEBACK in (stderr or ""):
            return False
        if any(marker in text for marker in _ABORTED):
            return False
        return _NOT_FOUND in text

    def parse(self, stdout, stderr="", action=None):
        dead: list[str] = []
        found_url = ""
        detected = False
        engine = ""
        technologies: list[str] = []
        negative = False
        aborted = False
        chatter = 0
        # main.py prints the headers repr and the ASCII banner before any
        # verdict line, so the header block ends at the first `[`-prefixed
        # line. Restricting the banner rule to that block is what keeps a
        # traceback or a warning on stdout from being swallowed as art.
        body = False
        for raw in (stdout or "").splitlines():
            line = _ANSI.sub("", raw).strip()
            if not line:
                continue
            m = _FOUND_AT.match(line)
            if m:
                found_url, detected, body = m.group(1), True, True
                continue
            if _FOUND.match(line):
                detected, body = True, True
                continue
            m = _ENGINE.match(line)
            if m:
                engine, body = m.group(1), True
                continue
            m = _TECHS.match(line)
            if m:
                technologies = [t.strip() for t in m.group(1).split(",")
                                if t.strip()]
                body = True
                continue
            if _MATRIX.match(line) or _HOMEPAGE.match(line):
                body = True          # recognised, deliberately not stored
                continue
            if _NOT_FOUND in line:
                negative, body = True, True
                continue
            if _NO_ENGINE in line:
                negative, body = True, True
                continue
            if any(marker in line for marker in _ABORTED):
                aborted, body = True, True
                continue
            if line.startswith("["):
                body = True
            if not body or line.startswith(("[*]", "[x]")) \
                    or (line.startswith("{'") and line.endswith("}")) \
                    or set(line) <= set("+-|* \t"):
                chatter += 1
                continue
            dead.append(line[:_DEAD_LEN])

        url = found_url or str((action or {}).get("url") or "")
        findings: list[dict] = []
        if (detected or engine) and url.startswith(("http://", "https://")):
            extra: dict = {}
            if engine:
                extra["engine"] = engine
            if technologies:
                extra["technologies"] = technologies
            findings.append(self._finding(
                class_="fingerprint.graphql",
                title=(f"GraphQL endpoint fingerprinted as {engine}" if engine
                       else "GraphQL endpoint detected, engine not "
                            "fingerprinted"),
                url=url,
                severity="info",
                extra=extra or None,
            ))
        elif detected or engine:
            # Choice 3: the evidence exists but names no endpoint, and a
            # url-less finding would park as a decision nobody made.
            dead.append("graphw00f evidence discarded, no endpoint url to "
                        f"attach it to: engine={engine or '-'} "
                        f"detected={detected}")

        if chatter and not (detected or engine or negative or aborted):
            # Progress lines and no verdict: the output moved. Say so instead
            # of reporting a clean negative.
            dead.append("graphw00f output format not recognised — "
                        f"{chatter} banner/progress line(s), no verdict")

        for raw in (stderr or "").splitlines():
            line = raw.strip()
            if line:
                dead.append(line[:_DEAD_LEN])

        if findings:
            summary = (f"graphw00f: GraphQL endpoint {url}"
                       + (f" fingerprinted as {engine}" if engine
                          else " detected"))
        elif negative and not detected:
            summary = (f"graphw00f: GraphQL not detected on {url or 'target'}"
                       f" ({chatter} progress line(s))")
        elif aborted:
            summary = "graphw00f: run aborted before a verdict"
        else:
            summary = f"graphw00f: no output ({len(dead)} dead)"
        return self._result(summary, findings=findings, dead_letter=dead)
