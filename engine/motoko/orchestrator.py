"""Orchestrator — the single-writer six-beat main loop.

SYNC -> VALIDATE -> EXPAND -> PRIORITIZE -> ACT -> REFLECT, replacing the
linear 5-layer pipeline. This module owns the ONLY writer connection; the
tool executor and the LLM reflector are injected so the loop is unit-testable
without live targets.

Invariants (grok review):

* One writer process. Hermes supervises via digest/query/events (read-only).
* scope guard runs before EVERY action; a block is recorded, never skipped.
* Deterministic validators promote findings; the reflector (LLM) may only
  propose hypotheses / adjust priorities, never drive a finding transition.
* Every transition writes an event; crash recovery = replay events.
"""

from __future__ import annotations

import hashlib
import http.client
import inspect
import os
import re
import socket
import ssl
from collections import deque
from pathlib import Path
from urllib.parse import urlparse

from . import cmd, db, digest, opsec, util, writer_views
from . import asset_link
from .dedup import compute_dedup_key
from .hypothesis_engine import HypothesisEngine
from .opsec import CooldownBoard
from .parsers import parse_tool
from .scope import ScopeDecision, ScopeGuard
from .verification import Verdict, dom, oob, pick_validator, replay

# R5 H1: a rule-missed asset keeps its frontier open (facts may arrive
# later); after this many consecutive empty expansions it is retired.
_MAX_EMPTY_EXPANSIONS = 3

# Production lesson: cap on hypotheses minted per EXPAND pass. A crawl that dumps
# thousands of frontier assets must not drown the ACT queue in one cycle.
_EXPAND_BUDGET = 30

# R6-4: ACT batch size (executed sequentially, one observation at a time —
# the per-registrable-domain concurrency discipline is unchanged).
# R7-6: raised to 4 so the reserved-category phase can honor scan + three
# work categories in one batch.
_ACT_K = 4

# R6-4: stop minting fresh hypotheses for a rule once this many of its
# hypotheses sit proposed (the backlog cap that EXPAND_BUDGET alone could
# not provide — one production wave carried 638 bootstrap hyps).
_MAX_PROPOSED_PER_RULE = 40


def _accepts_failure_lines(reflector) -> bool:
    """R3: does the injected reflector take ``failure_lines=``?

    Probed once at construction. Introspection deliberately happens here and
    not as a ``try: f(..., failure_lines=x) except TypeError: f(...)`` at call
    time — a TypeError raised *inside* a reflector would be misread as "old
    signature" and the reflector would be invoked twice, doubling the LLM
    proposals for that beat.
    """
    if reflector is None:
        return False
    try:
        sig = inspect.signature(reflector)
    except (TypeError, ValueError):
        return False                    # builtin/C callable: assume the old shape
    params = sig.parameters
    if "failure_lines" in params:
        return True
    # a reflector written as (*args, **kwargs) can take it too
    return any(p.kind is p.VAR_KEYWORD for p in params.values())


def _command_fingerprint(tool: str, target: tuple[str, str], argv: list[str]) -> tuple:
    """G9: identity of a concrete ACT command (tool, target, argv digest).

    Keyed on the STRUCTURED target, not the rendered string: the same
    command with different targets (different {url}/{host} placeholder
    values) must not collide, while cosmetic argv re-rendering of the same
    command does.
    """
    return (tool, target[0], target[1],
            hashlib.sha256(" ".join(argv).encode("utf-8", "replace")).hexdigest())


def default_fetcher(url: str, bind_ip: str | None = None):
    """Real HTTP IO for the replay validator (stdlib only), PINNED to the
    address the scope guard actually cleared (F03 / R3 H3).

    Connects a fresh TCP stream to ``bind_ip`` while presenting the original
    hostname in the ``Host`` header and the TLS SNI. Re-resolving the hostname
    here (``urlopen`` did exactly that) reopened the DNS-rebinding window the
    guard had just closed: the guard checks an in-scope A record, the connect
    lands on an out-of-scope one. Without a bind_ip there is no cleared
    address to talk to, so no request is sent (returns None, which the
    validator maps to ``inconclusive`` — never falsification, F26).

    Any transport error returns None as well; tests inject a stub instead.
    """
    if not bind_ip:
        return None
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    port = u.port or (443 if u.scheme == "https" else 80)
    target = u.path or "/"
    if u.query:
        target += f"?{u.query}"
    host_header = u.hostname if u.port is None else f"{u.hostname}:{port}"
    try:
        sock = socket.create_connection((bind_ip, port), timeout=15)
        try:
            if u.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(
                    sock, server_hostname=u.hostname)
            sock.sendall(
                (f"GET {target} HTTP/1.1\r\n"
                 f"Host: {host_header}\r\n"
                 f"User-Agent: {os.environ.get('MOTOKO_UA', opsec.DEFAULT_UA)}\r\n"
                 f"Connection: close\r\n\r\n").encode("ascii", "replace"))
            resp = http.client.HTTPResponse(sock)
            resp.begin()
            body = resp.read(65536).decode("utf-8", "replace")
            return replay.Response(status=resp.status, body=body,
                                   headers=dict(resp.headers or {}))
        finally:
            try:
                sock.close()
            except OSError:
                pass
    except (OSError, ValueError, http.client.HTTPException):
        return None


class Orchestrator:
    def __init__(self, engagement_id: str, *, root=None,
                 rules_dir=None, executor=None, reflector=None,
                 resolver=None, fetcher=None, browser=None, canary=None,
                 intensity: str | None = None):
        self.engagement_id = engagement_id
        self.root = root or db.default_root()
        self.edir = db.engagement_dir(self.root, engagement_id)
        self.writer = db.Database(self.edir / "graph.db")

        rules_dir = rules_dir or (Path(__file__).resolve().parents[1] / "rules")
        self.rules_dir = Path(rules_dir)
        self.engine = HypothesisEngine(self.rules_dir)
        self.executor = executor or self._default_executor
        self.reflector = reflector          # LLM reflector (injected; optional)

        # Injected validation IO (F11): tests pass stubs. ``fetcher`` has a
        # real stdlib default; the browser and the canary manager are
        # deployment backends — while they are absent the DOM/OOB validators
        # return inconclusive instead of guessing (F26).
        self.fetcher = fetcher or default_fetcher
        self.browser = browser
        self.canary = canary

        scope = self.writer.get_scope(engagement_id) or {}
        self.guard = ScopeGuard(
            scope.get("in_scope", []),
            scope.get("out_of_scope", []),
            resolver=resolver,
        )
        # The reflector never sees the writer (F04).
        self.propose_view = writer_views.ProposeOnlyView(self.writer, engagement_id)
        self.cycle = 0
        self.artifacts = self.edir / "obs"

        # R3: the failure digest is computed by the recovery pass (which owns
        # the writer) and handed to the reflector read-only. Probing the
        # signature once here keeps the injected-reflector contract backward
        # compatible: a 2-arg reflector still works and simply gets no failure
        # context. Introspection is NOT done with try/except TypeError at call
        # time — a TypeError raised *inside* a reflector would be misattributed
        # as "unsupported signature" and silently re-invoke it.
        self._failure_digest = None
        self._reflector_takes_failures = _accepts_failure_lines(reflector)

        # OPSEC (2026-09-13 P0): per-origin cooldowns + canary accounting.
        # A WAF fact landing on an asset (httpx/nuclei parser sensor) cools
        # the whole origin down; ACT skips cooled origins and planted
        # canary paths with events instead of hammering the wall.
        self._cooldowns = CooldownBoard()
        self._waf_noted: set[tuple[str, str]] = set()
        # intensity=stealth selects a rule's stricter cmd_<intensity>
        # variant when present (was a dead init parameter until now). The
        # explicit argument wins; otherwise the engagement's scope row.
        self.intensity = intensity or str(scope.get("intensity") or "normal")

    # -- main loop -----------------------------------------------------
    def run(self, max_cycles: int = 20, max_depth: int = 3) -> dict:
        try:
            for _ in range(max_cycles):
                self.cycle += 1
                self._sync()
                self._validate()
                self._recover_failures()
                self._expand()
                batch = self._prioritize()
                if not batch:
                    self._reflect_if_needed(force=True)
                    if not self.writer.query_entities(
                            kind="hypothesis",
                            engagement_id=self.engagement_id):
                        break
                    continue
                self._act(batch)
                if self.cycle % 5 == 0:
                    self._reflect_if_needed(force=True)
                self.writer.commit()
        finally:
            # P-031: whatever happens inside the loop (exception, interrupt,
            # operator TERM), no scan this run spawned may outlive it.
            reap = getattr(self.executor, "reap", None)
            if callable(reap):
                reap()
        self._checkpoint()
        # Graph self-perception: after every run, sweep for broken links.
        # Issues land as graph_health events and feed the wave-loop bundle.
        try:
            from .graph_health import check_health
            report = check_health(self.engagement_id, root=self.root,
                                  rules_dir=self.rules_dir)
            if report.issues:
                self.writer.append_event(
                    "graph_health", self.engagement_id,
                    {"issues": [i.to_dict() for i in report.issues]})
        except Exception:
            pass                     # a health sweep must never fail the run
        return self._summary()

    # -- six beats -----------------------------------------------------
    def _sync(self) -> None:
        """Normalize UNPROCESSED observations into assets + findings (F12).

        Only ``processed_at IS NULL`` rows are ingested, and each row is
        marked after handling, so a cycle no longer replays the whole
        observation history and re-builds the same assets/findings.
        """
        for o in self.writer.unprocessed_observations(self.engagement_id):
            if o.get("raw_path"):
                self._ingest_raw(
                    o["id"], o["tool"], o["raw_path"],
                    context={"url": o.get("url"), "host": o.get("host"),
                             "action_id": o.get("action_id")},
                )
            self.writer.mark_observation_processed(o["id"])

    def _ingest_raw(self, obs_id: str, tool: str, raw_path: str,
                    context: dict | None = None) -> None:
        try:
            # HIGH-10 (round-3 audit): tool output is NOT guaranteed UTF-8 —
            # a dirty byte used to raise UnicodeDecodeError straight through
            # (only OSError was caught) and permanently killed the run.
            raw = Path(raw_path).read_text(errors="replace")
        except OSError as e:
            # Nothing to parse — record why and let the observation be marked
            # processed instead of retrying it forever.
            self.writer.append_event("observation_dead_letter", obs_id,
                                     {"tool": tool, "raw_path": raw_path,
                                      "error": str(e)})
            return
        # F13: hand the observation's action/url/host context to the parser, so
        # a tool that prints no URL (sqlmap) still yields a targeted finding.
        action = {k: v for k, v in (context or {}).items() if v}
        # R6-1: the sibling .err carries the tool's stderr. Feed it to the
        # parser instead of a hardcoded empty string — wave-audit HIGH-3:
        # error detail was invisible to the loop, making failures undiagnosable.
        err_text = ""
        err_path = Path(str(raw_path).replace(".out", ".err"))
        try:
            err_text = err_path.read_text(errors="replace")
        except OSError:
            err_text = ""
        try:
            parsed = parse_tool(tool, raw, err_text, action)
        except Exception as e:
            # R3 H4: a parser bug must not kill run(). Record the dead letter
            # and let the observation be marked processed (no infinite retry).
            self.writer.append_event(
                "observation_dead_letter", obs_id,
                {"tool": tool, "raw_path": raw_path,
                 "error": f"parse_tool raised: {e!r}"})
            return
        # R6-1: persist the parse outcome — summary goes on the observation row
        # and dead letters become events (never silently dropped, per the
        # parser contract).
        self.writer.update_observation_summary(obs_id, parsed.summary)
        if parsed.dead_letter:
            self.writer.append_event(
                "observation_dead_letter", obs_id,
                {"tool": tool, "raw_path": raw_path,
                 "dead_letter": parsed.dead_letter[:50]})
        for a in parsed.assets:
            a.setdefault("engagement_id", self.engagement_id)
            aid = self._merge_asset(a)
            if a.get("waf"):
                self._note_waf(aid, str(a["waf"]),
                               source=str(a.get("source") or parsed.tool))
        # R7-3: enum tools stamp the SOURCE asset too, so the parent-domain
        # gate closes even when the tool output doesn't contain the apex
        # host (grok adjudication: keep self-stamp, ADD source stamp).
        if parsed.assets and context and context.get("action_id"):
            hyp_id = self.writer.tool_run_hypothesis(context["action_id"])
            if hyp_id:
                hyp = self.writer.get_entity(hyp_id)
                src_aid = (hyp or {}).get("asset_id")
                if src_aid:
                    src = self.writer.get_entity(src_aid)
                    if src and src.get("kind") == "asset":
                        val = str(src.get("value", ""))
                        src_host = val.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] \
                            if "://" in val else val
                        if src_host and src.get("enumerated_host") != src_host:
                            src["enumerated_host"] = src_host
                            self.writer.upsert_entity(src)
        for f in parsed.findings:
            f.setdefault("engagement_id", self.engagement_id)
            self._ingest_finding(f)
            if f.get("waf") and f.get("asset_id"):
                self._note_waf(str(f["asset_id"]), str(f["waf"]),
                               source=str(f.get("detector") or parsed.tool))
        # R7-5: nmap services land in the services table, keyed to the target
        # asset, so _fact_view can surface them (SMB chain input).
        if parsed.services:
            aid = None
            if context and context.get("url"):
                aid = self._asset_id_for_url(str(context["url"]))
            if aid is None and context and context.get("host"):
                for e in self.writer.query_entities(kind="asset",
                                                    engagement_id=self.engagement_id):
                    val = str(e.get("value", ""))
                    h = val.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] \
                        if "://" in val else val
                    if h == context["host"]:
                        aid = e["id"]
                        break
            if aid:
                for s in parsed.services:
                    s.setdefault("id", util.new_id("service"))
                    s["asset_id"] = aid
                    self.writer.add_service(s)

    def _merge_asset(self, a: dict) -> str:
        """Dedup assets by (type, value) and merge new facts into the row.

        Production wave bug: httpx re-reporting the same URL minted a fresh asset
        every SYNC, each of which re-fired the bootstrap rule — the loop
        re-probed the same hosts forever and starved every other rule.
        a re-seen asset now merges (union of tech, new keys win) and only
        re-opens ``frontier`` when the facts actually changed, so a stable
        host settles instead of self-locking.
        """
        a.setdefault("id", util.new_id("asset"))
        a.setdefault("engagement_id", self.engagement_id)
        for e in self.writer.query_entities(kind="asset",
                                            engagement_id=self.engagement_id):
            if e.get("type") != a.get("type") or e.get("value") != a.get("value"):
                continue
            merged = dict(e)
            changed = False
            for k, v in a.items():
                if k in ("id", "created_at"):
                    continue
                if k == "tech" and e.get("tech") and v:
                    union = sorted(set(e["tech"]) | set(v))
                    if union != e.get("tech"):
                        merged["tech"] = union
                        changed = True
                elif e.get(k) != v and v not in (None, "", []):
                    merged[k] = v
                    changed = True
            if changed and not e.get("frontier"):
                merged["frontier"] = True      # new facts -> re-evaluate once
            self.writer.upsert_entity(merged)
            return e["id"]
        self.writer.upsert_entity(a)
        return a["id"]

    def _note_waf(self, asset_id: str, vendor: str, *, source: str) -> None:
        """React to a WAF fact landing on an asset.

        The ``waf`` vendor is already merged onto the asset row by
        ``_merge_asset`` (that's what activates R-CTX-WAF-001 in _fact_view);
        this is the reaction half: cool the whole origin down and log one
        ``waf_detected`` event per (asset, vendor). Re-observations extend
        the cooldown silently instead of spamming the event log.
        """
        ent = self.writer.get_entity(asset_id)
        host = ""
        if ent:
            val = str(ent.get("value", ""))
            host = (val.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
                    if "://" in val else val)
        self._cooldowns.trigger(host, f"waf:{vendor}")
        key = (asset_id, vendor)
        if key in self._waf_noted:
            return
        self._waf_noted.add(key)
        self.writer.append_event("waf_detected", asset_id, {
            "vendor": vendor, "host": host, "source": source,
            "origin": CooldownBoard.normalize(host),
            "cooldown_s": self._cooldowns.cooldown_s,
        })

    @staticmethod
    def _origin_of(kind: str, value: str) -> str:
        """Cooldown key for a structured target (host, port-stripped)."""
        if kind == "url":
            host = (value.split("://", 1)[1].split("/", 1)[0]
                    if "://" in value else value)
            return CooldownBoard.normalize(host)
        return CooldownBoard.normalize(value)

    def _robots_canary_hit(self, origin: str, url: str) -> str | None:
        """robots.txt Disallow prefix match for this origin's known traps.

        R-CTX-ROBOTS-001 stamps ``canary_paths`` on the base asset; a
        target URL whose path falls under one of them is a planted tripwire
        (robots semantics are prefix-based, so the comparison is too).
        """
        path = urlparse(url).path or "/"
        for e in self.writer.query_entities(kind="asset",
                                            engagement_id=self.engagement_id):
            if e.get("robots_host") != origin:
                continue
            for p in e.get("canary_paths") or []:
                p = str(p)
                if p and p != "/" and (path == p or path.startswith(p)):
                    return p
        return None

    def _ingest_finding(self, f: dict) -> str:
        """Create one finding, or link it to the surviving duplicate.

        F15: a dedup hit creates NO new entity — it records a ``duplicate_of``
        edge plus a counter on the primary and returns the primary's id.
        State moves only through ``advance_and_persist`` (F06).

        R5 M7: a parser finding carries no asset_id; the per-asset class
        rules read facts["class"], so find the asset by URL/host first.
        """
        if not f.get("asset_id") and f.get("url"):
            aid = self._asset_id_for_url(str(f["url"]))
            if aid:
                f["asset_id"] = aid
        key = f.get("dedup_key") or compute_dedup_key(f)
        f["dedup_key"] = key
        for e in self.writer.query_entities(kind="finding",
                                            engagement_id=self.engagement_id):
            if e.get("dedup_key") == key:
                return self._record_duplicate(f, e)
        f.setdefault("state", "candidate")
        f["signals"] = list(f.get("signals") or [])
        self.writer.upsert_entity(f)      # always born 'candidate'
        ok, reason = self.writer.advance_and_persist(f["id"], "dedup_pass",
                                                     actor="validator")
        if not ok:
            self.writer.append_event("validation_error", f["id"],
                                     {"event": "dedup_pass", "reason": reason})
        return f["id"]

    def _asset_id_for_url(self, url: str) -> str | None:
        """R5 M7: find the asset a finding URL belongs to (exact value or
        host match), so the finding is visible to per-asset rules.

        M1-asset-link: delegates to the shared ``asset_link`` module so the
        CLI strix ingest and this path can never drift apart.
        """
        return asset_link.asset_id_for_url(self.writer, url,
                                           engagement_id=self.engagement_id)

    def _record_duplicate(self, f: dict, primary: dict) -> str:
        """F15: duplicate occurrence = edge + counter, never a new row."""
        self.writer.add_edge(f["id"], primary["id"], "duplicate_of",
                             engagement_id=self.engagement_id,
                             data={"dedup_key": f.get("dedup_key"),
                                   "detector": f.get("detector")})
        self.writer.bump_duplicate_count(primary["id"])
        return primary["id"]

    def _validate(self) -> None:
        """Run the deterministic validators — F11: this is where validation
        actually happens.

        Triaged findings are advanced by their class-specific validator;
        already-``reproduced`` findings are re-checked so hard evidence (OOB /
        DOM / credential) can promote them (F10's reproduced rows). Every
        verdict drives ``advance_and_persist`` — the only door to a state
        change.
        """
        findings = (
            self.writer.query_entities(kind="finding", engagement_id=self.engagement_id,
                                       state="triaged")
            + self.writer.query_entities(kind="finding", engagement_id=self.engagement_id,
                                         state="reproduced")
        )
        for f in findings[:5]:
            name = pick_validator(f)
            try:
                verdict = self._run_validator(name, f)
            except Exception as e:      # a validator bug must not kill the run
                self.writer.append_event("validation_error", f["id"],
                                         {"validator": name, "error": str(e)})
                continue
            if verdict is None:
                continue
            ok, reason = self.writer.advance_and_persist(
                f["id"], verdict.event, actor="validator", verdict=verdict)
            if not ok:
                # F30: an illegal event is recorded and skipped, never allowed
                # to blow up the main loop.
                self.writer.append_event("validation_error", f["id"],
                                         {"event": verdict.event, "reason": reason})

    def _run_validator(self, name: str, finding: dict):
        """Validator entry point.

        F02: the scope guard runs FIRST and unconditionally — ``finding.url``
        is attacker-influenced tool output, and nothing may leave the box
        before it is checked. A blocked target records a ``scope_blocked``
        event and returns an ``inconclusive`` verdict, which (F26/F27) is a
        no-op on the state machine: it neither falsifies nor promotes.

        F11: dispatch to the validator picked by class, over injected IO.
        """
        url = finding.get("url") or ""
        decision = (self.guard.check_url(url) if url
                    else ScopeDecision(False, "finding has no url"))
        if not decision.allowed:
            self.writer.append_event("scope_blocked", finding.get("id"), {
                "phase": "validate", "url": url, "reason": decision.reason})
            return Verdict("inconclusive",
                           f"scope guard blocked validation: {decision.reason}")
        try:
            if name == "replay":
                # R3 H3: connect to the address the guard actually cleared —
                # re-resolving at request time reopens the DNS rebinding
                # window. A decision without a bind_ip never produced an
                # address to pin, so no request may go out (inconclusive).
                if "bind_ip" not in decision.detail:
                    return Verdict(
                        "inconclusive",
                        f"scope guard cleared {url!r} without a bind_ip; "
                        f"refusing to connect unpinned (DNS rebinding window)")
                return replay.replay_verdict(finding, self.fetcher,
                                             bind_ip=decision.detail.get("bind_ip"))
            if name == "dom":
                if self.browser is None:
                    return Verdict("inconclusive",
                                   "no browser backend is wired for the DOM validator")
                return dom.dom_verdict(finding, self.browser)
            if name == "oob":
                if self.canary is None:
                    return Verdict("inconclusive",
                                   "no canary backend is wired for the OOB validator")
                return oob.oob_verdict(finding, self.canary.issue,
                                       self.canary.trigger, self.canary.poll)
        except Exception as e:
            # F26: anything the IO layer throws is inconclusive.
            return Verdict("inconclusive", f"validator {name!r} IO failure: {e}")
        return Verdict("inconclusive", f"no validator implementation for {name!r}")

    def _expand(self) -> None:
        """Hypothesis engine fires on frontier nodes.

        R5 H1: a rule miss no longer extinguishes the frontier outright —
        the asset stays open so facts that arrive later (a tech fingerprint
        from the bootstrap httpx run, a service, a finding class) can still
        fire rules on it. To keep a node that never matches from
        re-expanding forever, the frontier is dropped after
        ``_MAX_EMPTY_EXPANSIONS`` consecutive misses.
        """
        assets = self.writer.query_entities(kind="asset", engagement_id=self.engagement_id)
        # F16: one hypothesis per (rule, asset). A frontier re-open after a
        # fact merge must not mint duplicate hypotheses — wave3 showed
        # bootstrap duplicates starving the ACT queue (nuclei never ran).
        seen = {(h.get("rule_id"), h.get("asset_id"))
                for h in self.writer.query_entities(kind="hypothesis",
                                                    engagement_id=self.engagement_id)
                if (h.get("state") or "proposed") not in ("error", "timeout", "failed")}
        # R6-4: per-rule proposed backlog cap — once a rule has 40+ proposed
        # hypotheses waiting, stop minting more for it (bootstrap carried 638
        # in one production wave and starved every other category).
        proposed_by_rule: dict[str, int] = {}
        for h in self.writer.query_entities(kind="hypothesis",
                                            engagement_id=self.engagement_id,
                                            state="proposed"):
            rid = h.get("rule_id") or ""
            proposed_by_rule[rid] = proposed_by_rule.get(rid, 0) + 1
        # Production lesson: one crawl dumped 1876 assets, each minting a
        # bootstrap hypothesis — the ACT queue drowned. Cap hypotheses minted
        # per cycle; un-expanded assets keep frontier=True and resume next
        # cycle.
        budget = _EXPAND_BUDGET
        for a in assets:
            if budget <= 0:
                break
            if not a.get("frontier", True):
                continue
            facts = self._fact_view(a, assets)
            hyps = self.engine.generate(facts)
            a["expansion_count"] = a.get("expansion_count", 0) + 1
            if hyps:
                minted_any = False
                dup_skips = 0
                cap_skips = 0
                for hyp in hyps:
                    hyp.setdefault("engagement_id", self.engagement_id)
                    # bind the subject asset's URL so scope guard + action
                    # rendering have a concrete target.
                    hyp.setdefault("asset_id", a["id"])
                    key = (hyp.get("rule_id"), a["id"])
                    if key in seen:
                        dup_skips += 1
                        continue
                    seen.add(key)
                    rid = hyp.get("rule_id") or ""
                    # P0-2 (round-3 audit): a (rule, asset) pair that
                    # already failed out three times stops re-minting.
                    # Counted as a dup so an all-skipped pass still retires
                    # the frontier instead of burning the expand budget.
                    pair_attempts = (a.get("attempts_by_rule") or {}).get(rid)
                    if isinstance(pair_attempts, int) and pair_attempts >= 3:
                        dup_skips += 1
                        continue
                    if proposed_by_rule.get(rid, 0) >= _MAX_PROPOSED_PER_RULE:
                        # R6-4: backlog cap — keep the frontier open and mint
                        # later, once ACT drains the queue.
                        cap_skips += 1
                        continue
                    proposed_by_rule[rid] = proposed_by_rule.get(rid, 0) + 1
                    minted_any = True
                    if a.get("value") and a["value"].startswith(("http://", "https://")):
                        hyp.setdefault("url", a["value"])
                        # host for {host} placeholders (subfinder/nmap/gau…);
                        # port is kept separately so {host}:{port} targets stay
                        # correct (https://h:8443 must scan 8443, not 443).
                        hostport = a["value"].split("://", 1)[1].split("/", 1)[0]
                        hyp.setdefault("host", hostport.split(":", 1)[0])
                        # P-024: SUB/GAU enumerate the REGISTRABLE domain, not
                        # the subdomain itself (subfinder -d job.shop.invalid
                        # finds nothing; -d shop.invalid found 145 subs).
                        hyp.setdefault("domain",
                                       util.registrable_domain(hostport.split(":", 1)[0]))
                        if ":" in hostport:
                            hyp.setdefault("port", hostport.split(":", 1)[1])
                    elif a.get("value") and a.get("type") == "host":
                        hyp.setdefault("host", a["value"])
                        hyp.setdefault("domain", util.registrable_domain(a["value"]))
                        # P0-3 (round-2 audit): host assets carry no url, so
                        # any rule cmd with {url} rendered a LITERAL "{url}"
                        # into argv (unknown placeholders stay verbatim) and
                        # the tool attacked the string "{url}". Mint the
                        # canonical https URL so every placeholder resolves.
                        hyp.setdefault("url", f"https://{a['value']}")
                    self.writer.upsert_entity(hyp)
                budget -= 1
                if minted_any:
                    a["frontier"] = False
                elif cap_skips and not dup_skips:
                    a["frontier"] = True     # queue drain will unblock the cap
                elif dup_skips and not cap_skips:
                    # R7-7 (grok A-1): an all-duplicate pass is an EMPTY
                    # expansion. A CDN status flip (200→405) made every rule
                    # fire on rules already seen — that must retire like a
                    # miss, not burn the expand budget forever.
                    if a["expansion_count"] >= _MAX_EMPTY_EXPANSIONS:
                        a["frontier"] = False
                    else:
                        a["frontier"] = True
                else:
                    a["frontier"] = True     # mixed: keep waiting
            elif a["expansion_count"] >= _MAX_EMPTY_EXPANSIONS:
                a["frontier"] = False
            else:
                a["frontier"] = True     # keep waiting for facts
            self.writer.upsert_entity(a)

    def _fact_view(self, asset: dict, assets: list[dict] | None = None) -> dict:
        facts: dict = {"url": asset.get("value", ""), "ip": asset.get("ip", "")}
        facts["type"] = asset.get("type", "")
        if asset.get("status_code") is not None:
            facts["status"] = asset.get("status_code")
        # R6-5: host_crawled is True when ANY asset on this host was already
        # crawled (katana parser stamps crawled_host). CRAWL rules gate on it
        # to fire once per host instead of once per URL.
        host = asset.get("value", "").split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] \
            if "://" in asset.get("value", "") else ""
        facts["host_crawled"] = bool(
            host and assets and any(
                e.get("crawled_host") == host for e in assets))
        # enum tools (subfinder/gau/amass) stamp enumerated_host on their
        # output; a host already enumerated does not re-fire the enum rules.
        facts["host_enumerated"] = bool(
            host and assets and any(
                e.get("enumerated_host") == host for e in assets))
        # P-025: domain-level enum gate — 55 hosts under one registrable
        # domain must not mint 55 subfinder runs for the same domain.
        domain = util.registrable_domain(host)
        facts["domain_enumerated"] = bool(
            domain and assets and any(
                e.get("enumerated_domain") == domain for e in assets))
        # R7-4: nmap stamps nmap_host on its output; one scan per host.
        facts["host_nmapped"] = bool(
            host and assets and any(
                e.get("nmap_host") == host for e in assets))
        # OPSEC (2026-09-13): the robots probe stamps robots_host; fuzz and
        # crawl rules gate on it so a target's Disallow traps are known
        # before the first burst goes out.
        facts["robots_checked"] = bool(
            host and assets and any(
                e.get("robots_host") == host for e in assets))
        tech = asset.get("tech") or []
        facts["tech"] = tech
        facts["waf"] = bool(asset.get("waf"))
        facts["cloud"] = bool(asset.get("cloud"))
        facts["http2"] = bool(asset.get("http2"))
        facts["has_param"] = bool(asset.get("has_param"))
        # services found on this asset (list + legacy single for old rules)
        svcs = [s.get("service_name", "") for s in self.writer.get_services(asset["id"]) if s.get("service_name")]
        facts["services"] = svcs
        facts["service"] = svcs[0] if svcs else ""
        # current access level (if any access node points here)
        for acc in self.writer.query_entities(kind="access", engagement_id=self.engagement_id):
            if acc.get("asset_id") == asset["id"] and acc.get("valid", True):
                facts["level"] = acc.get("level")
                facts["principal"] = acc.get("principal")
        # surface a finding class onto facts for vuln rules
        for f in self.writer.query_entities(kind="finding", engagement_id=self.engagement_id):
            if f.get("asset_id") == asset["id"]:
                facts["class"] = f.get("class")
                # R6-2: expose the hidden param name so the R7 bridge rule can
                # render {param} into sqlmap/dalfox commands.
                if f.get("param"):
                    facts.setdefault("param", f.get("param"))
        return facts

    def _prioritize(self) -> list[dict]:
        """Top hypotheses for the ACT beat.

        R5 H1/M11: a hypothesis without actions (e.g. an LLM proposal) is
        kept on the graph but never becomes work — only actionable
        hypotheses enter ACT.

        R6-4: category quotas. With static priorities + K=1, the lowest-ranked
        category (SCAN=53.33) is mathematically unreachable behind a backlog
        of higher-ranked BOOT/PARAM hypotheses — one production wave ran 30
        cycles with nuclei ×0. The batch now reserves one slot per actionable
        category before filling the rest by priority.
        """
        hyps = self.writer.query_entities(kind="hypothesis", engagement_id=self.engagement_id, state="proposed")
        hyps = [h for h in hyps if h.get("actions")]
        hyps.sort(key=lambda h: h.get("priority", 0) or 0, reverse=True)

        batch: list[dict] = []
        seen_ids: set[str] = set()
        # one reserved slot per actionable category, priority order within it.
        # R7-6: scan sits before context so nuclei can never be flooded out
        # by the context rules again (R-BOOT-SCAN-001 category is "scan").
        for cat in ("vuln", "scan", "context", "tech", "injection", "access", "chain"):
            for h in hyps:
                if h["id"] in seen_ids:
                    continue
                if h.get("category") == cat:
                    batch.append(h)
                    seen_ids.add(h["id"])
                    break
        # fill remaining slots by pure priority
        for h in hyps:
            if h["id"] in seen_ids:
                continue
            batch.append(h)
            seen_ids.add(h["id"])
            if len(batch) >= _ACT_K:
                break
        return batch[:_ACT_K]

    def _act(self, batch: list[dict]) -> None:
        # OPSEC state is lazily built: legacy tests construct bare
        # Orchestrators via __new__ and call _act directly.
        if getattr(self, "_cooldowns", None) is None:
            self._cooldowns = CooldownBoard()
            self._waf_noted = set()
        # G9: per-cycle dedup of identical commands. A cold-start graph
        # carries many hypotheses whose rules render the SAME command for
        # the SAME target (bootstrap + tech + context firing on one host);
        # executing each copy burned tool quota and amplified noise on the
        # target. Key = (tool, structured target, argv digest); the set
        # lives for ONE _act call (per cycle) only, so the next cycle's
        # legitimate re-run of a still-proposed hypothesis is not blocked.
        seen_commands: set[tuple] = set()
        opsec_skipped = 0        # P0-2: transient skips vote differently
        for hyp in batch:
            # P-030-R (grok adjudication): testing BEFORE the action loop.
            # Writing it after the loop meant the executor-side retirement
            # guard (state == "testing") never fired in production — the
            # 92-hypothesis stall was NOT actually fixed by the first P-030
            # pass; the tests only covered the direct-call path _act never
            # takes. Retirement is now AGGREGATED here after the loop.
            if hyp.get("state") != "testing":
                hyp["state"] = "testing"
                self.writer.upsert_entity(hyp)
            started = 0          # P-030-R2: runs actually STARTED this loop
            run_ids: list[str] = []
            for action in hyp.get("actions", []):
                target = self._action_target(hyp, action)
                if target is None:
                    # F01: no structured target -> refuse to execute. The rule
                    # set has non-HTTP actions (kerberos/smb/shell/cloud) whose
                    # cmd carries no url; they must still name what they touch.
                    self.writer.append_event("scope_blocked", hyp["id"], {
                        "action": action.get("tool"),
                        "reason": "action has no structured target (url/host/ip/asset_id)",
                    })
                    continue
                kind, value = target
                # OPSEC gate 1 — defender-planted canary paths: never touch.
                # Two sources: builtin honeypot-shaped path tokens, and the
                # robots.txt Disallow list fetched by R-CTX-ROBOTS-001
                # (a target's robots.txt disallowing /honeypot.html is the
                # observed pattern; a fuzz hit there is an instant, deserved
                # flag).
                if kind == "url":
                    tok = opsec.canary_hit(value) \
                        or self._robots_canary_hit(
                            self._origin_of("url", value), value)
                    if tok:
                        opsec_skipped += 1
                        self.writer.append_event("opsec_canary_skip",
                                                 hyp["id"], {
                             "tool": action.get("tool"), "url": value,
                             "canary": tok})
                        continue
                # OPSEC gate 2 — origin under cooldown (WAF active / a run
                # classified `detected`): skip, don't provoke the wall.
                # Exemption: the WAF confirm probe (R-CTX-WAF-001) must be
                # able to run once against the very origin it cooled down —
                # otherwise the rule mints and instantly self-blocks
                # (P0-2, round-2 audit).
                origin = self._origin_of(kind, value)
                if self._cooldowns.blocked(origin) and \
                        hyp.get("rule_id") != "R-CTX-WAF-001":
                    opsec_skipped += 1
                    self.writer.append_event("opsec_cooldown_skip",
                                             hyp["id"], {
                         "tool": action.get("tool"), "origin": origin,
                         "reason": self._cooldowns.reason(origin),
                         "remaining_s": round(
                             self._cooldowns.remaining(origin), 1)})
                    continue
                decision = self._guard_target(kind, value)
                if not decision.allowed:
                    self.writer.append_event("scope_blocked", hyp["id"],
                                             {"target": {kind: value},
                                              "reason": decision.reason})
                    continue
                # R5 H4 (honest): re-check the same target immediately before
                # execution. A subprocess tool resolves the host itself at
                # connect time, so this narrows — but does not close — the
                # DNS-rebinding window; only the replay fetcher consumes the
                # guard's bind_ip as an actual pin. The fresh result travels
                # with the action and is recorded on the observation.
                recheck = self._guard_target(kind, value)
                if not recheck.allowed:
                    self.writer.append_event("scope_blocked", hyp["id"],
                                             {"target": {kind: value},
                                              "phase": "recheck",
                                              "reason": recheck.reason})
                    continue
                # F09: argv rendering — no shell, credentials to the env, and
                # only the masked summary is persisted in tool_run.command.
                # intensity profile: a stricter cmd_<intensity> variant wins
                # when the rule carries one (stealth is the live case).
                template = action.get("cmd", "")
                if getattr(self, "intensity", "normal") not in ("", "normal"):
                    template = action.get(
                        f"cmd_{self.intensity}") or template
                rendered = cmd.render_command(template,
                                              self._command_ctx(hyp, action))
                # G9: dedup AFTER the guard passes but BEFORE start_tool_run —
                # a repeated identical command is recorded as an act.dedup
                # event (full audit trail, masked summary in the payload) and
                # skipped; it must not produce a tool_run row.
                fp = _command_fingerprint(action["tool"], (kind, value),
                                          rendered.argv)
                if fp in seen_commands:
                    self.writer.append_event("act.dedup", hyp["id"], {
                        "tool": action["tool"],
                        "target": {kind: value},
                        "command": rendered.summary,
                    })
                    continue
                seen_commands.add(fp)
                run_id = self.writer.start_tool_run(tool=action["tool"],
                                                    command=rendered.summary,
                                                    hypothesis_id=hyp["id"])
                started += 1
                run_ids.append(run_id)
                # executor runs the tool; skeleton records an observation.
                # R5 M6: the tool_run id travels with the action so the
                # executor can close the row (done/error/timeout).
                payload = {**action, "command": rendered.summary,
                           "argv": rendered.argv, "env": rendered.env,
                           "bind_ip": recheck.detail.get("bind_ip"),
                           "_tool_run_id": run_id}
                # P0-1 (round-2 audit): a rule may need the OBSERVATION to
                # carry the real request URL — the robots probe fetches
                # {url}/robots.txt while its guard target stays the base
                # URL, and the curl parser dispatches on that suffix.
                # obs_url renders with the same ctx, never feeds the guard.
                if action.get("obs_url"):
                    r_obs = cmd.render_command(str(action["obs_url"]),
                                               self._command_ctx(hyp, action))
                    if r_obs.argv and r_obs.argv[0]:
                        # collapse "//" in the path: a seed value with a
                        # trailing slash must not mint ...com//robots.txt
                        payload["url"] = re.sub(r"(?<!:)/{2,}", "/",
                                                r_obs.argv[0])
                self.executor(hyp, payload)
            # P-030-R2: AGGREGATED retirement after the action loop, counting
            # only the runs THIS loop actually started. Blocked actions
            # (scope refusal / no target) never produce a run row and must
            # not vote; expected==0 (all blocked) retires as done — the
            # scope_blocked events are already on the log per-action.
            self._retire_hypothesis_if_complete(hyp, expected=started,
                                                opsec_blocked=opsec_skipped,
                                                run_ids=run_ids)

    def _retire_hypothesis_if_complete(self, hyp: dict, *,
                                       expected: int | None = None,
                                       opsec_blocked: int = 0,
                                       run_ids: list[str] | None = None) -> None:
        """Move a testing hypothesis to a terminal state when every run the
        last _act loop STARTED for it is terminal. Never raises.

        P-030-R/R2 (grok adjudication): retirement is aggregated here after
        the whole action loop, not per-run in the executor. ``expected`` is
        the count of runs actually started this loop (blocked actions never
        start one); expected==0 means every action was blocked — retire as
        'done' (NOT error/timeout: those re-mint via P-015 and would churn
        forever against a scope that will keep refusing).

        P0-2 (round-2 audit): opsec blocks are TRANSIENT (a 30-min cooldown
        expires; a canary stays untouchable but the rest of the rule set
        may still apply). Terminal `done` would freeze the (rule, asset)
        pair into the seen-set forever, so an opsec-blocked-only loop goes
        back to `proposed` instead — the next cycle re-acts it.

        P0-2 (round-3 audit): ``run_ids`` scopes the status query to the
        rows THIS loop started — older rows from previous cycles of the
        same hypothesis must not vote on this loop's outcome — and a
        terminal error/timeout bumps the per-(rule, asset) attempt counter
        on the ASSET so re-mints stop at three.
        """
        try:
            if run_ids is None:
                rows = self.writer.conn.execute(
                    "SELECT status FROM tool_run WHERE hypothesis_id = ?",
                    (hyp["id"],)).fetchall()
            elif not run_ids:
                rows = []            # loop started nothing (all blocked)
            else:
                marks = ",".join("?" * len(run_ids))
                rows = self.writer.conn.execute(
                    f"SELECT status FROM tool_run WHERE id IN ({marks})",
                    tuple(run_ids)).fetchall()
            started = expected if expected is not None else len(rows)
            if not rows and started == 0:
                # all-blocked: no run ever started, events already recorded
                # per action (scope_blocked / opsec_*_skip).
                cur = self.writer.get_entity(hyp["id"])
                if cur and cur.get("kind") == "hypothesis" and \
                        cur.get("state") == "testing":
                    if opsec_blocked:
                        cur["state"] = "proposed"
                        cur["opsec_blocked"] = opsec_blocked
                    else:
                        cur["state"] = "done"
                    cur["finished_at"] = util.now_iso()
                    self.writer.upsert_entity(cur)
                return
            if len(rows) < max(started, 1):
                return          # a started run's row exists but is not
                                # terminal yet, or the executor has not
                                # closed all rows this loop started —
                                # stay testing until the next beat retires
            statuses = {r["status"] for r in rows}
            if statuses & {"running", "queued", "pending"}:
                return          # an action is still in flight — stay testing
            if "error" in statuses:
                final = "error"
            elif "timeout" in statuses:
                final = "timeout"
            else:
                final = "done"
            if final in ("error", "timeout"):
                # P0-2 (round-3 audit): failed pairs accumulate attempts on
                # the ASSET so the re-mint can stop at three.
                self._bump_rule_attempts(hyp)
            cur = self.writer.get_entity(hyp["id"])
            if cur and cur.get("kind") == "hypothesis" and \
                    cur.get("state") == "testing":
                cur["state"] = final
                cur["finished_at"] = util.now_iso()
                self.writer.upsert_entity(cur)
        except Exception:
            pass

    def _bump_rule_attempts(self, hyp: dict) -> None:
        """P0-2 (round-3 audit): attempts must accumulate per (rule, asset)
        ACROSS re-mints — each mint is a fresh entity whose own counter
        resets to zero, so a deterministically failing pair used to re-mint
        forever. The counter lives on the asset (`attempts_by_rule`) and
        _expand stops minting a pair at three. Never raises."""
        try:
            aid, rid = hyp.get("asset_id"), hyp.get("rule_id")
            if not aid or not rid:
                return
            asset = self.writer.get_entity(aid)
            if not asset or asset.get("kind") != "asset":
                return
            counts = dict(asset.get("attempts_by_rule") or {})
            counts[rid] = int(counts.get(rid, 0)) + 1
            asset["attempts_by_rule"] = counts
            self.writer.upsert_entity(asset)
        except Exception:
            pass

    def _command_ctx(self, hyp: dict, action: dict) -> dict:
        """Context values for a rule command's placeholders (F09).

        Only the known target/credential keys are handed to the renderer;
        action-level values win over hypothesis-level ones. ``wordlist_dir``
        is injected here so rule JSONs never carry absolute home paths:
        they reference ``{wordlist_dir}/<file>``, the directory comes from
        ``MOTOKO_WORDLIST_DIR`` (default ``~/.motoko/wordlists``).
        """
        ctx: dict = {}
        for source in (hyp, action):
            for key in cmd.CTX_KEYS:
                if key in ctx:
                    continue
                value = source.get(key)
                if isinstance(value, (str, int, float)) and value != "":
                    ctx[key] = value
        if "wordlist_dir" not in ctx:
            wl = os.environ.get("MOTOKO_WORDLIST_DIR", "~/.motoko/wordlists")
            ctx["wordlist_dir"] = str(Path(wl).expanduser())
        # OPSEC: one UA per engagement (MOTOKO_UA overrides). Rules render
        # {ua} — no tool ships its default scanner fingerprint.
        if "ua" not in ctx:
            ctx["ua"] = os.environ.get("MOTOKO_UA", opsec.DEFAULT_UA)
        return ctx

    def _action_target(self, hyp: dict, action: dict) -> tuple[str, str] | None:
        """The structured target of an action (F01), most specific first."""
        url = action.get("url") or hyp.get("url")
        if url:
            return "url", str(url)
        host = action.get("host") or hyp.get("host")
        if host:
            return "host", str(host)
        ip = action.get("ip") or hyp.get("ip")
        if ip:
            return "ip", str(ip)
        asset_id = action.get("asset_id") or hyp.get("asset_id")
        if asset_id:
            return "asset_id", str(asset_id)
        return None

    def _guard_target(self, kind: str, value: str) -> ScopeDecision:
        """Route a structured target through the matching guard check."""
        if kind == "url":
            return self.guard.check_url(value)
        if kind == "host":
            return self.guard.check_host(value)
        if kind == "ip":
            return self.guard.check_ip(value)
        return self.guard.check_asset(self.writer.get_entity(value))

    def _recover_failures(self) -> None:
        """R3: classify this engagement's failures and un-strand stalled plans.

        Runs once per cycle, BEFORE ``_prioritize()``, so a hypothesis recycled
        out of ``testing`` can re-enter the ACT batch in the same run instead of
        waiting for the next invocation. The end-of-run health sweep is too late
        for that — it only ever helped the *next* run.

        The digest is cached on self so ``_reflect_if_needed`` can hand the
        reflector a read-only view of it. The reflector itself never gets the
        writer (F04/P0-1); recovery is this method's job because the
        orchestrator owns the writer.

        Never fails the run: a recovery pass is an optimization, and a locked
        or half-written graph must not take the loop down with it.
        """
        try:
            from . import failure
            self._failure_digest = failure.build_digest(
                self.writer, self.engagement_id, recover=True)
            if self._failure_digest.recycled or self._failure_digest.abandoned:
                self.writer.append_event(
                    "failure_recovery", self.engagement_id,
                    self._failure_digest.as_dict())
        except Exception:
            self._failure_digest = None

    def _reflect_if_needed(self, force: bool = False) -> None:
        if self.reflector is None:
            return
        # The LLM gets a propose-only handle: propose_hypothesis /
        # adjust_priority / queries. There is no upsert or transition on it (F04).
        if self._reflector_takes_failures:
            lines = (self._failure_digest.prompt_lines()
                     if self._failure_digest is not None else [])
            self.reflector(self.propose_view, self.engagement_id,
                           failure_lines=lines)
            return
        self.reflector(self.propose_view, self.engagement_id)

    # -- checkpoint / summary -----------------------------------------
    def _checkpoint(self) -> None:
        self.writer.commit()
        digest.write_digest(self.writer, self.engagement_id, self.edir / "digest.md")

    def _summary(self) -> dict:
        f = self.writer.query_entities(kind="finding", engagement_id=self.engagement_id)
        h = self.writer.query_entities(kind="hypothesis", engagement_id=self.engagement_id)
        from collections import Counter
        return {
            "cycle": self.cycle,
            "findings": len(f),
            "by_state": dict(Counter(x.get("state") for x in f)),
            "hypotheses": len(h),
        }

    def _default_executor(self, hyp: dict, action: dict) -> None:
        """Skeleton executor: record a placeholder observation.

        Records the MASKED command (F09) and the action's target context so
        SYNC can tie future raw output to its target (F13).
        """
        self.writer.record_observation(
            tool=action["tool"], engagement_id=self.engagement_id, raw_path=None,
            parsed_summary=f"skeleton: would run "
                           f"'{action.get('command', action.get('cmd', ''))}'",
            url=action.get("url") or hyp.get("url"),
            host=action.get("host") or hyp.get("host"),
        )

    def close(self) -> None:
        reap = getattr(self.executor, "reap", None)
        if callable(reap):
            reap()                       # P-031: no scan outlives the engine
        self.writer.close()


from pathlib import Path  # noqa: E402  (used in __init__)
