'Orchestrator — the single-writer six-beat main loop.\n\nSYNC -> VALIDATE -> EXPAND -> PRIORITIZE -> ACT -> REFLECT, replacing the\nlinear 5-layer pipeline. This module owns the ONLY writer connection; the\ntool executor and the LLM reflector are injected so the loop is unit-testable\nwithout live targets.\n\n* One writer process. Hermes supervises via digest/query/events (read-only).\n* scope guard runs before EVERY action; a block is recorded, never skipped.\n* Deterministic validators promote findings; the reflector (LLM) may only\n  propose hypotheses / adjust priorities, never drive a finding transition.\n* Every transition writes an event; crash recovery = replay events.\n'

from __future__ import annotations

import hashlib
import http.client
import inspect
import json
import os
import re
import socket
import ssl
from pathlib import Path
from urllib.parse import urlparse

from . import (cmd, confidence, db, digest, egress, opsec, util,
                  writer_views)
from . import asset_link
from .dedup import compute_dedup_key
from .hypothesis_engine import HypothesisEngine
from .opsec import CooldownBoard
from .parsers import dependency_context_keys, get_parser, parse_tool
from .scope import ScopeDecision, ScopeGuard
from .scan_waves import ScanWaves
from .verification import (
    EGRESS_POLICY, IO_ERROR, IO_EXHAUSTED, MISSING_BACKEND, NO_TARGET,
    NO_VALIDATOR, SCOPE_BLOCKED, STRIKE_REASONS, UNPINNED, Verdict, dom, oob,
    pick_validator, replay,
)

_MAX_EMPTY_EXPANSIONS = 3

_EXPAND_BUDGET = 30

_ACT_K = 4

_MAX_PROPOSED_PER_RULE = 40

_LIVE_HYPOTHESIS_STATES = ("proposed", "testing")

_REFLECT_IDLE_GAP = 5


def _accepts_failure_lines(reflector) -> bool:
    '    Probed once at construction. Introspection deliberately happens here and\n    not as a ``try: f(..., failure_lines=x) except TypeError: f(...)`` at call\n    time — a TypeError raised *inside* a reflector would be misread as "old\n    signature" and the reflector would be invoked twice, doubling the LLM\n    proposals for that beat.\n    '
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


def _accepts_canary_sender(canary) -> bool:
    'Does the injected canary manager\'s ``trigger`` take ``sender=``?\n\n    Probed once at construction, for the reason ``_accepts_failure_lines``\n    gives: a ``try: t(f, c, sender=s) except TypeError: t(f, c)`` at call time\n    would misread a TypeError raised INSIDE a delivery as "old signature" and\n    deliver the canary a second time — two payloads for one finding, the second\n    one outside anything the validator reasoned about.'
    trigger = getattr(canary, "trigger", None)
    if not callable(trigger):
        return False
    try:
        sig = inspect.signature(trigger)
    except (TypeError, ValueError):
        return False                    # builtin/C callable: assume no sender
    params = sig.parameters
    if "sender" in params:
        return True
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


def replay_egress_blocked(fetcher) -> bool:
    'True when the wired replay fetcher cannot send anything at all.'
    return fetcher is default_fetcher and not egress.replay_asserted()


_REPLAY_CONNECT_TIMEOUT_S = 15.0


def default_fetcher(url: str, bind_ip: str | None = None):
    '    Any transport error returns None as well; tests inject a stub instead.\n    '
    if not bind_ip:
        return None
    if not egress.replay_asserted():
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
        sock = socket.create_connection(
            (bind_ip, port), timeout=_REPLAY_CONNECT_TIMEOUT_S)
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
        rules_dir = rules_dir or util.default_rules_dir()
        self.rules_dir = Path(rules_dir)
        self.engine = HypothesisEngine(self.rules_dir)
        # Validate the corpus before acquiring the engagement's writer lease.
        self.writer = db.Database(self.edir / "graph.db")
        self.executor = executor or self._default_executor
        self.reflector = reflector          # LLM reflector (injected; optional)

        self.fetcher = fetcher or default_fetcher
        self.browser = browser
        self.canary = canary
        self._canary_takes_sender = _accepts_canary_sender(canary)

        scope = self.writer.get_scope(engagement_id) or {}
        self.guard = ScopeGuard(
            scope.get("in_scope", []),
            scope.get("out_of_scope", []),
            resolver=resolver,
        )
        self.propose_view = writer_views.ProposeOnlyView(self.writer, engagement_id)
        self.cycle = 0
        self._last_reflect_cycle: int | None = None
        self.artifacts = self.edir / "obs"

        self._failure_digest = None
        self._reflector_takes_failures = _accepts_failure_lines(reflector)

        self._cooldowns = CooldownBoard()
        try:
            snap_path = self.edir / "opsec-cooldowns.json"
            if snap_path.exists():
                self._cooldowns.restore(json.loads(snap_path.read_text()))
        except Exception as e:
            # A restore failure LIFTS every cooled origin — that must be
            # visible. Best-effort: observability never breaks the boot.
            try:
                self.writer.append_event(
                    "opsec_cooldown_restore_error", self.engagement_id,
                    {"error": repr(e)})
            except Exception:
                pass
        self._waf_noted: set[tuple[str, str]] = set()
        # intensity=stealth selects a rule's stricter cmd_<intensity>
        # variant when present (was a dead init parameter until now). The
        # explicit argument wins; otherwise the engagement's scope row.
        self.intensity = intensity or str(scope.get("intensity") or "normal")
        self.oob_domain = str(scope.get("oob_domain") or "")
        try:
            self.scan_waves = ScanWaves(self.writer, engagement_id)
        except Exception:
            self.writer.close()
            raise

    # -- main loop -----------------------------------------------------
    def run(self, max_cycles: int = 20, max_depth: int = 3, *,
            wave_cycles: int = 5, max_waves: int | None = None) -> dict:
        if isinstance(max_cycles, bool) or not isinstance(max_cycles, int) or max_cycles < 1:
            raise ValueError("max_cycles must be a positive integer")
        if isinstance(wave_cycles, bool) or not isinstance(wave_cycles, int) or wave_cycles < 1:
            raise ValueError("wave_cycles must be a positive integer")
        if max_waves is not None and (isinstance(max_waves, bool) or
                not isinstance(max_waves, int) or max_waves < 1):
            raise ValueError("max_waves must be a positive integer")
        self.scan_waves.history = []
        self.scan_waves.begin()
        self.stop_reason = "cycle_budget"
        try:
            for _ in range(max_cycles):
                self.cycle += 1
                self.scan_waves.cycles += 1
                self._sync()
                self._validate()
                self._recover_failures()
                self._expand()
                batch = self._prioritize()
                if not batch:
                    # Finish bounded frontier evaluation before declaring the
                    # graph exhausted. Queue-cap deferrals need ACT to drain
                    # the queue; reevaluating them in a tight loop cannot help.
                    frontier = self.writer.query_entities(
                        kind="asset", engagement_id=self.engagement_id)
                    frontier_pending = any(
                        a.get("frontier", True) and not a.get("deferred_rules")
                        for a in frontier)
                    if not frontier_pending:
                        live = self._live_hypotheses()
                        if live:
                            self._reflect_if_needed()
                            batch = self._prioritize()
                        if not batch:
                            self.stop_reason = "waiting" if live else "exhausted"
                            break
                if batch:
                    before = self._scheduling_state()
                    self._act(batch)
                    if self._scheduling_state() == before:
                        self.stop_reason = "waiting"
                        break
                if self.scan_waves.cycles >= wave_cycles:
                    self.scan_waves.complete(stop_reason="wave_boundary",
                                             pending=len(self._live_hypotheses()))
                    if max_waves is not None and len(self.scan_waves.history) >= max_waves:
                        self.stop_reason = "wave_budget"
                        break
                    self._reflect_if_needed(force=True)
                self.writer.commit()
        except BaseException:
            # Keep completed work and cancellation failures in feedback. A
            # host disconnect must not reset the policy to the last full
            # wave and repeatedly promote the same failing scanner.
            if self.scan_waves.cycles:
                self.scan_waves.complete(stop_reason="interrupted",
                                         pending=len(self._live_hypotheses()))
            raise
        finally:
            reap = getattr(self.executor, "reap", None)
            if callable(reap):
                reap()
        if self.scan_waves.cycles:
            self.scan_waves.complete(stop_reason=self.stop_reason,
                                     pending=len(self._live_hypotheses()))
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

    def _scheduling_state(self) -> tuple:
        """Progress excludes timestamps/events: repeating a skip is no work."""
        hyps = self.writer.query_entities(kind="hypothesis", engagement_id=self.engagement_id)
        runs = self.writer.conn.execute("SELECT COUNT(*) FROM tool_run").fetchone()[0]
        return (runs, tuple(sorted((h["id"], h.get("state") or "proposed",
                                    h.get("priority") or 0) for h in hyps)))

    def _cooldown_delay(self, hyp: dict) -> float:
        if hyp.get("rule_id") == "R-CTX-WAF-001":
            return 0.0
        delays = []
        for action in hyp.get("actions") or []:
            target = self._action_target(hyp, action)
            if target:
                delays.append(self._cooldowns.remaining(self._origin_of(*target)))
        return min(delays) if delays else 0.0

    def _live_hypotheses(self) -> list[dict]:
        "        ``done`` / ``rejected`` / ``error`` / ``timeout`` / ``failed`` rows are\n        history: counting them is what made ``run``'s only break condition\n        unsatisfiable, so a finished campaign spun to ``max_cycles`` doing\n        nothing. A missing state counts as ``proposed``, matching _expand's\n        own default.\n        "
        return [h for h in self.writer.query_entities(
                    kind="hypothesis", engagement_id=self.engagement_id)
                if (h.get("state") or "proposed") in _LIVE_HYPOTHESIS_STATES]

    # -- six beats -----------------------------------------------------
    def _sync(self) -> None:
        '        Only ``processed_at IS NULL`` rows are ingested, and each row is\n        marked after handling, so a cycle no longer replays the whole\n        observation history and re-builds the same assets/findings.\n        '
        for o in self.writer.unprocessed_observations(self.engagement_id):
            self._ingest_observation(o)

    def _ingest_observation(self, o: dict, action: dict | None = None) -> dict:
        """Ingest evidence and return ephemeral results to the current caller."""
        result = {}
        if o.get("raw_path"):
            result = self._ingest_raw(
                o["id"], o["tool"], o["raw_path"],
                context={"url": o.get("url"), "host": o.get("host"),
                         "action_id": o.get("action_id")}, action=action,
            )
        self.writer.mark_observation_processed(o["id"])
        return result

    def _sync_runs(self, run_ids: list[str], *, action: dict | None = None) -> dict:
        "        The executor is synchronous, so _act closes a hypothesis's runs and\n        retires it in the SAME beat — the beat-level _sync would only parse\n        those observations next cycle, after the retirement vote. The\n        on_hit_class oracle needs the evidence columns written back first,\n        so _act ingests its own loop's rows before retiring. Rows land\n        processed exactly once: the next _sync skips them.\n        "
        result = {}
        for o in self.writer.unprocessed_observations_for_runs(
                self.engagement_id, run_ids):
            result.update(self._ingest_observation(o, action=action))
        return result

    def _ingest_raw(self, obs_id: str, tool: str, raw_path: str,
                    context: dict | None = None, action: dict | None = None) -> dict:
        try:
            raw = Path(raw_path).read_text(errors="replace")
        except OSError as e:
            # Nothing to parse — record why and let the observation be marked
            # processed instead of retrying it forever.
            self.writer.append_event("observation_dead_letter", obs_id,
                                     {"tool": tool, "raw_path": raw_path,
                                      "error": str(e)})
            return {}
        action = {**(action or {}), **{k: v for k, v in (context or {}).items() if v}}
        err_text = ""
        err_path = Path(str(raw_path).replace(".out", ".err"))
        try:
            err_text = err_path.read_text(errors="replace")
        except OSError:
            err_text = ""
        try:
            parsed = parse_tool(tool, raw, err_text, action)
        except Exception as e:
            self.writer.append_event(
                "observation_dead_letter", obs_id,
                {"tool": tool, "raw_path": raw_path,
                 "error": f"parse_tool raised: {e!r}"})
            return {}
        self.writer.update_observation_summary(obs_id, parsed.summary)
        if parsed.dead_letter:
            self.writer.append_event(
                "observation_dead_letter", obs_id,
                {"tool": tool, "raw_path": raw_path,
                 "dead_letter": parsed.dead_letter[:50]})
        asset_ids: list[str] = []
        for a in parsed.assets:
            a.setdefault("engagement_id", self.engagement_id)
            aid = self._merge_asset(a)
            if aid not in asset_ids:
                asset_ids.append(aid)
            if a.get("waf"):
                self._note_waf(aid, str(a["waf"]),
                               source=str(a.get("source") or parsed.tool))
        run_id = str((context or {}).get("action_id") or "")
        run_status = self.writer.tool_run_status(run_id) if run_id else None
        run_complete = run_status == "done"
        if run_id and not run_complete and (parsed.assets or parsed.services):
            # No silent skip: a withheld completeness claim is graph history,
            # so a host that never gets re-enumerated stays diagnosable.
            self.writer.append_event(
                "completeness_stamp_withheld", obs_id,
                {"tool": tool, "tool_run_id": run_id,
                 "tool_run_status": run_status,
                 "withheld": [n for n, want in (
                     ("source_stamp", bool(parsed.assets)),
                     ("services", bool(parsed.services))) if want],
                 "reason": "only a terminal `done` run may close the "
                           "enumeration gate or define the service picture"})
        if run_complete and tool in {"subfinder", "amass", "gau"} and run_id:
            hyp_id = self.writer.tool_run_hypothesis(run_id)
            if hyp_id:
                hyp = self.writer.get_entity(hyp_id)
                src_aid = (hyp or {}).get("asset_id")
                if src_aid:
                    src = self.writer.get_entity(src_aid)
                    if src and src.get("kind") == "asset":
                        val = str(src.get("value", ""))
                        src_host = val.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] \
                            if "://" in val else val
                        changed_src = False
                        completed = dict(src.get("enumeration_completed") or {})
                        if completed.get(tool) != util.registrable_domain(src_host):
                            completed[tool] = util.registrable_domain(src_host)
                            src["enumeration_completed"] = completed
                            changed_src = True
                        if src_host and src.get("enumerated_host") != src_host:
                            src["enumerated_host"] = src_host
                            changed_src = True
                        src_domain = util.registrable_domain(src_host) \
                            if src_host else ""
                        if src_domain and \
                                src.get("enumerated_domain") != src_domain:
                            src["enumerated_domain"] = src_domain
                            changed_src = True
                        if changed_src:
                            src["frontier"] = True
                            src["expansion_count"] = 0
                            self.writer.upsert_entity(src)
        finding_ids: list[str] = []
        for f in parsed.findings:
            f.setdefault("engagement_id", self.engagement_id)
            fid = self._ingest_finding(f)
            if fid and fid not in finding_ids:
                finding_ids.append(fid)
            if f.get("waf") and f.get("asset_id"):
                self._note_waf(str(f["asset_id"]), str(f["waf"]),
                               source=str(f.get("detector") or parsed.tool))
        self.writer.update_observation_evidence(obs_id, asset_ids,
                                                finding_ids)
        if run_complete and parsed.services:
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
                previous = {(s.get("port"), s.get("service_name"))
                            for s in self.writer.get_services(aid)}
                for s in parsed.services:
                    s.setdefault("id", util.new_id("service"))
                    s["asset_id"] = aid
                    self.writer.add_service(s)
                if any((s.get("port"), s.get("service_name")) not in previous
                       for s in parsed.services):
                    self._reopen_frontier(aid)

        # Only a successful invocation can supply values to its immediate
        # dependent actions. The return value is never attached to graph data;
        # callers outside ACT discard it, including recovery after restart.
        parser = get_parser(tool)
        allowed = parser.context_keys(action) if parser and run_complete else frozenset()
        return {key: value for key, value in parsed.context.items()
                if key in allowed and key in cmd.CTX_KEYS and isinstance(value, str)
                and value and len(value) <= 8192}

    def _reopen_frontier(self, asset_id: str) -> None:
        asset = self.writer.get_entity(asset_id)
        if asset and asset.get("kind") == "asset":
            asset["frontier"] = True
            asset["expansion_count"] = 0
            asset.pop("deferred_rules", None)
            self.writer.upsert_entity(asset)

    def _merge_asset(self, a: dict) -> str:
        'Dedup assets by (type, value) and merge new facts into the row.'
        a.setdefault("id", util.new_id("asset"))
        a.setdefault("engagement_id", self.engagement_id)
        for e in self.writer.query_entities(kind="asset",
                                            engagement_id=self.engagement_id):
            if e.get("type") != a.get("type") or e.get("value") != a.get("value"):
                continue
            merged = dict(e)
            changed = False
            for k, v in a.items():
                if k in ("id", "created_at", "updated_at", "frontier",
                         "expansion_count", "attempts_by_rule", "deferred_rules"):
                    continue
                if k == "source":
                    merged[k] = v
                    continue
                if k == "tech" and e.get("tech") and v:
                    union = sorted(set(e["tech"]) | set(v))
                    if union != e.get("tech"):
                        merged["tech"] = union
                        changed = True
                elif e.get(k) != v and v not in (None, "", []):
                    merged[k] = v
                    changed = True
            if changed:
                merged["frontier"] = True      # new facts -> re-evaluate once
                merged["expansion_count"] = 0
                merged.pop("deferred_rules", None)
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
        'Create one finding, or link it to the surviving duplicate.'
        if not f.get("url"):
            f["dedup_key"] = key = compute_dedup_key(f)
            for e in self.writer.query_entities(kind="finding",
                                                engagement_id=self.engagement_id):
                if e.get("dedup_key") == key:
                    return self._record_duplicate(f, e)
            f.setdefault("state", "candidate")
            f["signals"] = list(f.get("signals") or [])
            self.writer.upsert_entity(f)
            self._park_blocked(f, "ingest", NO_TARGET,
                               "finding carries no url, so no validator can "
                               "target it and nothing ever attaches one later "
                               "— terminal, unlike a deployment block, which "
                               "clears when the backend or egress assertion "
                               "appears")
            ok, reason = self.writer.advance_and_persist(
                f["id"], "wont_test", actor="ingest",
                payload={"reason": NO_TARGET})
            if not ok:
                self.writer.append_event("validation_error", f["id"],
                                         {"event": "wont_test",
                                          "reason": reason})
            return f["id"]
        if not f.get("asset_id"):
            aid = self._asset_id_for_url(str(f["url"]))
            if aid:
                f["asset_id"] = aid
            else:
                # M3: mint the missing in-scope asset so the finding's rule
                # chain has a subject; out-of-scope hosts stay unlinked.
                decision = self.guard.check_url(str(f["url"]))
                if decision.allowed:
                    f["asset_id"] = self._merge_asset({
                        "kind": "asset", "type": "url", "value": str(f["url"]),
                        "frontier": True, "source": f.get("detector") or "ingest",
                    })
        key = f.get("dedup_key") or compute_dedup_key(f)
        f["dedup_key"] = key
        for e in self.writer.query_entities(kind="finding",
                                            engagement_id=self.engagement_id):
            if e.get("dedup_key") == key:
                return self._record_duplicate(f, e)
        f.setdefault("state", "candidate")
        f["signals"] = list(f.get("signals") or [])
        self.writer.upsert_entity(f)      # always born 'candidate'
        if f.get("asset_id"):
            self._reopen_frontier(f["asset_id"])
        ok, reason = self.writer.advance_and_persist(f["id"], "dedup_pass",
                                                     actor="validator")
        if not ok:
            self.writer.append_event("validation_error", f["id"],
                                     {"event": "dedup_pass", "reason": reason})
        return f["id"]

    def _asset_id_for_url(self, url: str) -> str | None:
        '        M1-asset-link: delegates to the shared ``asset_link`` module so the\n        CLI strix ingest and this path can never drift apart.\n        '
        return asset_link.asset_id_for_url(self.writer, url,
                                           engagement_id=self.engagement_id)

    def _record_duplicate(self, f: dict, primary: dict) -> str:
        ''
        self.writer.add_edge(f["id"], primary["id"], "duplicate_of",
                             engagement_id=self.engagement_id,
                             data={"dedup_key": f.get("dedup_key"),
                                   "detector": f.get("detector")})
        self.writer.bump_duplicate_count(primary["id"])
        return primary["id"]

    def _validate(self) -> None:
        ''
        findings = (
            self.writer.query_entities(kind="finding", engagement_id=self.engagement_id,
                                       state="triaged")
            + self.writer.query_entities(kind="finding", engagement_id=self.engagement_id,
                                         state="reproduced")
        )
        selected = [(f, self._select_validator(f)) for f in findings]
        selected = [(f, name) for f, name in selected if name]
        for f, name in selected[:5]:
            try:
                verdict = self._run_validator(name, f)
            except Exception as e:      # a validator bug must not kill the run
                self.writer.append_event("validation_error", f["id"],
                                         {"validator": name, "error": str(e)})
                continue
            if verdict is None:
                continue
            if verdict.event == "inconclusive":
                self._absorb_inconclusive(f, name, verdict)
                continue
            # a real verdict: the finding is testable here, so any earlier
            # block is stale and the strike budget resets.
            self._clear_block(f)
            ok, reason = self.writer.advance_and_persist(
                f["id"], verdict.event, actor="validator", verdict=verdict)
            if not ok:
                self.writer.append_event("validation_error", f["id"],
                                         {"event": verdict.event, "reason": reason})


    _VALIDATOR_ATTEMPT_BUDGET = 3

    def _select_validator(self, f: dict) -> str | None:
        'Which validator should run for this finding, or None to skip it.'
        name = pick_validator(f)
        # a replay re-check cannot promote past reproduced, so it is churn
        if f.get("state") == "reproduced" and name == "replay":
            return None
        if name == "dom" and self.browser is None:
            self._park_blocked(f, name, MISSING_BACKEND,
                               "no browser backend is wired for the DOM "
                               "validator")
            return None
        if name == "oob" and self.canary is None:
            self._park_blocked(f, name, MISSING_BACKEND,
                               "no canary backend is wired for the OOB "
                               "validator")
            return None
        prev = f.get("verification_blocked") or {}
        if prev.get("validator") == name and self._block_still_applies(
                prev.get("reason"), name):
            return None          # already reported, nothing has changed
        self._clear_block(f)
        return name

    def _block_still_applies(self, reason: str | None, name: str) -> bool:
        """Is a parked finding's block still in force?

        Deployment-shaped blocks (no backend, no asserted egress) and
        finding-shaped ones (out of scope, no url, retry budget spent) hold
        until something changes. ``unpinned`` does not: it records the DNS
        answer at that moment, so it re-enters the queue and is re-decided.
        Idempotent either way — ``_park_blocked`` never re-emits the same
        (validator, reason) pair, so a retry costs a slot, not an event.
        """
        if reason == MISSING_BACKEND:
            return ((name == "dom" and self.browser is None)
                    or (name == "oob" and self.canary is None))
        if reason == EGRESS_POLICY:
            # Both target-facing legs park on the same assertion, so both must
            # recognise it as still in force — otherwise an OOB finding is
            # re-decided every beat for a deployment condition that cannot
            # change under it.
            return name in ("replay", "oob") and replay_egress_blocked(self.fetcher)
        return reason in (NO_VALIDATOR, IO_EXHAUSTED, SCOPE_BLOCKED, NO_TARGET)

    def _absorb_inconclusive(self, f: dict, name: str, verdict) -> None:
        """An inconclusive verdict: park, or strike — never terminate.

        Only ``io_error`` (a real attempt that died on the wire) consumes the
        retry budget, and even an exhausted budget parks rather than advancing
        to ``wont_test``. ``wont_test`` is a terminal state that reads as a
        decision about the finding; a harness that lacks a browser has made no
        such decision, and recording one destroyed critical findings.
        """
        reason = verdict.reason or IO_ERROR
        if reason not in STRIKE_REASONS:
            self._park_blocked(f, name, reason, verdict.detail)
            return
        cur = self.writer.get_entity(f["id"])
        if not cur:
            return
        attempts = int(cur.get("validator_attempts") or 0) + 1
        cur["validator_attempts"] = attempts
        self.writer.upsert_entity(cur)
        if attempts >= self._VALIDATOR_ATTEMPT_BUDGET:
            self._park_blocked(
                f, name, IO_EXHAUSTED,
                f"{attempts} consecutive transport failures; last: "
                f"{verdict.detail}")

    def _park_blocked(self, finding: dict, validator: str, reason: str,
                      detail: str) -> None:
        """Mark a finding unverifiable HERE, without touching its state.

        Idempotent per (validator, reason): the field is rewritten and one
        ``verification_blocked`` event is appended the first time, so a finding
        stuck behind a missing backend produces one row in the event log and
        not one per beat.
        """
        cur = self.writer.get_entity(finding["id"]) or {}
        prev = cur.get("verification_blocked") or {}
        if prev.get("reason") == reason and prev.get("validator") == validator:
            return
        cur["verification_blocked"] = {
            "reason": reason, "validator": validator, "detail": detail,
            "at": util.now_iso(),
        }
        self.writer.upsert_entity(cur)
        self.writer.append_event("verification_blocked", finding["id"], {
            "reason": reason, "validator": validator, "detail": detail,
            "state": cur.get("state"), "class": cur.get("class"),
            "severity": cur.get("severity"),
        })

    def _clear_block(self, finding: dict) -> None:
        """Drop a stale block once the finding is testable again."""
        if not finding.get("verification_blocked"):
            return
        cur = self.writer.get_entity(finding["id"])
        if not cur or not cur.get("verification_blocked"):
            return
        prev = cur["verification_blocked"]
        cur.pop("verification_blocked", None)
        cur["validator_attempts"] = 0
        self.writer.upsert_entity(cur)
        self.writer.append_event("verification_unblocked", finding["id"], {
            "reason": prev.get("reason"), "validator": prev.get("validator"),
            "state": cur.get("state"),
        })

    def _run_validator(self, name: str, finding: dict):
        'Validator entry point.'
        url = finding.get("url") or ""
        if not url:
            self.writer.append_event("verification_blocked", finding.get("id"),
                                     {"phase": "validate", "validator": name,
                                      "reason": NO_TARGET})
            return Verdict("inconclusive", "finding has no url to validate",
                           reason=NO_TARGET)
        decision = self.guard.check_url(url)
        if not decision.allowed:
            self.writer.append_event("scope_blocked", finding.get("id"), {
                "phase": "validate", "url": url, "reason": decision.reason})
            return Verdict("inconclusive",
                           f"scope guard blocked validation: {decision.reason}",
                           reason=SCOPE_BLOCKED)
        try:
            bind_ip = (decision.detail.get("bind_ip")
                       if isinstance(decision.detail, dict) else None)
            unpinned = ("bind_ip" not in decision.detail
                        or (self.fetcher is default_fetcher and not bind_ip))
            # Gate order matters and is deliberate: egress BEFORE unpinned.
            # `egress_policy` is deployment-shaped — it holds until the
            # operator asserts a lane, and `_block_still_applies` knows that.
            # `unpinned` is finding-shaped and transient (a DNS answer at one
            # instant), so it is re-decided every beat. Reporting a deployment
            # that has no asserted egress as "DNS gave us no address" sends the
            # operator to fix the resolver instead of the lane, and re-decides
            # a condition that cannot change under it.
            egress_blocked = replay_egress_blocked(self.fetcher)
            if name == "replay":
                if egress_blocked:
                    return Verdict(
                        "inconclusive",
                        "the built-in replay fetcher fails closed: "
                        "MOTOKO_ALLOW_DIRECT_REPLAY is not asserted for this "
                        "deployment, so no replay traffic may leave the box",
                        reason=EGRESS_POLICY)
                if unpinned:
                    return Verdict(
                        "inconclusive",
                        f"scope guard cleared {url!r} without a bind_ip; "
                        f"refusing to connect unpinned (DNS rebinding window)",
                        reason=UNPINNED)
                return replay.replay_verdict(finding, self.fetcher,
                                             bind_ip=bind_ip)
            if name == "dom":
                if self.browser is None:
                    return Verdict("inconclusive",
                                   "no browser backend is wired for the DOM "
                                   "validator", reason=MISSING_BACKEND)
                return dom.dom_verdict(finding, self.browser)
            if name == "oob":
                if self.canary is None:
                    return Verdict("inconclusive",
                                   "no canary backend is wired for the OOB "
                                   "validator", reason=MISSING_BACKEND)
                if egress_blocked:
                    return Verdict(
                        "inconclusive",
                        "the canary injection rides the replay fetcher, which "
                        "fails closed: MOTOKO_ALLOW_DIRECT_REPLAY is not "
                        "asserted for this deployment, so no OOB payload may "
                        "leave the box",
                        reason=EGRESS_POLICY)
                if unpinned:
                    return Verdict(
                        "inconclusive",
                        f"scope guard cleared {url!r} without a bind_ip; the "
                        "canary injection would reconnect unpinned (DNS "
                        "rebinding window), so no payload is delivered",
                        reason=UNPINNED)
                # `interactions` is passed when the manager offers it: the
                # protocol that answered (dns vs http) is evidence about how
                # strong the callback is, and getattr keeps a boolean-only
                # manager — the test stubs — working unchanged.
                return oob.oob_verdict(
                    finding, self.canary.issue,
                    self._canary_trigger(bind_ip), self.canary.poll,
                    getattr(self.canary, "interactions", None))
        except Exception as e:
            return Verdict("inconclusive", f"validator {name!r} IO failure: {e}",
                           reason=IO_ERROR)
        return Verdict("inconclusive",
                        f"no validator implementation for {name!r}",
                        reason=NO_VALIDATOR)

    def _canary_trigger(self, bind_ip: str | None):
        'The ``(finding, canary)`` callable ``oob_verdict`` delivers with.\n\n        Managers that take no ``sender`` keep their own path (probed once at\n        construction — see ``_accepts_canary_sender``).\n        '
        manager = self.canary
        takes_sender = self._canary_takes_sender
        fetcher = self.fetcher

        def deliver(url: str):
            # Same contract replay_verdict offers an injected fetcher: the
            # pinned form only when there is an address to pin to.
            if bind_ip is None:
                return fetcher(url)
            return fetcher(url, bind_ip=bind_ip)

        def trigger(finding: dict, canary: str):
            if not takes_sender:
                return manager.trigger(finding, canary)
            return manager.trigger(finding, canary, sender=deliver)

        return trigger

    def _expand(self) -> None:
        'Hypothesis engine fires on frontier nodes.'
        assets = self.writer.query_entities(kind="asset", engagement_id=self.engagement_id)
        seen = {(h.get("rule_id"), h.get("asset_id"))
                for h in self.writer.query_entities(kind="hypothesis",
                                                    engagement_id=self.engagement_id)
                if (h.get("state") or "proposed") not in ("error", "timeout", "failed")}
        proposed_by_rule: dict[str, int] = {}
        for h in self.writer.query_entities(kind="hypothesis",
                                            engagement_id=self.engagement_id,
                                            state="proposed"):
            rid = h.get("rule_id") or ""
            proposed_by_rule[rid] = proposed_by_rule.get(rid, 0) + 1
        _ENUM_RULES = {"R-RECON-SUB-001", "R-RECON-GAU-001"}
        enum_domains_in_flight: set[tuple[str, str]] = set()
        for h in self.writer.query_entities(kind="hypothesis",
                                            engagement_id=self.engagement_id):
            if h.get("rule_id") in _ENUM_RULES and                     (h.get("state") or "proposed") in ("proposed", "testing")                     and h.get("domain"):
                enum_domains_in_flight.add((h["rule_id"], h["domain"]))
        budget = _EXPAND_BUDGET
        assets.sort(key=lambda a: (a.get("expansion_count", 0),
                                   str(a.get("value", ""))))
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
                deferred = []
                for hyp in hyps:
                    hyp.setdefault("engagement_id", self.engagement_id)
                    # bind the subject asset's URL so scope guard + action
                    # rendering have a concrete target.
                    hyp.setdefault("asset_id", a["id"])
                    key = (hyp.get("rule_id"), a["id"])
                    if key in seen:
                        dup_skips += 1
                        continue
                    rid = hyp.get("rule_id") or ""
                    if budget <= 0:
                        cap_skips += 1
                        deferred.append(rid)
                        continue
                    if rid in _ENUM_RULES:
                        a_val = str(a.get("value") or "")
                        a_host = (a_val.split("://", 1)[1].split("/", 1)[0]
                                  .split(":", 1)[0]
                                  if "://" in a_val else a_val)
                        a_domain = (util.registrable_domain(a_host)
                                    if a_host else "")
                        if a_domain and (rid, a_domain) in enum_domains_in_flight:
                            cap_skips += 1
                            deferred.append(rid)
                            continue
                    pair_attempts = (a.get("attempts_by_rule") or {}).get(rid)
                    if isinstance(pair_attempts, int) and pair_attempts >= 3:
                        dup_skips += 1
                        continue
                    if proposed_by_rule.get(rid, 0) >= _MAX_PROPOSED_PER_RULE:
                        cap_skips += 1
                        deferred.append(rid)
                        continue
                    if a.get("value") and a["value"].startswith(("http://", "https://")):
                        hyp.setdefault("url", a["value"])
                        # host for {host} placeholders (subfinder/nmap/gau…);
                        # port is kept separately so {host}:{port} targets stay
                        # correct (https://h:8443 must scan 8443, not 443).
                        hostport = a["value"].split("://", 1)[1].split("/", 1)[0]
                        hyp.setdefault("host", hostport.split(":", 1)[0])
                        hyp.setdefault("domain",
                                       util.registrable_domain(hostport.split(":", 1)[0]))
                        if ":" in hostport:
                            hyp.setdefault("port", hostport.split(":", 1)[1])
                    elif a.get("value") and a.get("type") == "host":
                        hyp.setdefault("host", a["value"])
                        hyp.setdefault("domain", util.registrable_domain(a["value"]))
                        hyp.setdefault("url", f"https://{a['value']}")
                    if facts.get("param"):
                        hyp.setdefault("param", facts["param"])
                    if facts.get("token"):
                        hyp.setdefault("token", facts["token"])
                    if facts.get("ssrf_url") and facts.get("ssrf_param"):
                        hyp.setdefault("ssrf_url", facts["ssrf_url"])
                        hyp.setdefault("ssrf_param", facts["ssrf_param"])
                    dead = self._broken_tools(hyp)
                    if dead:
                        self.writer.append_event(
                            "mint.tool_broken_skip", a["id"],
                            {"rule_id": rid, "tools": dead,
                             "asset": str(a.get("value", ""))[:120]})
                        dup_skips += 1
                        continue
                    missing = self._unrenderable_slots(hyp)
                    if missing:
                        self.writer.append_event(
                            "mint.placeholder_unsatisfiable", a["id"],
                            {"rule_id": rid, "placeholders": missing,
                             "asset": str(a.get("value", ""))[:120]})
                        dup_skips += 1
                        continue
                    proposed_by_rule[rid] = proposed_by_rule.get(rid, 0) + 1
                    minted_any = True
                    self.writer.upsert_entity(hyp)
                    seen.add(key)
                    budget -= 1
                    if rid in _ENUM_RULES and hyp.get("domain"):
                        enum_domains_in_flight.add((rid, hyp["domain"]))
                a["deferred_rules"] = deferred
                if cap_skips:
                    a["frontier"] = True
                elif minted_any:
                    a["frontier"] = False
                elif a["expansion_count"] >= _MAX_EMPTY_EXPANSIONS:
                    a["frontier"] = False
                else:
                    a["frontier"] = True
            elif a["expansion_count"] >= _MAX_EMPTY_EXPANSIONS:
                a["frontier"] = False
            else:
                a["frontier"] = True     # keep waiting for facts
            self.writer.upsert_entity(a)

    def _fact_view(self, asset: dict, assets: list[dict] | None = None) -> dict:
        assets = assets if assets is not None else self.writer.query_entities(
            kind="asset", engagement_id=self.engagement_id)
        facts: dict = {"url": asset.get("value", ""), "ip": asset.get("ip", "")}
        facts["type"] = asset.get("type", "")
        if asset.get("status_code") is not None:
            facts["status"] = asset.get("status_code")
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
        domain = util.registrable_domain(host)
        facts["domain_enumerated"] = bool(
            domain and assets and any(
                e.get("enumerated_domain") == domain for e in assets))
        # Each enumeration tool contributes a different surface. Legacy
        # generic stamps cannot prove that both URL and DNS enumeration ran.
        completed = {tool for e in assets
                     for tool, dom in (e.get("enumeration_completed") or {}).items()
                     if domain and dom == domain}
        facts["domain_urls_enumerated"] = "gau" in completed
        facts["domain_subdomains_enumerated"] = {"subfinder", "amass"} <= completed
        twoXX = any(
            isinstance(e.get("status_code"), int) and 200 <= e["status_code"] < 300
            and (e.get("value", "").split("://", 1)[1].split("/", 1)[0]
                 .split(":", 1)[0] if "://" in e.get("value", "") else "") == host
            for e in assets)
        facts["host_no_2xx"] = bool(host and not twoXX)
        facts["host_nmapped"] = bool(
            host and assets and any(
                e.get("nmap_host") == host for e in assets))
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
        classes: list = []
        for f in self.writer.query_entities(kind="finding", engagement_id=self.engagement_id):
            if f.get("asset_id") == asset["id"]:
                if f.get("class") and f.get("class") not in classes:
                    classes.append(f.get("class"))
                if f.get("param"):
                    facts.setdefault("param", f.get("param"))
                if f.get("token"):
                    facts.setdefault("token", f.get("token"))
                # A confirmed SSRF carries its own injection point (the nuclei
                # parser writes the pair via util.ssrf_injection_point, which
                # normalises or refuses): R-VULN-SSRF-CHAIN-001 rewrites that
                # ONE query value to reach the cloud metadata service, instead
                # of appending a second `?url=` to a matched-at that already
                # carries a query. Both halves or neither — a base without the
                # parameter name renders a URL that injects nothing.
                if f.get("ssrf_url") and f.get("ssrf_param"):
                    facts.setdefault("ssrf_url", f.get("ssrf_url"))
                    facts.setdefault("ssrf_param", f.get("ssrf_param"))
        facts["class"] = classes
        return facts

    def _prioritize(self) -> list[dict]:
        'Top hypotheses for the ACT beat.'
        hyps = self.writer.query_entities(kind="hypothesis", engagement_id=self.engagement_id, state="proposed")
        hyps = [h for h in hyps if h.get("actions") and not self._cooldown_delay(h)]
        waves = getattr(self, "scan_waves", None)
        hyps.sort(key=waves.score if waves else lambda h: h.get("priority", 0) or 0,
                  reverse=True)

        batch: list[dict] = []
        seen_ids: set[str] = set()
        for cat in ("vuln", "scan", "context", "tech", "injection", "access", "chain"):
            for h in hyps:
                if h["id"] in seen_ids:
                    continue
                if h.get("category") == cat:
                    batch.append(h)
                    seen_ids.add(h["id"])
                    break
        for h in hyps:
            if h["id"] in seen_ids:
                continue
            if len(batch) >= _ACT_K:
                break
            batch.append(h)
            seen_ids.add(h["id"])
        return batch

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
        for hyp in batch:
            opsec_skipped = 0
            render_refused = 0
            if hyp.get("state") != "testing":
                hyp["state"] = "testing"
                self.writer.upsert_entity(hyp)
            started = 0
            run_ids: list[str] = []
            action_runs: dict[int, str] = {}
            action_results: dict[int, dict] = {}
            for index, action in enumerate(hyp.get("actions", [])):
                dependencies = action.get("depends_on", [])
                if (not isinstance(dependencies, list) or any(
                        isinstance(i, bool) or not isinstance(i, int) or i < 0 or i >= index
                        for i in dependencies)):
                    render_refused += 1
                    self.writer.append_event("act.dependency_invalid", hyp["id"],
                                             {"action_index": index})
                    continue
                if any(self.writer.tool_run_status(action_runs.get(i, "")) != "done"
                       for i in dependencies):
                    render_refused += 1
                    self.writer.append_event("act.dependency_blocked", hyp["id"],
                                             {"action_index": index, "depends_on": dependencies})
                    continue
                target = self._action_target(hyp, action)
                if target is None:
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
                recheck = self._guard_target(kind, value)
                if not recheck.allowed:
                    self.writer.append_event("scope_blocked", hyp["id"],
                                             {"target": {kind: value},
                                              "phase": "recheck",
                                              "reason": recheck.reason})
                    continue
                template = action.get("cmd", "")
                if getattr(self, "intensity", "normal") not in ("", "normal"):
                    template = action.get(
                        f"cmd_{self.intensity}") or template
                results = {}
                for dependency in dependencies:
                    results.update(action_results.get(dependency, {}))
                ctx = self._command_ctx(hyp, action, results=results)
                try:
                    rendered = cmd.render_command(template, ctx)
                    r_obs = (cmd.render_command(str(action["obs_url"]), ctx)
                             if action.get("obs_url") else None)
                except (TypeError, ValueError) as exc:
                    render_refused += 1
                    self.writer.append_event("act.template_invalid", hyp["id"],
                        {"action_index": index, "error_type": type(exc).__name__})
                    continue
                supplied = {str(k).lower() for k in ctx}
                unknown = [n
                           for tpl in (template, str(action.get("obs_url") or ""))
                           for n in cmd.placeholder_names(tpl)
                           if n.lower() not in supplied]
                if unknown:
                    render_refused += 1
                    self.writer.append_event("act.placeholder_refused",
                                             hyp["id"], {
                         "tool": action.get("tool"),
                         "placeholders": sorted(set(unknown)),
                         "command": rendered.summary})
                    continue
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
                action_runs[index] = run_id
                payload = {**action, "command": rendered.summary,
                           "argv": rendered.argv, "env": rendered.env,
                           "secret_bindings": rendered.secret_bindings,
                           "bind_ip": recheck.detail.get("bind_ip"),
                           "_tool_run_id": run_id}
                # The executor's success contract is judged against the
                # template that was RENDERED, not the rule's default one: a
                # stealth run executes cmd_stealth, and a parser that reads
                # `cmd` to recognize its own invocation would otherwise grade
                # an argv it never saw.
                payload["cmd"] = template
                if r_obs:
                    if r_obs.argv and r_obs.argv[0]:
                        # collapse "//" in the path: a seed value with a
                        # trailing slash must not mint ...com//robots.txt
                        payload["url"] = re.sub(r"(?<!:)/{2,}", "/",
                                                r_obs.argv[0])
                try:
                    self.executor(hyp, payload)
                except Exception as exc:
                    self.writer.finish_tool_run(run_id, status="error", exit_code=-2)
                    self.writer.append_event("act.executor_error", hyp["id"],
                        {"run_id": run_id, "tool": action.get("tool"),
                         "error_type": type(exc).__name__})
                action_results[index] = self._sync_runs(
                    [run_id], action={**action, "cmd": template})
            if run_ids:
                try:
                    self._sync_runs(run_ids)
                except Exception:
                    self.writer.append_event(
                        "sync_runs_failed", hyp["id"],
                        {"run_ids": run_ids[:10]})
            self._retire_hypothesis_if_complete(
                hyp, expected=started, opsec_blocked=opsec_skipped,
                run_ids=run_ids, render_refused=render_refused)

    def _retire_hypothesis_if_complete(self, hyp: dict, *,
                                       expected: int | None = None,
                                       opsec_blocked: int = 0,
                                       run_ids: list[str] | None = None,
                                       render_refused: int = 0) -> None:
        'Move a testing hypothesis to a terminal state when every run the\n        last _act loop STARTED for it is terminal. Never raises.'
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
                # per action (scope_blocked / opsec_*_skip /
                # act.placeholder_refused).
                cur = self.writer.get_entity(hyp["id"])
                if cur and cur.get("kind") == "hypothesis" and \
                        cur.get("state") == "testing":
                    if render_refused:
                        self._bump_rule_attempts(hyp)
                        cur["state"] = "error"
                        cur["render_refused"] = render_refused
                    elif opsec_blocked:
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
            if "error" in statuses or render_refused:
                final = "error"
            elif "timeout" in statuses:
                final = "timeout"
            else:
                final = "done"
            if final in ("error", "timeout"):
                self._bump_rule_attempts(hyp)
            cur = self.writer.get_entity(hyp["id"])
            if cur and cur.get("kind") == "hypothesis" and \
                    cur.get("state") == "testing":
                cur["state"] = final
                cur["finished_at"] = util.now_iso()
                self.writer.upsert_entity(cur)
                if final == "done":
                    self._maybe_mint_on_hit(cur)
        except Exception as e:
            try:
                self.writer.append_event(
                    "hypothesis_retire_error", str(hyp.get("id") or "?"),
                    {"rule_id": hyp.get("rule_id"), "error": repr(e)})
            except Exception:
                pass

    def _hypothesis_hit(self, hyp_id: str, required_class: str | None = None) -> bool:
        "        General discovery queries accept findings or reachable assets. Class\n        attribution requires matching parser evidence from a successful run;\n        an HTTP 200 alone proves no vulnerability. Aliases below are narrow\n        parser contracts, not substring matches or a model's interpretation.\n        "
        try:
            rows = self.writer.conn.execute(
                "SELECT o.new_asset_ids, o.new_finding_ids, t.status "
                "FROM observations o JOIN tool_run t ON o.action_id = t.id "
                "WHERE t.hypothesis_id = ? AND o.engagement_id = ?",
                (hyp_id, self.engagement_id)).fetchall()
        except Exception:
            return False
        for r in rows:
            try:
                fids = json.loads(r["new_finding_ids"] or "[]")
                if required_class:
                    if r["status"] != "done":
                        continue
                    aliases = {
                        "sqli.confirmed": {("sqli", "sqlmap")},
                        "xss.confirmed": {("xss.reflected", "dalfox")},
                        "misconfig.api_docs": {("exposure.swagger", "nuclei")},
                    }
                    for fid in fids:
                        finding = self.writer.get_entity(str(fid))
                        if not finding or finding.get("kind") != "finding":
                            continue
                        pair = (finding.get("class"), finding.get("detector"))
                        if finding.get("class") == required_class or pair in aliases.get(required_class, set()):
                            return True
                    continue
                if fids:
                    return True
                aids = json.loads(r["new_asset_ids"] or "[]")
            except (ValueError, TypeError):
                continue          # corrupt evidence = no evidence
            for aid in aids:
                a = self.writer.get_entity(str(aid))
                if not a or a.get("kind") != "asset":
                    continue
                try:
                    sc = int(a.get("status_code"))
                except (TypeError, ValueError):
                    continue
                if 200 <= sc <= 299:
                    return True
        return False

    def _maybe_mint_on_hit(self, hyp: dict) -> None:
        ''
        try:
            cls = hyp.get("on_hit_class")
            if not isinstance(cls, str) or not cls:
                return
            if not self._hypothesis_hit(str(hyp["id"]), required_class=cls):
                return
            aid = hyp.get("asset_id")
            asset = self.writer.get_entity(aid) if aid else None
            url = str(hyp.get("url") or "")
            if not url and asset and asset.get("kind") == "asset" and \
                    asset.get("type") == "url":
                url = str(asset.get("value") or "")
            if not url:
                self.writer.append_event(
                    "rule_hit_class_skipped", hyp["id"],
                    {"rule_id": hyp.get("rule_id"), "class": cls,
                     "reason": "no_url"})
                return
            f = {
                "id": util.new_id("finding"),
                "kind": "finding",
                "state": "candidate",
                "class": cls,
                "title": f"rule hit: {cls} ({hyp.get('rule_id') or 'unknown'})",
                "url": url,
                "param": None,
                "sink": None,
                "severity": "unknown",
                "detector": str(hyp.get("rule_id") or "on_hit_class"),
                "signals": [],
                "engagement_id": self.engagement_id,
            }
            if aid:
                f["asset_id"] = aid
            f["confidence"] = confidence.prior_for(f["detector"])
            f["dedup_key"] = compute_dedup_key(f)
            fid = self._ingest_finding(f)
            self.writer.append_event(
                "rule_hit_class", hyp["id"],
                {"rule_id": hyp.get("rule_id"), "class": cls,
                 "finding_id": fid, "asset_id": aid, "url": url})
        except Exception as e:
            try:
                self.writer.append_event(
                    "rule_hit_class_error", str(hyp.get("id") or "?"),
                    {"error": repr(e)})
            except Exception:
                pass

    def _bump_rule_attempts(self, hyp: dict) -> None:
        ''
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
        except Exception as e:
            # The failure of THIS guard re-opens the infinite re-mint it
            # exists to prevent — it must be observable, never silent.
            try:
                self.writer.append_event(
                    "rule_attempts_bump_error", str(hyp.get("id") or "?"),
                    {"rule_id": hyp.get("rule_id"),
                     "asset_id": hyp.get("asset_id"), "error": repr(e)})
            except Exception:
                pass

    def _command_ctx(self, hyp: dict, action: dict, *, results: dict | None = None) -> dict:
        '        Only the known target/credential keys are handed to the renderer;\n        action-level values win over hypothesis-level ones. ``wordlist_dir``\n        is injected here so rule JSONs never carry absolute home paths:\n        they reference ``{wordlist_dir}/<file>``, the directory comes from\n        ``MOTOKO_WORDLIST_DIR`` (default ``~/.motoko/wordlists``).\n        '
        ctx = {key: value for key, value in (results or {}).items() if key in cmd.CTX_KEYS}
        for source in (hyp, action):
            for key in cmd.CTX_KEYS:
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
        if "out" not in ctx:
            # bare-constructed orchestrators (legacy tests) carry no
            # artifacts dir — fall back to the system temp dir.
            art = getattr(self, "artifacts", None) or Path(
                os.environ.get("TMPDIR", "/tmp"))
            out_dir = art / f"out-{hyp.get('id', 'x')}"
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            ctx["out"] = str(out_dir)
        if "oob" not in ctx and getattr(self, "oob_domain", ""):
            ctx["oob"] = f"http://{self.oob_domain}/{hyp.get('id', 'x')[-8:]}"
        return ctx

    def _broken_tools(self, hyp: dict) -> list[str]:
        """The candidate's tools, if EVERY one of them is known-unrunnable.

        Empty means "propose it": a rule with one dead and one live action still
        has something to do, so partial capability goes ahead and the dead
        action fails on its own — attributed by the executor's
        ``tool_run.broken_wrapper`` event rather than silently.
        """
        broken = set(getattr(self.executor, "broken_tools", None) or ())
        if not broken:
            return []
        tools = {str(act.get("tool") or "")
                 for act in (hyp.get("actions") or [])
                 if isinstance(act, dict)}
        tools.discard("")
        if not tools or not tools <= broken:
            return []
        return sorted(tools)

    def _unrenderable_slots(self, hyp: dict) -> list[str]:
        "Placeholder names ACT could never render for this hypothesis.\n\n        Returns the missing names, sorted and de-duplicated across the rule's\n        actions; empty means every action can render.\n        "
        missing: set[str] = set()
        stealth = getattr(self, "intensity", "normal") not in ("", "normal")
        actions = hyp.get("actions") or []
        for index, action in enumerate(actions):
            if not isinstance(action, dict):
                continue
            template = action.get("cmd", "")
            if stealth:
                template = action.get(f"cmd_{self.intensity}") or template
            supplied = {str(k).lower() for k in self._command_ctx(hyp, action)}
            supplied.update(dependency_context_keys(
                actions, index, getattr(self, "intensity", "normal")))
            for tpl in (template, str(action.get("obs_url") or "")):
                for name in cmd.placeholder_names(tpl):
                    if name.lower() not in supplied:
                        missing.add(name.lower())
        return sorted(missing)

    def _action_target(self, hyp: dict, action: dict) -> tuple[str, str] | None:
        ''
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
        '        Runs once per cycle, BEFORE ``_prioritize()``, so a hypothesis recycled\n        out of ``testing`` can re-enter the ACT batch in the same run instead of\n        waiting for the next invocation. The end-of-run health sweep is too late\n        for that — it only ever helped the *next* run.\n\n        Never fails the run: a recovery pass is an optimization, and a locked\n        or half-written graph must not take the loop down with it.\n        '
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
        cycle = getattr(self, "cycle", 0)
        if not force:
            last = getattr(self, "_last_reflect_cycle", None)
            if last is not None and cycle - last < _REFLECT_IDLE_GAP:
                return
        self._last_reflect_cycle = cycle
        try:
            if self._reflector_takes_failures:
                lines = (self._failure_digest.prompt_lines()
                         if self._failure_digest is not None else [])
                waves = getattr(self, "scan_waves", None)
                if waves is not None:
                    lines.extend(waves.prompt_lines())
                self.reflector(self.propose_view, self.engagement_id,
                               failure_lines=lines)
                return
            self.reflector(self.propose_view, self.engagement_id)
        except Exception as exc:
            self.writer.append_event("reflector.error", self.engagement_id,
                                     {"error_type": type(exc).__name__})

    # -- checkpoint / summary -----------------------------------------
    def _checkpoint(self) -> None:
        self.writer.commit()
        try:
            (self.edir / "opsec-cooldowns.json").write_text(
                json.dumps(self._cooldowns.snapshot(), ensure_ascii=False))
        except Exception as e:
            # A persist failure means the next restart silently lifts every
            # WAF cooldown — observable, still never fatal to the loop.
            try:
                self.writer.append_event(
                    "opsec_cooldown_persist_error", self.engagement_id,
                    {"error": repr(e)})
            except Exception:
                pass
        digest.write_digest(self.writer, self.engagement_id, self.edir / "digest.md")

    def _summary(self) -> dict:
        f = self.writer.query_entities(kind="finding", engagement_id=self.engagement_id)
        h = self.writer.query_entities(kind="hypothesis", engagement_id=self.engagement_id)
        from collections import Counter
        delays = [self._cooldown_delay(x) for x in h
                  if (x.get("state") or "proposed") == "proposed"]
        return {
            "cycle": self.cycle,
            "findings": len(f),
            "by_state": dict(Counter(x.get("state") for x in f)),
            "hypotheses": len(h),
            "stop_reason": getattr(self, "stop_reason", "not_started"),
            "pending": len(self._live_hypotheses()),
            "retry_after_s": round(min((d for d in delays if d > 0), default=0), 1),
            "waves": self.scan_waves.history,
        }

    def _default_executor(self, hyp: dict, action: dict) -> None:
        """Fail visibly when the caller did not configure an executor."""
        self.writer.record_observation(
            tool=action["tool"], engagement_id=self.engagement_id, raw_path=None,
            parsed_summary="executor is not configured",
            action_id=action.get("_tool_run_id"), exit_code=-2,
            url=action.get("url") or hyp.get("url"),
            host=action.get("host") or hyp.get("host"),
        )
        self.writer.finish_tool_run(action["_tool_run_id"], status="error", exit_code=-2)

    def close(self) -> None:
        reap = getattr(self.executor, "reap", None)
        if callable(reap):
            reap()
        # A canary manager owns a long-lived interactsh-client session, so it
        # must not outlive the engine either. It stops by the PID it recorded
        # at launch (its own process group) — never by matching a command line,
        # which would also match whatever ran the match.
        close_canary = getattr(self.canary, "close", None)
        if callable(close_canary):
            try:
                close_canary()
            except Exception:      # noqa: BLE001 - shutdown must never raise
                pass
        self.writer.close()


def default_canary(engagement_id: str):
    "The interactsh-backed canary manager for a run, or None.\n\n    Lives here, next to ``default_fetcher``, because both engine entry points\n    (``cli.cmd_run`` and ``adapter.dispatch``) call ``run_engagement``: a\n    canary wired only into the CLI would make the same engine two different\n    engines depending on who launched it.\n\n    The session starts lazily on the first ``issue()`` — a run that never\n    verifies an OOB finding never spawns a poller — and is closed by\n    ``Orchestrator.close()`` through ``run_engagement``'s finally.\n    "
    from .verification.interactsh import InteractshCanary

    edir = db.engagement_dir(db.default_root(), engagement_id)
    mgr = InteractshCanary(workdir=edir / "obs" / "canary")
    return mgr if mgr.resolve_binary() else None


def run_engagement(engagement_id: str, *, max_cycles: int = 20,
                   wave_cycles: int = 5, max_waves: int | None = None,
                   timeout: float = 300, rules_dir=None, reflector=None,
                   canary=None) -> dict:
    """Shared operator/adapter entry; one scheduler, executor and writer lease."""
    from .executor import SubprocessExecutor

    orch = Orchestrator(engagement_id, rules_dir=rules_dir, reflector=reflector,
                        canary=canary)
    try:
        orch.executor = SubprocessExecutor(orch.writer, orch.engagement_id,
                                          orch.artifacts, tool_timeout=timeout)
        return orch.run(max_cycles=max_cycles, wave_cycles=wave_cycles, max_waves=max_waves)
    finally:
        orch.close()
