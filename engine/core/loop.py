"""Feedback loop module — wave-driven audit/adjudicate cycle, engine-native.

The loop is the feedback regulator of MOTOKO itself: after every run wave
(or tooling change), the engine bundles its own code + wave graph data,
sends the bundle to N auditor legs — each through its own analysis lens
(``LENS_NAMES``), so ONE substrate still yields genuinely different failure
modes — aggregates the audit reports, and has one adjudicator rank the
findings into a fix list. The fix list lands under ``plans/`` and feeds the
next wave.

Generic by construction:
* No vendor or model name is hardcoded. Every model is an
  ``LLMEndpoint`` supplied by a config file (default ``~/.motoko/loop.yaml``)
  or the environment; the engine only speaks protocols
  (openai-chat / anthropic-messages / cli-subprocess).
* Prompt templates are vendor-neutral.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import db, util

DEFAULT_CONFIG = Path.home() / ".motoko" / "loop.yaml"

_CLI_ARGV_LIMIT = 100_000
_TRUNCATION_MARKER = (
    "\n\n[...BUNDLE TRUNCATED: {cut} bytes removed to fit the CLI argv "
    "limit. This is a PREFIX of the bundle — audit what is visible and say "
    "so explicitly in your report...]\n")


def default_config_path() -> Path:
    """Loop-config resolution order (ARCHITECTURE.md config layering):

    1. ``$MOTOKO_CONFIG`` — explicit override, wins over everything;
    2. ``<motoko_root>/engine/loop/loop.yaml`` — in-tree live config (TRACKED
       in git since 8d0879c, not gitignored: it carries the operator's real
       ``base_url``, but no secret — ``api_key_env`` holds a variable NAME);
    3. ``~/.motoko/loop.yaml`` — legacy home location, kept so
       pre-consolidation setups and shepherded runs keep working.
    """
    env = os.environ.get("MOTOKO_CONFIG")
    if env:
        return Path(env).expanduser()
    in_tree = util.motoko_root() / "engine" / "loop" / "loop.yaml"
    if in_tree.exists():
        return in_tree
    return DEFAULT_CONFIG


def _expand_value(value: str) -> str:
    """Expand ``${VAR}`` from the environment and a leading ``~/``.

    Unset variables are a hard error — a loop leg silently pointing at a
    literal ``${UNSET}`` base_url would fail much later and much further
    from the cause. For ``api_key_env``, expansion selects the variable
    *name*; ``LLMEndpoint.resolve_key`` reads its secret only at call time.
    """
    def _lookup(m: re.Match) -> str:
        var = m.group(1)
        v = os.environ.get(var)
        if v is None:
            raise ValueError(
                f"loop config references unset environment variable: {var}")
        return v

    out = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", _lookup, value)
    if out.startswith("~"):
        out = str(Path(out).expanduser())
    return out

_OPEN_CONFIRMED_STATES = frozenset({"verified", "exploitable"})

# Directories the pyflakes metric walks past. `strix-patches` holds vendored
# deploy patches anchored by hash — a finding there is not ours to fix in place
# — and the two others are build artefacts. Same set as
# tests/test_lint_engine.py's EXCLUDE_PARTS; keep them in step.
_LINT_EXCLUDE_PARTS = frozenset({"strix-patches", "__pycache__", "build"})

_SUITE_TIMEOUT_S = 600


class LoopError(RuntimeError):
    """Base class for loop execution errors."""


class LoopEvaluationError(LoopError):
    """The deterministic EVALUATE beat failed.

    Never silent: the error is archived into verdict.json (action=ERROR)
    and raised, so callers exit non-zero instead of mistaking a broken
    evaluation for a converged loop.
    """


class LoopRollbackError(LoopError):
    """A ROLLBACK verdict could not be executed safely."""


def _load_prompt(name: str) -> str:
    'Single source of truth: docs/loop-prompts/<name> wins when present.'
    doc = util.motoko_root() / "engine" / "docs" / "loop-prompts" / name
    try:
        text = doc.read_text()
        if text.strip():
            return text
    except OSError:
        pass
    fallback = {
        "audit.md": AUDIT_PROMPT,
        "adjudicate.md": ADJUDICATE_PROMPT,
    }
    fallback.update({f"audit-{lens}.md": text
                     for lens, text in LENS_PROMPTS.items()})
    return fallback[name]


ADJUDICATE_PROMPT = """\
You are the loop adjudicator of the penetration engine. N audit legs have
reviewed the same code and data through different lenses (e.g. coverage
breadth, adversarial verification); their reports follow below, each
section labeled with the leg name and its lens. On ONE substrate,
cross-lens corroboration is WEAKER than cross-vendor independent discovery
(the blind spots are correlated) — label consensus accordingly. Adjudicate:

1. Dedup and merge (pointer-level): every finding keeps its source label;
   merging never erases a leg's original judgment; a single-leg HIGH is
   never dropped — mark its consensus low and hand it to VERIFY.
2. Fix scope: only the watershed items — those deciding whether the next
   wave's data carries information — enter this round; schedule the rest.
3. Order fixes by the dependency chain (P0 dependency ordering is not
   bound by the "no reordering" constraint).
4. Output a strict fix list; per item: id / one-line content / why this
   position in the order.
5. Every item MUST carry: severity (P0|HIGH|MEDIUM|LOW), evidence
   (file:line or data reference, never vague), consensus (which audit
   lenses corroborate it, e.g. "both" / "a leg only" / "single"). You hold
   orchestration authority only — never final judgment on truth.

Output JSON on the LAST line (the rest is free-form); each fixes item strictly:
{"verdict": "go|no_go", "fixes": [{"id": "...", "summary": "...",
  "severity": "P0|HIGH|MEDIUM|LOW", "evidence": "file:line", "consensus": "both"}],
 "deferred": [{"id": "...", "when": "..."}]}
"""


_AUDIT_HEADER = """\
You are a senior code auditor. Audit the LANDED code implementation of this
repository (not a design draft), independently. Your report is deduplicated
and merged by the convergence model and drives the next round of fixes.

## The report MUST be organized on two axes (skilleval-20260914 ruling, STANDING)

Every finding carries an axis label; both axes look at the same material —
never report on only one:

- **[axis:standards]** — violates this repo's discipline: the internal design notes execution
  discipline (anti-patterns / OPSEC invariants), known the internal design notes, existing
  architecture contracts.
- **[axis:spec]** — deviates from this round's task intent: whether the task
  brief / fix list was faithfully implemented (including "fixed but fixed
  wrong").

A finding that fits no axis goes under [axis:spec] with the reason stated in
the body.
"""

_AUDIT_FOCUS_GENERIC = """\
# Audit focus

1. Scheduling correctness (priority / quota / budget / starvation)
2. Rule-firing correctness (misfires / explosions / broken chains)
3. Parsing and graph integrity (the tool output -> asset/finding chain is
   complete)
4. Security boundaries (scope guard, injection surface, defense in depth)
5. Conflicts between new code and existing behavior (miss keep-alive,
   frontier re-open, the F-series invariants)
"""

_AUDIT_FOCUS_BREADTH = """\
# Audit focus (lens: coverage breadth — what did this round MISS)

1. Untouched surfaces: which assets / endpoints / rules saw no tool or leg
   coverage this wave
2. Scheduling blind spots: which hypotheses were starved by priority /
   quota / budget; frontiers that should have re-opened and did not
3. Broken chains: where the tool output -> asset/finding parsing chain
   silently drops data
4. Silent rules: rules that should have fired and did not (conditions too
   narrow, missing dependencies, misses not kept alive)
5. Boundary gaps: corners of the scope guard, injection surface and defense
   in depth that no existing check covers

Division of labor: adversarial verification of evidence belongs to the
adversarial lens — do not challenge existing findings point by point;
focus on "where nobody looked". Findings belonging to other lenses get a
brief note, not an expansion.
"""

_AUDIT_FOCUS_ADVERSARIAL = """\
# Audit focus (lens: adversarial verification — does what was SAID hold up)

1. Challenge every evidence chain: is each finding/hypothesis's evidence
   reproducible, or overclaimed
2. False-positive hunt: misfires, parsing mismatches, tool noise reported
   as findings
3. "Fixed but fixed wrong": items from the fix list that were implemented
   incorrectly or introduced new conflicts
4. Invariant conflicts: contradictions between new code and existing
   behavior (miss keep-alive, frontier re-open, the F-series invariants)
5. Boundary pressure: can the scope guard and the write approvals be
   bypassed on real call paths

Division of labor: coverage breadth belongs to the breadth lens — do not
enumerate untouched surfaces; focus on challenging "what has already been
said". Findings belonging to other lenses get a brief note, not an
expansion.
"""

_AUDIT_FOCUS_DISCIPLINE = """\
# Audit focus (lens: repository discipline — deep pass on the standards axis)

1. the internal design notes execution-discipline violations: the anti-pattern list, OPSEC
   invariants, write-approval boundaries
2. the internal design notes re-enactments: does new code replay a recorded mechanism
   (including ones in the retired index)
3. Architecture-contract drift: module boundaries, data/code separation,
   directory and naming semantics — still holding?
4. Gate bypasses: are test / lint / export gates short-circuited by
   exceptions, skips or ignore rules
5. Discipline debt: rules promised in documents and ledgers but never
   landed in code

Division of labor: the other lenses own their specialties — findings
belonging to them get a brief note, not an expansion.
"""

_AUDIT_FOCUS_INTENT = """\
# Audit focus (lens: task-intent fidelity — deep pass on the spec axis)

1. Walk the task brief / fix list item by item: was each faithfully
   implemented
2. Fixed but fixed wrong: did a fix introduce a new semantic drift, or only
   change the surface
3. Half-fixes and silent abandonment: items claimed done but untouched, or
   only partly implemented
4. Intent-level conflicts: does the implementation approach contradict a
   design decision stated in the task brief
5. Acceptance drift: was "done" proven with the gate/command the task brief
   named

Division of labor: the other lenses own their specialties — findings
belong to them get a brief note, not an expansion.
"""

_AUDIT_FOCUS_INVARIANTS = """\
# Audit focus (lens: regression and invariants)

1. Conflicts between new code and existing behavior: miss keep-alive,
   frontier re-open, the F-series invariants
2. State-machine integrity: every legal hypothesis/finding transition is
   still reachable and reversible
3. Regression surface: which existing paths does the change touch, and do
   tests actually cover them
4. Data integrity: do the graph / persistence / seal paths still satisfy
   foreign keys, manifests and hash chains under the new code
5. Compatibility: do config/CLI contract changes silently break old
   deployment shapes

Division of labor: the other lenses own their specialties — findings
belonging to them get a brief note, not an expansion.
"""

_AUDIT_FOCUS_RESOURCES = """\
# Audit focus (lens: concurrency and resources)

1. Races: shared state across threads / processes / legs, timing of
   concurrent file writes
2. Slot and budget accounting: do concurrency ceilings, quotas and budget
   bookkeeping match actual behavior
3. Descriptor leaks: sockets / pipes / file handles left unclosed (the
   ResourceWarning class)
4. Timeout semantics: does every network/subprocess call carry an explicit
   timeout, and is the post-timeout state recoverable
5. Disk pressure: /tmp usage, artifact cleanup paths, behavior when the
   quota is hit

Division of labor: the other lenses own their specialties — findings
belonging to them get a brief note, not an expansion.
"""

_AUDIT_FORMAT = """\
# Output format

- Number every finding (e.g. B1/A1/S1) with severity (P0/P1/P2) and axis
  ([axis:standards]/[axis:spec]).
- Each finding carries a `file:line` reference, its trigger condition and
  a one-line fix direction.
- End with a ranking of the "5 most lethal".
- The final line states the verdict: this round may continue (0 P0s) or N
  items must be fixed first.
"""


def _compose_audit_prompt(focus: str) -> str:
    return _AUDIT_HEADER + "\n" + focus + "\n" + _AUDIT_FORMAT


AUDIT_PROMPT = _compose_audit_prompt(_AUDIT_FOCUS_GENERIC)

LENS_PROMPTS = {
    "breadth": _compose_audit_prompt(_AUDIT_FOCUS_BREADTH),
    "adversarial": _compose_audit_prompt(_AUDIT_FOCUS_ADVERSARIAL),
    "discipline": _compose_audit_prompt(_AUDIT_FOCUS_DISCIPLINE),
    "intent": _compose_audit_prompt(_AUDIT_FOCUS_INTENT),
    "invariants": _compose_audit_prompt(_AUDIT_FOCUS_INVARIANTS),
    "resources": _compose_audit_prompt(_AUDIT_FOCUS_RESOURCES),
}
LENS_NAMES = tuple(LENS_PROMPTS)


def _audit_prompt_name(lens: str) -> str:
    """Per-leg prompt file: a known lens gets its own brief; anything else
    (including the empty default) falls back to the generic audit brief."""
    return f"audit-{lens}.md" if lens in LENS_NAMES else "audit.md"


@dataclass
class LLMEndpoint:
    """One model endpoint. Protocol + credentials come from config, never
    from the engine."""

    name: str
    protocol: str                      # openai | anthropic | cli
    model: str = ""
    base_url: str = ""
    api_key_env: str = ""              # env var holding the key
    command: list[str] = field(default_factory=list)   # protocol=cli
    # cli legs: flag that accepts a prompt FILE path (e.g. --prompt-file).
    # Empty = the CLI only takes the prompt as an argv value, so oversized
    # bundles are truncated loudly instead of dying with E2BIG.
    prompt_file_flag: str = ""
    timeout: int = 1800
    lens: str = ""

    def resolve_key(self) -> str:
        if not self.api_key_env:
            return ""
        return os.environ.get(self.api_key_env, "")

    @classmethod
    def from_dict(cls, d: dict, name: str | None = None) -> "LLMEndpoint":
        return cls(
            name=d.get("name") or name or "endpoint",
            protocol=d.get("protocol", "openai"),
            model=str(d.get("model", "")),
            base_url=str(d.get("base_url", "")),
            api_key_env=str(d.get("api_key_env", "")),
            command=[str(c) for c in (d.get("command") or [])],
            prompt_file_flag=str(d.get("prompt_file_flag", "")),
            lens=str(d.get("lens", "")),
            timeout=int(d.get("timeout", 1800)),
        )


def load_loop_config(path: Path | None = None) -> dict:
    """Load the loop config (YAML-ish: we accept a minimal flat JSON too).

    Expected shape::

        {"auditors": [ {endpoint...}, ... ], "adjudicator": {endpoint...}}
    """
    cfg_path = path or default_config_path()
    if not cfg_path.exists():
        return {}
    text = cfg_path.read_text()
    if cfg_path.suffix in (".json",):
        return json.loads(text)
    return _parse_minimal_yaml(text)


def _parse_minimal_yaml(text: str) -> dict:
    """Tiny YAML subset: top-level lists of flat key: value maps.

    Enough for loop.yaml without a PyYAML dependency (stdlib-only engine).
    """
    out: dict = {}
    current: str | None = None
    current_list: list[dict] = []
    current_map: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*$", line)
        if m:                              # top-level key:
            if current is not None:
                _commit_section(out, current, current_list, current_map)
            current = m.group(1)
            current_list, current_map = [], {}
            continue
        m = re.match(r"^-\s+name:\s*(.+)$", line)
        if m:                              # list item start
            current_map = {"name": m.group(1)}
            current_list.append(current_map)
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.+)$", line)
        if m:                              # key: value in current item/map
            key, value = m.group(1), m.group(2).strip()
            value = value.strip("\"'")
            value = _expand_value(value)
            if key == "api_key_env" and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
                raise ValueError("api_key_env must resolve to an environment variable name")
            if key == "command":
                if value.startswith("["):
                    try:
                        parsed = json.loads(value)
                    except json.JSONDecodeError:
                        inner = value.strip("[]")
                        parsed = [x.strip().strip("'\"")
                                  for x in inner.split(",") if x.strip()]
                    current_map[key] = [str(x) for x in parsed]
                else:
                    current_map[key] = shlex.split(value)
                # the whole-value expansion above cannot reach a leading "~"
                # inside the list (the value starts with "[") — expand per
                # entry, or a cli leg would exec a literal "~/.local/bin/..."
                current_map[key] = [os.path.expanduser(x)
                                    for x in current_map[key]]
            elif key in ("timeout",):
                current_map[key] = int(value)
            else:
                current_map[key] = value
    _commit_section(out, current, current_list, current_map)
    return out


def _commit_section(out: dict, name: str | None, items: list, single: dict) -> None:
    if name is None:
        return
    if items:
        out[name] = items
    elif single:
        out[name] = single


# -- protocol adapters --------------------------------------------------

def call_endpoint(ep: LLMEndpoint, prompt: str) -> dict:
    """Call one endpoint leg.

    Every protocol returns ONE dict shape so per-leg telemetry needs no
    isinstance dance: {"text", "duration_ms", "usage": {"input_tokens",
    "output_tokens"}, "stop_reason"}, and a cli leg adds {"exit_code",
    "stderr"} because its failure metadata must survive into leg-meta.json
    instead of being collapsed into the report text. usage is read off the
    wire when the lane reports it (anthropic: message_start /
    message_delta events; openai: a stream_options.include_usage chunk)
    and stays None-valued when the lane does not report — telemetry is
    measured, never fabricated.
    """
    if ep.protocol == "openai":
        return _call_openai(ep, prompt)
    if ep.protocol == "anthropic":
        return _call_anthropic(ep, prompt)
    if ep.protocol == "cli":
        return _call_cli(ep, prompt)
    raise ValueError(f"unknown protocol {ep.protocol!r}")


def _call_openai(ep: LLMEndpoint, prompt: str) -> dict:
    started = time.monotonic()
    body = json.dumps({
        "model": ep.model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
        # ask the lane for a final usage chunk; a lane that ignores the
        # option simply never sends one and usage stays None
        "stream_options": {"include_usage": True},
    }).encode("utf-8")
    req = urllib.request.Request(
        ep.base_url.rstrip("/") + "/chat/completions", data=body,
        headers={"Authorization": f"Bearer {ep.resolve_key()}",
                 "Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    parts: list[str] = []
    usage: dict = {"input_tokens": None, "output_tokens": None}
    stop_reason = None
    with opener.open(req, timeout=ep.timeout) as resp:
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                ev = json.loads(payload)
            except json.JSONDecodeError:
                continue
            choices = ev.get("choices") or []
            if choices:
                delta = choices[0].get("delta") or {}
                content = delta.get("content")
                if content:
                    parts.append(content)
                if choices[0].get("finish_reason"):
                    stop_reason = choices[0]["finish_reason"]
            u = ev.get("usage")
            if u:
                usage = {"input_tokens": u.get("prompt_tokens"),
                         "output_tokens": u.get("completion_tokens")}
    return {"text": "".join(parts),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "usage": usage, "stop_reason": stop_reason}


def _call_anthropic(ep: LLMEndpoint, prompt: str) -> dict:
    started = time.monotonic()
    body: dict = {
        "model": ep.model,
        "max_tokens": 40960,
        "stream": True,
        "messages": [{"role": "user", "content": prompt}],
    }
    body["thinking"] = {"type": "enabled", "budget_tokens": 8192}
    wire = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        ep.base_url.rstrip("/") + "/v1/messages", data=wire,
        headers={"x-api-key": ep.resolve_key(),
                  "anthropic-version": "2023-06-01",
                  "Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    parts: list[str] = []
    usage: dict = {"input_tokens": None, "output_tokens": None}
    stop_reason = None
    with opener.open(req, timeout=ep.timeout) as resp:
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            try:
                ev = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
            etype = ev.get("type")
            if etype == "content_block_delta":
                d = ev.get("delta") or {}
                if d.get("type") == "text_delta":
                    parts.append(d.get("text", ""))
            elif etype == "message_start":
                u = (ev.get("message") or {}).get("usage") or {}
                if u.get("input_tokens") is not None:
                    usage["input_tokens"] = u["input_tokens"]
                if u.get("output_tokens") is not None:
                    usage["output_tokens"] = u["output_tokens"]
            elif etype == "message_delta":
                # message_delta carries the CUMULATIVE output_tokens and
                # the terminal stop_reason — overwrite, never add.
                u = ev.get("usage") or {}
                if u.get("output_tokens") is not None:
                    usage["output_tokens"] = u["output_tokens"]
                d = ev.get("delta") or {}
                if d.get("stop_reason"):
                    stop_reason = d["stop_reason"]
            elif etype == "message_stop":
                break
    return {"text": "".join(parts),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "usage": usage, "stop_reason": stop_reason}


def _call_cli(ep: LLMEndpoint, prompt: str) -> dict:
    'Run a cli-protocol leg. Returns the transcript plus meta (exit code,\n    stderr) so a failed leg is archived instead of silently half-reported.'
    if not ep.command:
        raise ValueError("cli endpoint needs a command list")
    started = time.monotonic()
    if ep.prompt_file_flag:
        fd, ppath = tempfile.mkstemp(prefix="motoko-prompt-",
                                      suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(prompt)
            proc = subprocess.run(
                [*ep.command, ep.prompt_file_flag, ppath],
                capture_output=True, text=True, timeout=ep.timeout)
        finally:
            try:
                os.unlink(ppath)
            except OSError:
                pass
        return {"text": proc.stdout or proc.stderr,
                "exit_code": proc.returncode, "stderr": proc.stderr,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "usage": {"input_tokens": None, "output_tokens": None},
                "stop_reason": None}
    sent = prompt
    size = len(prompt.encode("utf-8", "replace"))
    if size > _CLI_ARGV_LIMIT:
        cut = size - _CLI_ARGV_LIMIT
        sent = (prompt.encode("utf-8", "replace")[:_CLI_ARGV_LIMIT]
                .decode("utf-8", "ignore")
                + _TRUNCATION_MARKER.format(cut=cut))
    proc = subprocess.run(
        [*ep.command, sent], capture_output=True, text=True,
        timeout=ep.timeout)
    return {"text": proc.stdout or proc.stderr,
            "exit_code": proc.returncode, "stderr": proc.stderr,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "usage": {"input_tokens": None, "output_tokens": None},
            "stop_reason": None}


# -- loop orchestration -------------------------------------------------

class LoopRunner:
    """One wave-loop round: bundle -> auditors -> adjudicator -> fix list."""

    def __init__(self, engagement_id: str, *, root: Path | None = None,
                 config: dict | None = None, rules_dir: Path | None = None,
                 engine_root: Path | None = None):
        self.engagement_id = engagement_id
        self.root = root or db.default_root()
        self.rules_dir = rules_dir or (
            Path(engine_root) / "rules" if engine_root
            else util.default_rules_dir())
        self.engine_root = engine_root or Path(__file__).resolve().parents[1]
        cfg = config or load_loop_config()
        self.auditors = [LLMEndpoint.from_dict(d, f"auditor-{i + 1}")
                         for i, d in enumerate(cfg.get("auditors") or [])]
        adj = cfg.get("adjudicator") or {}
        if adj:
            self.adjudicator = LLMEndpoint.from_dict(adj, "adjudicator")
        else:
            self.adjudicator = None
        # the latest round's fix list (set by run_round) — feeds fix
        # re-queueing on ROLLBACK and residual_risks on STOP
        self._last_fixes: list[dict] = []

    # -- audit legs -----------------------------------------------------
    def _run_audit_legs(self, out_dir: Path, bundle: str) -> tuple[list[str], list[dict]]:
        "        A failed leg is isolated: its error goes to leg-meta.json + a\n        stderr file, never into audits[] — a broken leg cannot pollute the\n        adjudicator's input or the round report.\n        "
        out_dir.mkdir(parents=True, exist_ok=True)

        def _leg(i: int, ep: LLMEndpoint) -> dict:
            meta: dict = {"index": i + 1, "name": ep.name,
                          "protocol": ep.protocol, "model": ep.model,
                          "lens": ep.lens or "generic",
                          "exit_code": 0, "stderr": "",
                          "stop_reason": None,
                          "duration_ms": None, "usage": None}
            try:
                prompt = (_load_prompt(_audit_prompt_name(ep.lens))
                          + "\n\n" + bundle)
                out = call_endpoint(ep, prompt)
                meta["text"] = out["text"]
                meta["exit_code"] = out.get("exit_code", 0)
                meta["stderr"] = out.get("stderr", "")
                meta["stop_reason"] = out.get("stop_reason")
                meta["duration_ms"] = out.get("duration_ms")
                meta["usage"] = out.get("usage")
            except Exception as e:               # noqa: BLE001 - leg isolation
                meta["exit_code"] = 1
                meta["stderr"] = f"{type(e).__name__}: {e}"
                meta["text"] = None
            return meta

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, len(self.auditors))) as pool:
            metas = list(pool.map(_leg, range(len(self.auditors)),
                                  self.auditors))

        audits: list[str] = []
        for meta in metas:
            if meta["text"] is not None:
                audits.append(meta["text"])
                (out_dir / f"audit-{meta['index']}-{meta['name']}.md"
                 ).write_text(meta["text"])
            else:
                # failed leg: stderr archived separately, no report file,
                # nothing flows into the adjudicator body
                (out_dir / f"audit-{meta['index']}-{meta['name']}"
                 f".stderr.txt").write_text(meta["stderr"])
            (out_dir / f"leg-{meta['index']}-{meta['name']}-meta.json"
             ).write_text(json.dumps(meta, ensure_ascii=False, indent=2))
        return audits, metas

    _BUNDLE_CORE = (
        "core/schema.py", "core/orchestrator.py", "core/executor.py",
        "core/failure.py", "core/opsec.py", "core/cmd.py",
        "core/hypothesis_engine.py", "core/state_machine.py",
        "core/confidence.py", "core/scope.py", "core/db.py",
    )

    def build_bundle(self, extra: str = "") -> str:
        parts: list[str] = ["# 波次数据摘要\n"]
        parts.append(self._graph_summary())
        parts.append("\n# 引擎代码（本轮流审）\n")

        def emit(paths):
            for p in paths:
                parts.append(f"\n===== {p} =====\n")
                parts.append((self.engine_root / p).read_text())

        py_files = sorted(
            str(p.relative_to(self.engine_root))
            for p in self.engine_root.glob("core/*.py"))
        core = [f for f in py_files if f in self._BUNDLE_CORE]
        emit(core)
        parsers = sorted(str(p.relative_to(self.engine_root)) for p in
                         (self.engine_root / "core" / "parsers").glob("*.py"))
        emit(parsers)
        parts.append("\n# 规则（全量）\n")
        for p in sorted(self.rules_dir.rglob("*.json")):
            parts.append(f"\n===== {p.relative_to(self.rules_dir.parent)} =====\n")
            parts.append(p.read_text())
        emit([f for f in py_files if f not in core])
        if extra:
            parts.append("\n# 附加材料\n" + extra)
        return "\n".join(parts)

    def _graph_summary(self) -> str:
        edir = db.engagement_dir(self.root, self.engagement_id)
        g = edir / "graph.db"
        if not g.exists():
            return f"(engagement {self.engagement_id} has no graph.db yet)"
        import sqlite3
        from collections import Counter
        con = sqlite3.connect(g)
        con.row_factory = sqlite3.Row
        lines: list[str] = []
        try:
            lines.append("entities:")
            # Row rows must be indexed, not unpacked — unpacking yields the
            # row's VALUES (this loop used to subscript the count int).
            for r in con.execute(
                    "SELECT kind, COUNT(*) n FROM entities GROUP BY kind"):
                lines.append(f"  {r['kind']}: {r['n']}")
            lines.append("tool_run:")
            for r in con.execute(
                    "SELECT tool, status, COUNT(*) n FROM tool_run GROUP BY tool, status"):
                lines.append(f"  {r['tool']} {r['status']}: {r['n']}")
            lines.append("observations:")
            for r in con.execute(
                    "SELECT tool, COUNT(*) n, SUM(CASE WHEN exit_code=0 THEN 1 ELSE 0 END) ok "
                    "FROM observations GROUP BY tool"):
                lines.append(f"  {r['tool']}: n={r['n']} ok={r['ok']}")
            rules = Counter()
            for r in con.execute("SELECT data FROM entities WHERE kind='hypothesis'"):
                try:
                    rules[json.loads(r["data"]).get("rule_id", "?")] += 1
                except (TypeError, json.JSONDecodeError):
                    rules["(unparseable)"] += 1
            lines.append("hypotheses by rule (top 12):")
            for rid, n in rules.most_common(12):
                lines.append(f"  {rid}: {n}")
            lines.append("recent events:")
            for r in con.execute(
                    "SELECT kind, entity_id, payload FROM events ORDER BY seq DESC LIMIT 10"):
                lines.append(f"  {r['kind']} {r['entity_id'] or '-'} {str(r['payload'])[:100]}")
        finally:
            con.close()
        return "\n".join(lines)

    # -- round ----------------------------------------------------------
    def run_round(self, out_dir: Path, *, extra: str = "",
                  bundle_limit: int = 200_000) -> dict:
        """One loop round. Returns {'audits': [...], 'adjudication': '...',
        'fixes': [...], 'verdict': '...', 'verdict_json': {...}} and writes
        everything to out_dir."""
        out_dir.mkdir(parents=True, exist_ok=True)
        bundle = self.build_bundle(extra)
        if len(bundle) > bundle_limit:
            cut = len(bundle) - bundle_limit
            bundle = bundle[:bundle_limit] + (
                f"\n\n[...BUNDLE TRUNCATED AT {bundle_limit} BYTES: {cut} "
                "bytes cut. This is a PREFIX of the bundle — audit what is "
                "visible and say so explicitly in your report...]")
        (out_dir / "bundle.txt").write_text(bundle)

        audits, leg_meta = self._run_audit_legs(out_dir, bundle)

        adjudication = ""
        fixes: list[dict] = []
        verdict = "no_go"
        if self.adjudicator is not None:
            body = _load_prompt("adjudicate.md")
            for meta in leg_meta:
                if meta["text"] is None:
                    continue
                body += (f"\n\n# Audit leg {meta['index']}"
                         f" ({meta['name']}, lens {meta['lens']})"
                         f"\n\n{meta['text']}")
            adj_meta: dict = {"name": self.adjudicator.name,
                              "protocol": self.adjudicator.protocol,
                              "model": self.adjudicator.model,
                              "exit_code": 0, "stderr": "",
                              "stop_reason": None,
                              "duration_ms": None, "usage": None}
            try:
                out = call_endpoint(self.adjudicator, body)
                adjudication = out["text"]
                exit_code = out.get("exit_code", 0)
                adj_meta.update({
                    "exit_code": exit_code,
                    "stderr": out.get("stderr", ""),
                    "stop_reason": out.get("stop_reason"),
                    "duration_ms": out.get("duration_ms"),
                    "usage": out.get("usage")})
            except (urllib.error.URLError, urllib.error.HTTPError,
                    subprocess.SubprocessError, ValueError) as e:
                adjudication = (f"(adjudicator failed: "
                                f"{type(e).__name__}: {e})")
                exit_code = 1
                adj_meta.update({"exit_code": 1,
                                 "stderr": f"{type(e).__name__}: {e}"})
            (out_dir / "adjudication.md").write_text(adjudication)
            # telemetry rides along on success too — the meta file is the
            # per-round account of what the adjudication cost (duration,
            # tokens), not only a failure record
            (out_dir / "adjudicator-meta.json").write_text(json.dumps(
                adj_meta, ensure_ascii=False, indent=2))
            verdict, fixes = _parse_verdict(adjudication)
            (out_dir / "fix-list.json").write_text(json.dumps(
                {"verdict": verdict, "fixes": fixes}, ensure_ascii=False,
                indent=2))
        self._last_fixes = list(fixes)

        from .loop_evaluate import evaluate as _evaluate

        try:
            metrics = self._collect_metrics(out_dir, verdict, fixes)
            history = self._load_history(out_dir)
            round_num = history.get("round", 0) + 1
            prev = (history["rounds"][-1].get("metrics")
                    if history.get("rounds") else None)
            findings = self._round_findings(metrics)
            if self.adjudicator is not None:
                self._guard_no_go(verdict, fixes, findings)
            ev = _evaluate(round_num, prev, metrics, findings,
                           history.get("rounds") or [], None)
            payload = asdict(ev)
            (out_dir / "verdict.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2))
            history.setdefault("rounds", []).append(
                {"round": round_num, "checkpoint": ev.best_checkpoint,
                 "reward": ev.reward, "metrics": metrics})
            history["round"] = round_num
            (out_dir.parent / "loop-history.json").write_text(
                json.dumps(history, ensure_ascii=False, indent=2))
        except LoopEvaluationError:
            raise
        except Exception as e:
            err = (f"evaluate failed: {type(e).__name__}: {e}")
            (out_dir / "verdict.json").write_text(
                json.dumps({"action": "ERROR", "error": err},
                           ensure_ascii=False, indent=2))
            raise LoopEvaluationError(err) from e
        return {"audits": audits, "adjudication": adjudication,
                "fixes": fixes, "verdict": verdict,
                "verdict_json": payload}

    # -- verdict execution (ROLLBACK / STOP) -----------------------------
    def apply_verdict(self, verdict: dict, *,
                      round_dir: Path | None = None) -> dict:
        "        ROLLBACK → git revert the round's landing diff up to the last\n        checkpoint commit (i.e. revert everything after the best/highest\n        checkpoint), mark the round's fixes back into the queue (they are\n        NOT lost — they re-enter the next round's fix list), and archive\n        rollback.json. No checkpoint on record → hard error, the tree is\n        left untouched.\n\n        STOP → write best_checkpoint + residual_risks.json (unresolved\n        confirmed fixes from the fix lists) as the final deliverables.\n\n        Returns a summary dict; never mutates git state on STOP.\n        "
        action = str(verdict.get("action", "CONTINUE")).upper()
        if action not in ("ROLLBACK", "STOP"):
            return {"action": action, "executed": False}

        if action == "ROLLBACK":
            try:
                return self._apply_rollback(verdict, round_dir)
            except LoopRollbackError as e:
                if round_dir is not None:
                    try:
                        (round_dir / "rollback.json").write_text(json.dumps(
                            {"action": "ROLLBACK", "executed": False,
                             "degraded_to": "STOP", "reason": str(e)},
                            ensure_ascii=False, indent=2))
                    except OSError:
                        pass
                return {"action": "ROLLBACK", "executed": False,
                        "degraded_to": "STOP", "reason": str(e)}
        return self._apply_stop(verdict, round_dir)

    # -- rollback --------------------------------------------------------
    def _git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", *args], cwd=str(self.engine_root),
                              capture_output=True, text=True, timeout=60)

    def _checkpoint_history(self, round_dir: Path | None = None) -> list[dict]:
        """Checkpoint rows from the wave's loop-history.json (the run_round
        history file lives in the wave dir, next to the round dirs)."""
        hp = (round_dir.parent / "loop-history.json") if round_dir else None
        if hp is None or not hp.exists():
            return []
        try:
            return json.loads(hp.read_text()).get("rounds") or []
        except json.JSONDecodeError:
            return []

    def _apply_rollback(self, verdict: dict,
                        round_dir: Path | None) -> dict:
        best = verdict.get("best_checkpoint")
        if not best:
            rounds = self._checkpoint_history(round_dir)
            best = rounds[-1]["checkpoint"] if rounds else None
        if not best:
            raise LoopRollbackError(
                "ROLLBACK refused: no checkpoint on record "
                "(loop-history.json has no checkpoint rows) — refusing to "
                "revert blindly")
        # the checkpoint commit must exist, else revert would be a guess
        chk = self._git("rev-parse", "--verify", f"{best}^{{commit}}")
        if chk.returncode != 0:
            raise LoopRollbackError(
                f"ROLLBACK refused: checkpoint {best!r} is not a valid "
                f"commit — refusing to revert blindly")
        rev = self._git("revert", "--no-edit", f"{best}..HEAD")
        if rev.returncode != 0:
            raise LoopRollbackError(
                f"git revert {best}..HEAD failed: "
                f"{(rev.stderr or rev.stdout).strip()[:400]}")
        requeue = [{"id": f.get("id"), "summary": f.get("summary", ""),
                    "severity": f.get("severity", "MEDIUM"),
                    "status": "fix_failed"} for f in self._last_fixes]
        if round_dir is not None:
            round_dir.mkdir(parents=True, exist_ok=True)
            (round_dir / "rollback.json").write_text(json.dumps(
                {"action": "ROLLBACK", "reverted_to": best,
                 "requeued_fixes": requeue}, ensure_ascii=False, indent=2))
        return {"action": "ROLLBACK", "executed": True,
                "reverted_to": best, "requeued": len(requeue)}

    # -- stop ------------------------------------------------------------
    def _apply_stop(self, verdict: dict, round_dir: Path | None) -> dict:
        rounds = self._checkpoint_history(round_dir)
        best = verdict.get("best_checkpoint")
        if not best and rounds:
            best_round = max(rounds, key=lambda r: r.get("reward", 0))
            best = best_round.get("checkpoint")
        residual = self._residual_risks()
        if round_dir is not None:
            round_dir.mkdir(parents=True, exist_ok=True)
            (round_dir / "residual_risks.json").write_text(json.dumps(
                {"best_checkpoint": best,
                 "converged": bool(verdict.get("converged")),
                 "reason": verdict.get("reason", ""),
                 "residual_risks": residual}, ensure_ascii=False, indent=2))
        return {"action": "STOP", "executed": True, "best_checkpoint": best,
                "residual_risks": residual}

    def _residual_risks(self) -> list[dict]:
        """Unresolved confirmed fixes — from the latest fix list, status
        fix_failed or still queued (never landed/closed)."""
        return [{"id": f.get("id"), "severity": f.get("severity", "MEDIUM"),
                 "title": f.get("summary", ""), "status": "open"}
                for f in self._last_fixes]

    def _collect_metrics(self, out_dir: Path, verdict: str,
                         fixes: list[dict], *,
                         _prev_test_results: list | None = None) -> dict:
        "        Every value comes from a tool measurement, zero model self-assessment:\n        * test_pass_rate / new_red_tests — a real unittest run of the engine\n          suite (subprocess python3 -m unittest), compared with the previous\n          round's per-test results (override: _prev_test_results, used by\n          tests that run inside the measured suite);\n        * static_warnings / static_errors — pyflakes on core/ (warnings =\n          style-level findings, errors = syntax/unparseable failures);\n        * churn — ``git diff --stat`` against HEAD (uncommitted round diff);\n        * open_confirmed — findings still open at/above 'verified' state in\n          this engagement's graph.db.\n        "
        history = self._load_history(out_dir)
        prev_round = None
        if history.get("rounds"):
            prev_round = history["rounds"][-1]

        prev_results = _prev_test_results \
            if _prev_test_results is not None \
            else (prev_round or {}).get("_test_results")
        passed, failed, new_red = self._run_test_suite(prev_results)
        static_warnings, static_errors = self._static_analysis()
        churn = self._churn()

        return {
            "test_pass_rate": (passed / (passed + failed)) if (passed + failed) else 0.0,
            "new_red_tests": new_red,
            "static_warnings": static_warnings,
            "static_errors": static_errors,
            "arch_violations": (prev_round or {}).get("arch_violations", 0),
            "coverage": (prev_round or {}).get("coverage", 0.0),
            "open_confirmed": self._open_confirmed(),
            "churn": churn,
            "test_passed": passed,
            "test_failed": failed,
            "p0": sum(1 for f in fixes
                      if str(f.get("severity", "")).lower() == "p0"),
            "high": sum(1 for f in fixes
                        if str(f.get("severity", "")).lower() == "high"),
            "adjudicated_verdict": verdict,
            "fix_count": len(fixes),
            "_fixes": fixes,
            # per-test identity map for the next round's new_red_tests
            "_test_results": self._last_test_results,
        }

    # -- metric probes ---------------------------------------------------
    def _run_test_suite(self, prev_results: list | None) -> tuple[int, int, int]:
        'Really run the engine test suite; return (passed, failed, new_red).\n\n        Implementation: ``python3 -m unittest discover`` in a subprocess\n        with the same wiring the operator uses (tests/ is a namespace dir,\n        not a package — in-process TestLoader.discover cannot import it).'
        if os.environ.get("MOTOKO_LOOP_METRICS_CHILD") == "1":
            self._last_test_results = []
            return 0, 0, 0
        child_env = dict(os.environ,
                         MOTOKO_LOOP_METRICS_CHILD="1")
        started = time.monotonic()
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests",
                 "-v"], cwd=str(self.engine_root), capture_output=True,
                text=True, timeout=_SUITE_TIMEOUT_S, env=child_env)
        except subprocess.TimeoutExpired:
            # A hung suite is a measurement failure, not a zero — surface it as
            # 0 passed / 1 failed so the reward signal reacts. The elapsed
            # number IS the diagnosis, and the failure mode is not theoretical:
            # the child runs 124 s cold and 374 s under tracemalloc, so a
            # loaded host can reach a fixed budget that a cold one never does.
            self._last_test_results = [
                f"(suite timeout after {int(time.monotonic() - started)}s, "
                f"budget {_SUITE_TIMEOUT_S}s)"]
            return 0, 1, 1
        # Verbose status lines can span docstrings or be interrupted by test
        # diagnostics. Read the final summary and failure headings instead.
        output = proc.stderr or ""
        summaries = list(re.finditer(
            r"^Ran (\d+) tests? in [^\n]+\n\s*\n"
            r"(OK|FAILED)(?: \(([^\n]*)\))?[ \t]*$",
            output, re.MULTILINE))
        if not summaries or int(summaries[-1].group(1)) == 0:
            # Record WHY, not merely that. This branch produces a red metric
            # with no artefact: the round history said "(suite output
            # unparsable)" and nothing in it distinguished "the suite is
            # broken" from "a warning line landed between `Ran` and `OK`" —
            # which is exactly what three ResourceWarnings from an unclosed
            # test socket could do. The tail is the evidence, so the next
            # occurrence is diagnosable from the history alone.
            tail = " | ".join(ln.strip() for ln in output.splitlines()
                              if ln.strip())[-400:]
            self._last_test_results = [
                f"(suite output unparsable; rc={proc.returncode}; "
                f"stderr tail: {tail})"]
            return 0, 1, 1
        summary = summaries[-1]
        ran = int(summary.group(1))
        counts = {k.strip(): int(v) for k, v in re.findall(
            r"([a-z ]+)=(\d+)", summary.group(3) or "")}
        skipped = counts.get("skipped", 0) + counts.get("expected failures", 0)
        summary_failed = sum(counts.get(k, 0) for k in
                             ("failures", "errors", "unexpected successes"))
        # Subtest suffixes follow the parenthesised id. A failed subtest
        # makes its parent red once, even when multiple subtests fail.
        curr_failed = {
            m.group(1) for m in re.finditer(
                r"^={10,}\n(?:FAIL|ERROR|UNEXPECTED SUCCESS): "
                r"[^\n]*?\(([\w.]+)\)(?:[^\n]*)$",
                output[:summary.start()], re.MULTILINE)
        }
        if summary.group(2) == "OK" and not proc.returncode:
            curr_failed.clear()
        elif not curr_failed or not summary_failed:
            # A crashed runner or an incomplete result is a red measurement,
            # including nonzero exits after printing an otherwise green run.
            curr_failed.add("(suite runner failure)")
        failed = len(curr_failed)
        prev_failed = set(prev_results or [])
        new_red = len(curr_failed - prev_failed) if prev_results is not None \
            else failed
        self._last_test_results = sorted(curr_failed)
        # Skips are neither passes nor failures.  Exclude them from both
        # sides of the rate denominator while preserving the existing tuple
        # contract used by the loop evaluator.
        return max(ran - failed - skipped, 0), failed, new_red

    def _static_analysis(self) -> tuple[int, int]:
        """pyflakes over core/: (warnings, errors).

        Two shapes are excluded on purpose, and both were making the metric
        useless rather than making it lenient:

        * vendored sources under ``core/tools_anchor/strix-patches`` — anchored
          by hash, not ours to fix in place, so counting them put a permanent
          non-zero in every round record;
        * ``imported but unused`` — ``core/parsers/__init__.py`` imports
          nineteen modules purely for their ``@register`` side effect, which
          pyflakes cannot tell from a leftover. That is a constant
          nineteen-warning floor under a number that is supposed to move.

        Everything else stays in, and it is the set that means "this code does
        something other than what it says": undefined names, repeated dict keys,
        unused locals, f-strings with nothing in them. ``tests/
        test_lint_engine.py`` fails the suite on the same classes across core/,
        interface/, tests/ and scripts/, so a non-zero here is residue
        that gate cannot see — which is worth a round record, not a shrug.

        Falls back to (0, 0) when pyflakes is unavailable or the walk finds
        nothing: a missing linter must not fabricate metric values. That does
        leave (0, 0) ambiguous between "clean" and "unmeasured", which is
        tolerable only because tests/test_lint_engine.py imports pyflakes at
        module scope — a venv without it fails the suite loudly rather than
        reporting a clean round. (The docstring this replaced claimed the error
        was captured; nothing ever captured it.)
        """
        paths = [str(p)
                 for p in sorted((self.engine_root / "core").rglob("*.py"))
                 if not _LINT_EXCLUDE_PARTS.intersection(p.parts)]
        if not paths:
            return 0, 0
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pyflakes", *paths],
                capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return 0, 0
        if proc.returncode not in (0, 1):
            # pyflakes exits 1 for findings (normal); other codes = broken run
            return 0, 1
        warnings = [line for line in (proc.stdout or "").splitlines()
                    if ": " in line and "imported but unused" not in line]
        return len(warnings), 0

    def _churn(self) -> int:
        """Round churn: changed lines from git diff --stat vs HEAD."""
        try:
            proc = subprocess.run(
                ["git", "diff", "--stat", "HEAD"],
                cwd=str(self.engine_root), capture_output=True, text=True,
                timeout=30)
        except OSError:
            return 0
        m = re.search(r"changed\s+(\d+)\s+insertion", proc.stdout)
        if m:
            return int(m.group(1))
        # parse per-file lines: " n files changed, X insertions(+), Y deletions(-)"
        ins = re.findall(r"(\d+) insertion", proc.stdout)
        dels = re.findall(r"(\d+) deletion", proc.stdout)
        return (int(ins[0]) if ins else 0) + (int(dels[0]) if dels else 0)

    def _open_confirmed(self) -> int:
        """Confirmed findings still open in graph.db (state >= verified,
        not in a terminal resolved state) — the O_t stock term."""
        g = db.engagement_dir(self.root, self.engagement_id) / "graph.db"
        if not g.exists():
            return 0
        import sqlite3
        con = sqlite3.connect(f"file:{g}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT state, COUNT(*) n FROM entities "
                "WHERE kind='finding' AND state IS NOT NULL "
                "GROUP BY state").fetchall()
        except sqlite3.Error:
            return 0
        finally:
            con.close()
        return sum(n for state, n in rows
                   if state in _OPEN_CONFIRMED_STATES)

    def _round_findings(self, metrics: dict) -> list[dict]:
        'Map the adjudicated fix list onto loop_evaluate findings.'
        sev = {"p0": "CRITICAL", "high": "HIGH",
               "medium": "MEDIUM", "low": "LOW"}
        # Tolerant match: adjudicators write "both", "both legs", "multi"…
        # a single-leg report ("a leg only", "single") carries neither
        # token and stays excluded.
        def _confirmed(f: dict) -> bool:
            c = str(f.get("consensus", "")).lower()
            return "both" in c or "multi" in c

        confirmed = [f for f in (metrics.get("_fixes") or []) if _confirmed(f)]
        return [{"id": str(f.get("id", i)),
                 "severity": sev.get(str(f.get("severity", "")).lower(),
                                     "MEDIUM"),
                 "status": "verified_true"}
                for i, f in enumerate(confirmed)]

    @staticmethod
    def _guard_no_go(verdict: str, fixes: list[dict],
                     findings: list[dict]) -> None:
        ''
        if str(verdict).lower() != "no_go" or findings:
            return
        raise LoopEvaluationError(
            f"no_go adjudication but 0 of {len(fixes)} fix(es) carry "
            "cross-lens confirmation (consensus both/multi) — refusing "
            "to score an empty finding set as converged")

    def _load_history(self, out_dir: Path) -> dict:
        hp = out_dir.parent / "loop-history.json"
        if hp.exists():
            try:
                return json.loads(hp.read_text())
            except json.JSONDecodeError:
                pass
        return {"round": 0, "rounds": []}


def _parse_verdict(text: str) -> tuple[str, list[dict]]:
    "Extract the final JSON verdict from the adjudicator's output."
    decoder = json.JSONDecoder()
    best: dict | None = None
    for idx, ch in enumerate(text or ""):
        if ch != "{":
            continue
        try:
            obj, _end = decoder.raw_decode(text, idx)
        except ValueError:
            continue
        if isinstance(obj, dict) and "verdict" in obj:
            best = obj                 # keep scanning — the LAST block wins
    if best is None:
        return "no_go", []
    verdict = str(best.get("verdict", "no_go"))
    fixes = [f for f in (best.get("fixes") or []) if isinstance(f, dict)]
    return verdict, fixes
