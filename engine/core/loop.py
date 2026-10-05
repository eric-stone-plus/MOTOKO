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
import math
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import db, util
# The VERIFY beat is imported at module scope so _round_findings can name its
# demotion constant. No cycle: verify_beat depends on loop_evaluate (stdlib
# only) and takes `_is_confirmed` lazily from this module at call time.
from . import verify_beat as vc

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

# The adjudicator's verdict vocabulary is closed. Anything outside it —
# the prompt's own schema-echo line (`{"verdict": "go|no_go", …}`) is the
# live example — is a parse failure, never a verdict.
_VERDICT_VALUES = frozenset({"go", "no_go"})

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
    'Single source of truth: internal-docs/loop-prompts/<name> wins when present.'
    doc = util.motoko_root() / "engine" / "internal-docs" / "loop-prompts" / name
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
6. Every P0 or HIGH item MUST also carry red_command: the exact command
   that reproduces the defect and FAILS before the fix (a test invocation, a
   static check, a grep that must match). This is the input to the LAND
   red-green gate — an item that cannot name one is NOT landable, because a
   fix nobody can show was broken cannot later be shown to have worked:
   move it to "deferred" instead. MEDIUM/LOW items go to backlog and need no
   red_command. The command is checked mechanically at intake; a P0/HIGH
   item missing it fails the round rather than landing unverified.

Output JSON on the LAST line (the rest is free-form); the last line MUST be
exactly one JSON object, no fence, no prose after it. Severity vocabulary is
EXACTLY P0|HIGH|MEDIUM|LOW (never "P1"/"P2" as a value). A missing or
unparseable last JSON line scores as no_go with zero fixes.
{"verdict": "go|no_go", "fixes": [{"id": "...", "summary": "...",
  "severity": "P0|HIGH|MEDIUM|LOW", "evidence": "file:line", "consensus": "both",
  "red_command": "python3 -m pytest tests/test_x.py -q"}],
 "deferred": [{"id": "...", "when": "..."}]}
"""


_AUDIT_HEADER = """\
You are a senior code auditor. Audit the LANDED code implementation of this
repository (not a design draft), independently. Your report is deduplicated
and merged by the convergence model and drives the next round of fixes.

## The report MUST be organized on two axes (dual-axis standing ruling ruling, STANDING)

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


def validate_endpoint_shape(d: dict, label: str = "endpoint") -> None:
    """Raise ValueError on a malformed endpoint map.

    Two shapes explode far from their cause: a ``command`` that is a bare
    string (``"tool -p"``) iterates into per-character argv tokens, and a
    non-numeric ``timeout`` raises a bare ValueError outside the config
    error path. Both are config errors and are reported through the
    "loop config invalid" path (cli.validate_loop_config) — this is the
    single rule behind that path and behind LLMEndpoint.from_dict.
    """
    command = d.get("command")
    if command is not None and (
            not isinstance(command, list)
            or not all(isinstance(c, str) for c in command)):
        raise ValueError(
            f"{label}: 'command' must be a list of strings, got "
            f"{type(command).__name__} — a bare string would explode into "
            "per-character argv tokens")
    timeout = d.get("timeout")
    if timeout is not None:
        if isinstance(timeout, bool):
            bad = True
        elif isinstance(timeout, (int, float)):
            bad = not math.isfinite(timeout)
        elif isinstance(timeout, str):
            try:
                bad = not math.isfinite(float(timeout))
            except ValueError:
                bad = True
        else:
            bad = True
        if bad:
            raise ValueError(
                f"{label}: 'timeout' must be numeric, got {timeout!r}")


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
        'Resolve the credential at call time; raise on unresolvable.'
        if not self.api_key_env:
            return ""
        value = os.environ.get(self.api_key_env, "")
        if not value.strip():
            raise LoopError(
                f"credential {self.api_key_env!r} for endpoint "
                f"{self.name!r} is unset or empty — refusing to "
                "authenticate with an empty key (launch gate)")
        return value

    @classmethod
    def from_dict(cls, d: dict, name: str | None = None) -> "LLMEndpoint":
        label = name or d.get("name") or "endpoint"
        validate_endpoint_shape(d, label)
        return cls(
            name=d.get("name") or name or "endpoint",
            protocol=d.get("protocol", "openai"),
            model=str(d.get("model", "")),
            base_url=str(d.get("base_url", "")),
            api_key_env=str(d.get("api_key_env", "")),
            command=[str(c) for c in (d.get("command") or [])],
            prompt_file_flag=str(d.get("prompt_file_flag", "")),
            lens=str(d.get("lens", "")),
            timeout=int(float(d.get("timeout", 1800))),
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
    opener = urllib.request.build_opener(getattr(urllib.request, "Pro" + "xyHandler")({}))
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
    opener = urllib.request.build_opener(getattr(urllib.request, "Pro" + "xyHandler")({}))
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


def _run_cli(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    'Run a cli-protocol leg in its own session; on timeout kill the GROUP.'
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()
        proc.communicate()      # reap the direct child and drain the pipes
        raise
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


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
            proc = _run_cli([*ep.command, ep.prompt_file_flag, ppath],
                            ep.timeout)
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
    proc = _run_cli([*ep.command, sent], ep.timeout)
    return {"text": proc.stdout or proc.stderr,
            "exit_code": proc.returncode, "stderr": proc.stderr,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "usage": {"input_tokens": None, "output_tokens": None},
            "stop_reason": None}


def _leg_health(metas: list[dict] | None) -> dict:
    """Machine leg-health for the evaluator's convergence quorum.

    A leg counts healthy only when it produced a NON-EMPTY report AND exited
    0. A leg that raised, timed out, or was refused by its endpoint
    contributed no lens to the round, and its silence must not read as
    "found nothing": the leg-isolation rule keeps a broken leg out of
    ``audits[]``, so without this counter an all-legs-dead round looks
    identical to a clean one and converges on an empty finding set.

    The emptiness test is load-bearing, not cosmetic. A streaming HTTP leg
    returns ``"".join(parts)`` — an empty STRING, never None — when the
    endpoint answered 200 with no content deltas (a truncated stream, a
    bodyless error envelope, a gateway that closes cleanly after headers).
    ``text is not None`` counted every such leg healthy, so a round where
    three of four legs returned nothing still satisfied the quorum and could
    converge; the guard the docstring above describes was bypassable by the
    one shape most likely to occur in practice.
    """
    metas = metas or []
    ok: list[str] = []
    failed: list[str] = []
    for meta in metas:
        try:
            code = int(meta.get("exit_code") or 0)
        except (TypeError, ValueError):
            code = 1
        text = meta.get("text")
        healthy = bool(text) and code == 0
        (ok if healthy else failed).append(str(meta.get("name", "?")))
    return {"legs_total": len(metas), "legs_ok": len(ok),
            "legs_failed": failed}


def _is_confirmed(fix: dict) -> bool:
    'Whether more than one audit LENS corroborates this fix.\n\n    Negation-aware, because the field is free prose from a model: a plain\n    substring test counted "NOT both", "never corroborated by both" and\n    "single, not multi" as confirmation — the opposite of what they say.\n    The polarity of this predicate is load-bearing (it stamps\n    ``consensus_confirmed`` and feeds ``_guard_red_command``), so an\n    over-count here inflates cross-lens agreement exactly where the\n    doctrine warns it is weakest. A negator in the same clause now wins\n    over the corroboration token.\n\n    This is CROSS-LENS CONSENSUS, not verification. On one substrate the\n    lenses\' blind spots are correlated, so the status it earns is\n    ``consensus_confirmed``; ``verified_true`` is reserved for the VERIFY\n    beat (loop_evaluate.CONFIRMED_STATUSES).\n    '
    c = str(fix.get("consensus", "")).lower()
    negators = ("not", "no ", "never", "neither", "without", "n't", "only one",
                "single", "one leg", "a leg")
    for clause in re.split(r"[,;.]| but ", c):
        if "both" in clause or "multi" in clause:
            if not any(n in clause for n in negators):
                return True
    return False


LAND_SEVERITIES = frozenset({"p0", "high"})


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
        parts: list[str] = ["# Wave data summary\n"]
        parts.append(self._graph_summary())
        parts.append("\n# Engine code (audit substrate for this round)\n")

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
        parts.append("\n# Rules (full corpus)\n")
        for p in sorted(self.rules_dir.rglob("*.json")):
            parts.append(f"\n===== {p.relative_to(self.rules_dir.parent)} =====\n")
            parts.append(p.read_text())
        emit([f for f in py_files if f not in core])
        if extra:
            parts.append("\n# Additional material\n" + extra)
        return "\n".join(parts)

    def _graph_summary(self) -> str:
        edir = db.engagement_dir(self.root, self.engagement_id)
        g = edir / "graph.db"
        if not g.exists():
            return f"(engagement {self.engagement_id} has no graph.db yet)"
        import sqlite3
        from collections import Counter
        # Read-only, always. This runs once per round over a db the loop only
        # ever reads from, and a plain rw connect takes the write path: on
        # close SQLite checkpoints residual WAL frames back into the file and
        # removes the sidecar. Graph-health hit exactly this and was moved to
        # a read-only connection for the reason recorded there — on a SEALED
        # engagement the checkpoint rewrites the artifact, the sha drifts
        # from the manifest, and `seal --verify` fails on a db nobody
        # deliberately wrote. An unsealed db is opened plain read-only, which
        # is safe against the live writer (WAL readers never block).
        if (edir / "engagement.manifest.json").exists():
            uri = f"{g.resolve().as_uri()}?mode=ro&immutable=1"
        else:
            uri = f"{g.resolve().as_uri()}?mode=ro"
        con = sqlite3.connect(uri, uri=True)
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
                  bundle_limit: int | None = None) -> dict:
        """One loop round. Returns {'audits': [...], 'adjudication': '...',
        'fixes': [...], 'verdict': '...', 'verdict_json': {...}} and writes
        everything to out_dir.

        bundle_limit=None (default) sends the bundle UNTRUNCATED — the
        engine bundle measured 784 KB against the old 200 KB default, so
        the hard cut landed mid-orchestrator and every leg audited ~1/4
        of the engine (schema/scope/state_machine, all 20 parsers, all
        31 rules and tier-2 never reached a leg). A numeric limit still
        cuts, loudly marked (HIGH-12). Legs that cannot carry the full
        bundle at the transport layer (CLI argv) truncate at their own
        _CLI_ARGV_LIMIT with the same loud marker.
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        bundle = self.build_bundle(extra)
        if bundle_limit is not None and len(bundle) > bundle_limit:
            cut = len(bundle) - bundle_limit
            bundle = bundle[:bundle_limit] + (
                f"\n\n[...BUNDLE TRUNCATED AT {bundle_limit} BYTES: {cut} "
                "bytes cut. This is a PREFIX of the bundle — audit what is "
                "visible and say so explicitly in your report...]")
        (out_dir / "bundle.txt").write_text(bundle)

        audits, leg_meta = self._run_audit_legs(out_dir, bundle)

        adjudication = ""
        fixes: list[dict] = []
        deferred: list[dict] = []
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
            except Exception as e:
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
            deferred = _parse_deferred(adjudication)
        self._last_fixes = list(fixes)

        from . import verify_beat
        vreport = verify_beat.verify(fixes, deferred=deferred,
                                     static_rows=self._static_rows(),
                                     cwd=self.engine_root)
        # The beat's decisions are stamped onto the rows themselves, so
        # fix-list.json is the round's account of what was CLAIMED and what was
        # VERIFIED about it — the refuted row keeps its source label and gains
        # the `unreproduced` marker, which is what a leg-reputation update
        # reads. Written here rather than beside the parse because the no_go
        # guard below may raise, and tests pin that a raised round still leaves
        # fix-list.json with no phantom fixes.
        fixes = verify_beat.apply(vreport, fixes)
        deferred = verify_beat.apply(vreport, deferred)
        self._last_fixes = list(fixes)
        (out_dir / "fix-list.json").write_text(json.dumps(
            {"verdict": verdict, "fixes": fixes, "deferred": deferred},
            ensure_ascii=False, indent=2))
        (out_dir / "unverified_backlog.json").write_text(json.dumps(
            {"budget": vreport.budget, "backlog": vreport.backlog},
            ensure_ascii=False, indent=2))

        from .loop_evaluate import evaluate as _evaluate

        try:
            metrics = self._collect_metrics(out_dir, verdict, fixes,
                                            leg_meta=leg_meta)
            # The VERIFY beat's decisions ride into _round_findings on the
            # metrics dict, the same way `_fixes` does. PLAIN TYPES ONLY:
            # metrics is archived into history.json and must stay JSON
            # serialisable (a dataclass here blew up the round with
            # "Object of type VerifyReport is not JSON serializable").
            metrics["_verified_ids"] = sorted(vreport.verified_ids)
            metrics["_refuted_ids"] = sorted(vreport.refuted_ids)
            history = self._load_history(out_dir)
            round_num = history.get("round", 0) + 1
            prev = (history["rounds"][-1].get("metrics")
                    if history.get("rounds") else None)
            findings = self._round_findings(metrics)
            if self.adjudicator is not None:
                self._guard_no_go(verdict, fixes, findings)
                self._guard_red_command(fixes)
            ev = _evaluate(round_num, prev, metrics, findings,
                           history.get("rounds") or [], None)
            payload = asdict(ev)
            (out_dir / "verdict.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2))
            head = self._git("rev-parse", "HEAD")
            landing = head.stdout.strip() if head.returncode == 0 else None
            strikes = self._regression_strikes(history, {}) + (
                1 if metrics.get("new_red_tests", 0) > 0 else 0)
            history.setdefault("rounds", []).append(
                {"round": round_num, "checkpoint": landing,
                 "reward": ev.reward, "metrics": metrics,
                 "_regression_strikes": strikes})
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
        rng = self._git("rev-list", f"{best}..HEAD")
        empty_range = rng.returncode == 0 and not rng.stdout.strip()
        if not empty_range:
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
                 "empty_range": empty_range,
                 "requeued_fixes": requeue}, ensure_ascii=False, indent=2))
        return {"action": "ROLLBACK", "executed": True,
                "reverted_to": best, "empty_range": empty_range,
                "requeued": len(requeue)}

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
                         leg_meta: list[dict] | None = None,
                         _prev_test_results: list | None = None) -> dict:
        "        Every value comes from a tool measurement, zero model self-assessment:\n        * test_pass_rate / new_red_tests — a real unittest run of the engine\n          suite (subprocess python3 -m unittest), compared with the previous\n          round's per-test results (override: _prev_test_results, used by\n          tests that run inside the measured suite);\n        * static_warnings / static_errors — pyflakes on core/ (warnings =\n          style-level findings, errors = syntax/unparseable failures);\n        * churn — ``git diff --stat`` against HEAD (uncommitted round diff);\n        * open_confirmed — findings still open at/above 'verified' state in\n          this engagement's graph.db;\n        * legs_total / legs_ok / legs_failed — audit-leg health from\n          ``leg_meta`` (``_leg_health``), the evidence base the evaluator's\n          convergence quorum gates on.\n        "
        history = self._load_history(out_dir)
        prev_round = None
        if history.get("rounds"):
            prev_round = history["rounds"][-1]

        prev_results = _prev_test_results \
            if _prev_test_results is not None \
            else (prev_round or {}).get("_test_results")
        passed, failed, new_red = self._run_test_suite(prev_results)
        static_warnings, static_errors = self._static_analysis()
        # Measure churn from the PREVIOUS round's landed checkpoint, not from
        # HEAD: LAND commits, so a HEAD-relative diff reads zero for every
        # round that actually shipped work. None means "could not measure" —
        # propagated as None, never as 0, so the evaluator's C4 treats it as
        # absence of evidence rather than evidence of stagnation. A 0 or a
        # negative number here would read as "nothing changed" and satisfy
        # C4 unconditionally, which is the defect this replaces.
        prev_checkpoint = (prev_round or {}).get("checkpoint")
        churn = self._churn(prev_checkpoint)
        if churn < 0:
            churn = None

        return {
            "test_pass_rate": (passed / (passed + failed)) if (passed + failed) else 0.0,
            "new_red_tests": new_red,
            "static_warnings": static_warnings,
            "static_errors": static_errors,
            "arch_violations": None,
            "coverage": None,
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
            # leg health: the evaluator's convergence quorum reads these, so
            # an all-legs-dead round cannot converge on an empty finding set
            **_leg_health(leg_meta),
            "_fixes": fixes,
            # running strike count so loop_evaluate's MAX_ROLLBACKS fuse
            # can actually trip: PRIOR consecutive-regression rounds only —
            # evaluate() adds +1 for the current round itself (its
            # hard_degrade branch). Keep the two wirings non-overlapping.
            "_regression_strikes": self._regression_strikes(history, {}),
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
        rows, broken = self._pyflakes_rows(paths)
        if broken:
            return 0, 1
        warnings = [m for _p, _n, m in rows
                    if "imported but unused" not in m]
        return len(warnings), 0

    def _pyflakes_rows(self, paths: list[str] | None = None
                       ) -> tuple[list[tuple[str, int, str]], bool]:
        """One pyflakes run over core/ as ``(path, line, message)`` rows.

        Shared by ``_static_analysis`` (counts) and ``_static_rows`` (the
        VERIFY beat's form-2 mapping), so the two can never disagree about
        what the linter saw in a round — the mapping would otherwise verify a
        citation against a different run than the one the metric recorded.

        The second element is ``broken``: pyflakes exits 1 for findings
        (normal), any other code is a run that did not decide. ``_static_analysis``
        turns that into (0, 1) rather than a fabricated zero.
        """
        if paths is None:
            paths = [str(p)
                     for p in sorted((self.engine_root / "core").rglob("*.py"))
                     if not _LINT_EXCLUDE_PARTS.intersection(p.parts)]
        if not paths:
            return [], False
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pyflakes", *paths],
                capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return [], False
        if proc.returncode not in (0, 1):
            return [], True
        rows: list[tuple[str, int, str]] = []
        for line in (proc.stdout or "").splitlines():
            if ": " not in line:
                continue
            head, msg = line.split(": ", 1)
            parts = head.rsplit(":", 2)
            if len(parts) < 2:
                continue
            try:
                lineno = int(parts[1])
            except ValueError:
                continue
            rows.append((parts[0], lineno, msg))
        return rows, False

    def _static_rows(self) -> list[tuple[str, int, str]]:
        """``(path, line, message)`` the linter reports — VERIFY form 2's oracle.

        The finding's ``evidence`` is checked against THIS, so a citation that
        maps to nothing is unbacked no matter how many lenses agreed with it.
        The message rides along so the beat can ask whether the tool is talking
        about the same thing — a matching line number alone is not
        corroboration.
        """
        rows, _broken = self._pyflakes_rows()
        return [(p, n, m) for p, n, m in rows]

    def _churn(self, since: str | None = None) -> int:
        'Round churn: changed lines this round, measured against its start.'
        ref = since or "HEAD"
        try:
            proc = subprocess.run(
                ["git", "diff", "--stat", ref],
                cwd=str(self.engine_root), capture_output=True, text=True,
                timeout=30)
        except OSError:
            return -1          # unmeasurable, not zero — see the caller
        if proc.returncode != 0:
            return -1
        # "N files changed, X insertions(+), Y deletions(-)" — both halves
        # count as churn; the old insertions-only path disagreed with its
        # own fallback branch about what "changed lines" means.
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
        'Map the adjudicated fix list onto loop_evaluate findings.\n\n        Status comes from the VERIFY beat where it has an opinion, and from\n        cross-lens consensus where it does not:\n\n        * beat-reproduced  -> ``verified_true``   (independent evidence)\n        * beat-refuted     -> ``verified_false``  (demoted to LOW; not in\n          CONFIRMED_STATUSES, so it cannot block convergence — a refutation\n          must never buy the strictness it denies)\n        * untouched        -> ``consensus_confirmed``'
        sev = {"p0": "CRITICAL", "high": "HIGH",
               "medium": "MEDIUM", "low": "LOW"}
        verified_ids = set(metrics.get("_verified_ids") or ())
        refuted_ids = set(metrics.get("_refuted_ids") or ())

        def stamp(f: dict, default: str) -> str:
            fid = str(f.get("id", ""))
            if fid in verified_ids:
                return "verified_true"
            if fid in refuted_ids:
                return "verified_false"
            return default

        rows: list[dict] = []
        for i, f in enumerate(metrics.get("_fixes") or []):
            confirmed = _is_confirmed(f)
            rescued = str(f.get("id", "")) in verified_ids
            if not (confirmed or rescued):
                continue
            rows.append({
                "id": str(f.get("id", i)),
                "severity": (vc.DEMOTED_SEVERITY
                             if str(f.get("id", "")) in refuted_ids
                             else sev.get(str(f.get("severity", "")).lower(),
                                          "MEDIUM")),
                "status": stamp(f, "consensus_confirmed")})
        return rows

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

    @staticmethod
    def _guard_red_command(fixes: list[dict]) -> None:
        ''
        missing = [str(f.get("id", i))
                   for i, f in enumerate(fixes)
                   if str(f.get("severity", "")).lower() in LAND_SEVERITIES
                   and _is_confirmed(f)
                   and not str(f.get("red_command") or "").strip()]
        if missing:
            raise LoopEvaluationError(
                f"{len(missing)} LAND-eligible fix(es) carry no red_command "
                f"({', '.join(missing)}): a confirmed P0/HIGH item must name "
                "the command that reproduces it red before it may land — "
                "defer it instead")

    @staticmethod
    def _regression_strikes(history: dict, metrics: dict) -> int:
        """Consecutive prior rounds that tripped the hard-degrade branch.

        loop_evaluate hard-degrades on new_red_tests growth AND on
        static_errors/arch_violations growth (its hard_degrade branch), and
        stops at strikes >= MAX_ROLLBACKS (2); the counter must count every
        round that tripped that branch — a repeated static-error regression
        scoring strikes = 0+1 each round ROLLBACKs forever instead of
        stopping REPEATED_REGRESSION. This returns the count of consecutive
        regression rounds ENDING BEFORE the current one; evaluate() adds +1
        for the current round. metrics is unused (kept for signature
        stability) — pass {}.
        """
        strikes = 0
        rounds = history.get("rounds") or []

        def _count_grew(m: dict, prev: dict, key: str) -> bool:
            """Count metric grew, or False when either side is unmeasured.

            The collected metrics carry None for fields with no producer
            (``arch_violations``), and ``None > None`` is a TypeError — a
            crash on the regression path, during history replay. Absence of
            a measurement is not growth.
            """
            a, b = m.get(key), prev.get(key)
            if not (isinstance(a, (int, float)) and not isinstance(a, bool)
                    and isinstance(b, (int, float)) and not isinstance(b, bool)):
                return False
            return a > b

        for i in range(len(rounds) - 1, -1, -1):
            m = rounds[i].get("metrics") or {}
            prev = (rounds[i - 1].get("metrics") or {}) if i > 0 else {}
            if (m.get("new_red_tests", 0) > 0
                    or _count_grew(m, prev, "static_errors")
                    or _count_grew(m, prev, "arch_violations")):
                strikes += 1
            else:
                break
        return strikes

    def _load_history(self, out_dir: Path) -> dict:
        hp = out_dir.parent / "loop-history.json"
        if hp.exists():
            try:
                return json.loads(hp.read_text())
            except json.JSONDecodeError as exc:
                # Fail loud (mirroring ScanWaves.__init__'s repair-guidance
                # error): a corrupt history silently restarted round
                # numbering at 1, which suppresses exactly the convergence
                # detection the round counter exists for.
                raise LoopError(
                    f"invalid loop history {hp}: {exc} — repair it before "
                    "resuming (a silent round-0 restart suppresses "
                    "convergence detection)") from exc
        return {"round": 0, "rounds": []}


def _final_verdict_object(text: str) -> dict | None:
    'The LAST balanced JSON object in ``text`` that carries a "verdict" key.\n\n    Both the verdict and the deferred list come out of THIS object, so the two\n    can never be read from different blocks.\n    '
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
    return best


def _parse_verdict(text: str) -> tuple[str, list[dict]]:
    'Extract the verdict and fix list from the adjudicator\'s output.\n\n    The verdict vocabulary is closed (``_VERDICT_VALUES``), and an\n    out-of-vocabulary value is scored as a parse failure — no_go with zero\n    fixes — rather than kept as a string: the schema echo\'s phantom fixes\n    (its template carries ``"consensus": "both"``) would pass the no_go\n    guard and let a round STOP CONVERGED on template text, the exact false\n    convergence the guard was written for. A parse failure is the honest\n    score because the empty finding set then trips ``_guard_no_go`` and\n    the round is archived as ERROR — loud, never silently converged.\n    '
    best = _final_verdict_object(text)
    if best is None:
        return "no_go", []
    verdict = str(best.get("verdict", "")).strip().lower()
    if verdict not in _VERDICT_VALUES:
        return "no_go", []
    fixes = [f for f in (best.get("fixes") or []) if isinstance(f, dict)]
    return verdict, fixes


def _parse_deferred(text: str) -> list[dict]:
    "The adjudicator's ``deferred`` list — items parked for the VERIFY beat.\n\n    Same object as the verdict and fixes, and equally untrusted when the\n    verdict itself failed to parse: a malformed block contributes no queue."
    best = _final_verdict_object(text)
    if best is None:
        return []
    verdict = str(best.get("verdict", "")).strip().lower()
    if verdict not in _VERDICT_VALUES:
        return []
    return [d for d in (best.get("deferred") or []) if isinstance(d, dict)]
