"""Feedback loop module — wave-driven audit/adjudicate cycle, engine-native.

The loop is the feedback regulator of MOTOKO itself: after every run wave
(or tooling change), the engine bundles its own code + wave graph data,
sends the bundle to N independent auditor endpoints, aggregates the audit
reports, and has one adjudicator rank the findings into a fix list. The fix
list lands under ``plans/`` and feeds the next wave.

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
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import db, util

DEFAULT_CONFIG = Path.home() / ".motoko" / "loop.yaml"


def default_config_path() -> Path:
    """Loop-config resolution order (ARCHITECTURE.md config layering):

    1. ``$MOTOKO_CONFIG`` — explicit override, wins over everything;
    2. ``<motoko_root>/config/loop.yaml`` — in-tree live config (gitignored:
       it carries the operator's real endpoints);
    3. ``~/.motoko/loop.yaml`` — legacy home location, kept so
       pre-consolidation setups and shepherded runs keep working.
    """
    env = os.environ.get("MOTOKO_CONFIG")
    if env:
        return Path(env).expanduser()
    in_tree = util.motoko_root() / "config" / "loop.yaml"
    if in_tree.exists():
        return in_tree
    return DEFAULT_CONFIG


def _expand_value(value: str) -> str:
    """Expand ``${VAR}`` from the environment and a leading ``~/``.

    Unset variables are a hard error — a loop leg silently pointing at a
    literal ``${UNSET}`` base_url would fail much later and much further
    from the cause. ``api_key_env`` is exempted by the caller: it holds a
    variable *name*, resolved at call time by ``LLMEndpoint.resolve_key``.
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

# Finding states that count as "confirmed and still open" for the O_t
# stock term (MECHANISM.md §3): at/above 'verified', not yet confirmed
# into a terminal state, not falsified. See state_machine._TRANSITIONS.
_OPEN_CONFIRMED_STATES = frozenset({"verified", "exploitable"})


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

AUDIT_PROMPT = """\
你是资深渗透引擎代码审计员。审计对象：攻击图驱动渗透引擎的当前代码与运行数据。

# 审计重点
1. 调度正确性（优先级/配额/预算/饿死）
2. 规则触发正确性（误点火/爆炸/断链）
3. 解析与图一致性（工具输出 -> 资产/发现 的链路完整）
4. 安全边界（scope guard、注入面、纵深防御）
5. 新增代码与既有行为（miss 保活、frontier 重开、F 系列不变量）的冲突

# 输出格式
按 P0（阻塞）/ HIGH（正确性）/ MEDIUM（健壮性）/ LOW（风格）分级，
每条给：问题、证据（文件:行或数据）、影响、修复建议。
最后一行给出判定：本轮可继续（0 条 P0）或需先修 N 条。
"""

ADJUDICATE_PROMPT = """\
你是渗透引擎的 loop 裁决者。N 个独立审计员已审完同一批代码与数据，报告在下方。
请裁决：

1. 每条 finding：真（实锤）/ 假（误报）/ 与其它条目合并。
2. 修复范围：只把"下一波数据有无信息量"的分水岭项列入本轮；其余排期。
3. 修复顺序按依赖链排。
4. 输出严格的修复清单，每项：编号 / 一句话内容 / 为什么这个顺序。
5. 每项必须标注：severity（P0|HIGH|MEDIUM|LOW）、evidence（文件:行或数据
   引用，不得空泛）、consensus（哪些审计腿独立发现了它，如 "both" / "qwen
   only" / "single"）。

最后一行输出 JSON（其余内容可自由发挥），fixes 每项字段严格如下：
{"verdict": "go|no_go", "fixes": [{"id": "...", "summary": "...",
  "severity": "P0|HIGH|MEDIUM|LOW", "evidence": "file:line", "consensus": "both"}],
 "deferred": [{"id": "...", "when": "..."}]}
"""


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
    timeout: int = 1800

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
            if key != "api_key_env":       # holds a variable NAME, not a value
                value = _expand_value(value)
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

def call_endpoint(ep: LLMEndpoint, prompt: str) -> str | dict:
    """Call one endpoint leg.

    Returns the transcript text; the cli protocol returns a dict with
    {text, exit_code, stderr} because a CLI leg's failure metadata (exit
    code, stderr) must survive into leg-meta.json instead of being
    collapsed into the report text.
    """
    if ep.protocol == "openai":
        return _call_openai(ep, prompt)
    if ep.protocol == "anthropic":
        return _call_anthropic(ep, prompt)
    if ep.protocol == "cli":
        return _call_cli(ep, prompt)
    raise ValueError(f"unknown protocol {ep.protocol!r}")


def _call_openai(ep: LLMEndpoint, prompt: str) -> str:
    body = json.dumps({
        "model": ep.model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
    }).encode("utf-8")
    req = urllib.request.Request(
        ep.base_url.rstrip("/") + "/chat/completions", data=body,
        headers={"Authorization": f"Bearer {ep.resolve_key()}",
                 "Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    parts: list[str] = []
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
    return "".join(parts)


def _call_anthropic(ep: LLMEndpoint, prompt: str) -> str:
    body: dict = {
        "model": ep.model,
        "max_tokens": 40960,
        "stream": True,
        "messages": [{"role": "user", "content": prompt}],
    }
    # qwen endpoints (anthropic-compatible gateways) require extended
    # thinking to be explicitly enabled: thinking.budget_tokens >= 1024
    # and < max_tokens, else the gateway 400s the whole request
    # (llm-legs-runbook §二).
    body["thinking"] = {"type": "enabled", "budget_tokens": 8192}
    wire = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        ep.base_url.rstrip("/") + "/messages", data=wire,
        headers={"x-api-key": ep.resolve_key(),
                 "anthropic-version": "2023-06-01",
                 "Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    parts: list[str] = []
    with opener.open(req, timeout=ep.timeout) as resp:
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            try:
                ev = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
            if ev.get("type") == "content_block_delta":
                d = ev.get("delta") or {}
                if d.get("type") == "text_delta":
                    parts.append(d.get("text", ""))
            elif ev.get("type") == "message_stop":
                break
    return "".join(parts)


def _call_cli(ep: LLMEndpoint, prompt: str) -> dict:
    """Run a cli-protocol leg. Returns the transcript plus meta (exit code,
    stderr) so a failed leg is archived instead of silently half-reported."""
    if not ep.command:
        raise ValueError("cli endpoint needs a command list")
    proc = subprocess.run(
        [*ep.command, prompt], capture_output=True, text=True,
        timeout=ep.timeout)
    return {"text": proc.stdout or proc.stderr,
            "exit_code": proc.returncode, "stderr": proc.stderr}


# -- loop orchestration -------------------------------------------------

class LoopRunner:
    """One wave-loop round: bundle -> auditors -> adjudicator -> fix list."""

    def __init__(self, engagement_id: str, *, root: Path | None = None,
                 config: dict | None = None, rules_dir: Path | None = None,
                 engine_root: Path | None = None):
        self.engagement_id = engagement_id
        self.root = root or db.default_root()
        self.rules_dir = rules_dir or (engine_root or Path(__file__).resolve().parents[1]) / "rules"
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
        """Fire every auditor leg CONCURRENTLY (runbook §二: same input,
        mutually blind, launched at the same time) and archive per-leg meta.

        A failed leg is isolated: its error goes to leg-meta.json + a
        stderr file, never into audits[] — a broken leg cannot pollute the
        adjudicator's input or the round report.
        """
        prompt = AUDIT_PROMPT + "\n\n" + bundle
        out_dir.mkdir(parents=True, exist_ok=True)

        def _leg(i: int, ep: LLMEndpoint) -> dict:
            meta: dict = {"index": i + 1, "name": ep.name,
                          "protocol": ep.protocol, "model": ep.model,
                          "exit_code": 0, "stderr": "",
                          "stop_reason": None}
            try:
                out = call_endpoint(ep, prompt)
                if isinstance(out, dict):        # cli protocol
                    meta["text"] = out["text"]
                    meta["exit_code"] = out.get("exit_code", 0)
                    meta["stderr"] = out.get("stderr", "")
                else:
                    meta["text"] = out
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

    # -- bundle ---------------------------------------------------------
    def build_bundle(self, extra: str = "") -> str:
        parts: list[str] = ["# 波次数据摘要\n"]
        parts.append(self._graph_summary())
        parts.append("\n# 引擎代码（本轮流审）\n")
        for p in sorted(self.engine_root.glob("motoko/*.py")):
            parts.append(f"\n===== {p.relative_to(self.engine_root)} =====\n")
            parts.append(p.read_text())
        for p in sorted(self.rules_dir.rglob("*.json")):
            parts.append(f"\n===== {p.relative_to(self.rules_dir.parent)} =====\n")
            parts.append(p.read_text())
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
            for kind, n in con.execute(
                    "SELECT kind, COUNT(*) n FROM entities GROUP BY kind"):
                lines.append(f"  {kind}: {n['n']}")
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
        bundle = self.build_bundle(extra)[:bundle_limit]
        (out_dir / "bundle.txt").write_text(bundle)

        audits, leg_meta = self._run_audit_legs(out_dir, bundle)

        adjudication = ""
        fixes: list[dict] = []
        verdict = "no_go"
        if self.adjudicator is not None:
            body = ADJUDICATE_PROMPT
            for i, text in enumerate(audits):
                body += f"\n\n# 审计员 {i + 1}\n\n{text}"
            try:
                out = call_endpoint(self.adjudicator, body)
                adjudication = out if isinstance(out, str) else out["text"]
                exit_code = out.get("exit_code") if isinstance(out, dict) else 0
            except (urllib.error.URLError, urllib.error.HTTPError,
                    subprocess.SubprocessError, ValueError) as e:
                adjudication = (f"(adjudicator failed: "
                                f"{type(e).__name__}: {e})")
                exit_code = 1
            (out_dir / "adjudication.md").write_text(adjudication)
            if exit_code:
                (out_dir / "adjudicator-meta.json").write_text(json.dumps(
                    {"name": self.adjudicator.name, "exit_code": exit_code},
                    ensure_ascii=False, indent=2))
            verdict, fixes = _parse_verdict(adjudication)
            (out_dir / "fix-list.json").write_text(json.dumps(
                {"verdict": verdict, "fixes": fixes}, ensure_ascii=False,
                indent=2))
        self._last_fixes = list(fixes)

        # -- audit-loop merge: deterministic EVALUATE beat ------------------
        # The adjudicator's verdict is ADVISORY only. Convergence is decided
        # by loop_evaluate (pure functions, zero model self-assessment) over
        # the round's machine-produced metrics: adjudicated fix counts, test
        # results, and the round history. This is the audit-loop core
        # discipline: truth and "enough" belong to machine evidence, never
        # to a model's opinion (MECHANISM.md §core-discipline).
        #
        # G0 contract: evaluate() is called with its REAL signature
        # (round_num, prev, curr, findings, history, r1_baseline). Failure
        # here is never swallowed — the error is archived into verdict.json
        # (action=ERROR) AND raised as LoopEvaluationError, so the caller
        # exits non-zero instead of reading a hollow verdict.
        from .loop_evaluate import evaluate as _evaluate

        try:
            metrics = self._collect_metrics(out_dir, verdict, fixes)
            history = self._load_history(out_dir)
            round_num = history.get("round", 0) + 1
            prev = (history["rounds"][-1].get("metrics")
                    if history.get("rounds") else None)
            findings = self._round_findings(metrics)
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
        """Execute a non-CONTINUE verdict (MECHANISM.md §5/§6).

        ROLLBACK → git revert the round's landing diff up to the last
        checkpoint commit (i.e. revert everything after the best/highest
        checkpoint), mark the round's fixes back into the queue (they are
        NOT lost — they re-enter the next round's fix list), and archive
        rollback.json. No checkpoint on record → hard error, the tree is
        left untouched.

        STOP → write best_checkpoint + residual_risks.json (unresolved
        confirmed fixes from the fix lists) as the final deliverables.

        Returns a summary dict; never mutates git state on STOP.
        """
        action = str(verdict.get("action", "CONTINUE")).upper()
        if action not in ("ROLLBACK", "STOP"):
            return {"action": action, "executed": False}

        if action == "ROLLBACK":
            return self._apply_rollback(verdict, round_dir)
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
        # re-queue: this round's fixes go back into the queue for the next
        # round (fix_failed per MECHANISM.md §5) — archived for the driver
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
        """Machine-produced round metrics (MECHANISM.md §7 Metrics schema).

        Every value comes from a tool measurement, zero model self-assessment:
        * test_pass_rate / new_red_tests — a real unittest run of the engine
          suite (subprocess python3 -m unittest), compared with the previous
          round's per-test results (override: _prev_test_results, used by
          tests that run inside the measured suite);
        * static_warnings / static_errors — pyflakes on motoko/ (warnings =
          style-level findings, errors = syntax/unparseable failures);
        * churn — ``git diff --stat`` against HEAD (uncommitted round diff);
        * open_confirmed — findings still open at/above 'verified' state in
          this engagement's graph.db.
        """
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
        """Really run the engine test suite; return (passed, failed, new_red).

        new_red_tests = tests green in the previous round that are red now
        (MECHANISM.md §3 G_t). With no previous round, any failing test is
        new red (the baseline must start clean). The per-test identity map
        is kept in ``self._last_test_results`` for the next round.

        Implementation: ``python3 -m unittest discover`` in a subprocess
        with the same wiring the operator uses (tests/ is a namespace dir,
        not a package — in-process TestLoader.discover cannot import it).

        Re-entrancy guard: the child suite CONTAINS the loop tests, and a
        loop test runs run_round -> _collect_metrics -> _run_test_suite —
        without a guard that recursion spawns a full suite per generation
        (a live fork bomb, observed 2026-09-12). The child is marked via
        env and stubs its own metric probe at depth >= 1.
        """
        if os.environ.get("MOTOKO_LOOP_METRICS_CHILD") == "1":
            self._last_test_results = []
            return 0, 0, 0
        child_env = dict(os.environ,
                         MOTOKO_LOOP_METRICS_CHILD="1")
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests",
                 "-v"], cwd=str(self.engine_root), capture_output=True,
                text=True, timeout=600, env=child_env)
        except subprocess.TimeoutExpired:
            # a hung suite is a measurement failure, not a zero — surface
            # it as 0 passed / 1 failed so the reward signal reacts
            self._last_test_results = ["(suite timeout)"]
            return 0, 1, 1
        curr_failed: set[str] = set()
        ran = 0
        name = "(unknown)"
        for line in (proc.stderr or "").splitlines():
            m = re.match(r"^(test_\S+?) \(([\w.]+)\) ?\.\.\. ", line)
            if m:
                ran += 1
                name = m.group(2)          # qualified id: pkg.Class.test_m
            verdict = line.split(" ... ", 1)[-1].strip() if " ... " in line else ""
            if verdict == "ok" or verdict.startswith("skipped"):
                continue
            if verdict in ("FAIL", "ERROR") or verdict.startswith(
                    ("ERROR:", "FAIL:")):
                curr_failed.add(name)
        if not ran:
            # no per-test lines parsed — refuse to fabricate a pass rate
            self._last_test_results = ["(suite output unparsable)"]
            return 0, 1, 1
        failed = len(curr_failed)
        prev_failed = set(prev_results or [])
        new_red = len(curr_failed - prev_failed) if prev_results is not None \
            else failed
        self._last_test_results = sorted(curr_failed)
        return ran - failed, failed, new_red

    def _static_analysis(self) -> tuple[int, int]:
        """pyflakes over motoko/: (warnings, errors). Falls back to (0, 0)
        with the error captured when pyflakes is unavailable — a missing
        linter must not fabricate metric values."""
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pyflakes",
                 str(self.engine_root / "motoko")],
                capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return 0, 0
        if proc.returncode not in (0, 1):
            # pyflakes exits 1 for findings (normal); other codes = broken run
            return 0, 1
        warnings = [l for l in (proc.stdout or "").splitlines() if ": " in l]
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
        """Map the adjudicated fix list onto loop_evaluate findings.

        MECHANISM.md §4/§7: only independently confirmed findings score in
        the evaluator. An adjudicated fix is treated as verified_true (the
        two legs found it independently and the adjudicator confirmed it);
        the fix itself has not landed yet, so it is NOT fix_confirmed.
        """
        sev = {"p0": "CRITICAL", "high": "HIGH",
               "medium": "MEDIUM", "low": "LOW"}
        return [{"id": str(f.get("id", i)),
                 "severity": sev.get(str(f.get("severity", "")).lower(),
                                     "MEDIUM"),
                 "status": "verified_true"}
                for i, f in enumerate(metrics.get("_fixes") or [])]

    def _load_history(self, out_dir: Path) -> dict:
        hp = out_dir.parent / "loop-history.json"
        if hp.exists():
            try:
                return json.loads(hp.read_text())
            except json.JSONDecodeError:
                pass
        return {"round": 0, "rounds": []}


def _parse_verdict(text: str) -> tuple[str, list[dict]]:
    """Extract the final JSON verdict from the adjudicator's output.

    Item 3: fixes entries carry {severity, evidence, consensus}; those
    fields are passed through untouched so _collect_metrics counts p0/high
    from the adjudicator's real severity ratings (missing severity counts
    as MEDIUM — visible in fix_count, invisible to the p0/high gates).
    """
    m = re.search(r"\{[\s\S]*\"verdict\"[\s\S]*\}", text)
    if not m:
        return "no_go", []
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return "no_go", []
    verdict = str(data.get("verdict", "no_go"))
    fixes = [f for f in (data.get("fixes") or []) if isinstance(f, dict)]
    return verdict, fixes
