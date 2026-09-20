"Static rule-corpus validator — the engine's honesty gate.\n\nEvery number quoted above is a snapshot; the ONLY honest way to cite one is\nto re-run ``motoko rules --report`` with the current model (audit A2\ndiscipline — the day-1 headline was itself partly wrong).\n\nDesign rules for this module:\n\nSeverity contract: HIGH = the rule cannot do what it claims (never fires,\ncannot execute, or silently attacks a literal placeholder); MEDIUM = it fires\nbut violates a standing discipline or its output goes nowhere; LOW = hygiene.\n\nRun:  motoko rules --report [--strict]\n"

from __future__ import annotations

import ast
import json
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import cmd, util
from .parsers import _REGISTRY

SEVERITIES = ("HIGH", "MEDIUM", "LOW")

_ATTIC_DIRNAME = "rules-attic"

# --------------------------------------------------------------------------
# Declared judgment tables (locked by tests/test_rulecheck.py)
# --------------------------------------------------------------------------

# The ops hypothesis_engine._eval accepts. Anything else RAISES ValueError at
# match time (it does not fall through to False), so a typo here is a crash on
# every asset, not a dead rule.
SUPPORTED_OPS: frozenset[str] = frozenset({
    "eq", "==", "ne", "!=", "contains", "matches", "in", "intersects",
})

# nmap names services from its own frequency table, not from the port's
# marketing name. A rule gating on ``service contains "smb"`` therefore never
# matches a real domain controller: 445 is ``microsoft-ds`` and 139 is
# ``netbios-ssn``. Keys are the substring a rule author reaches for; values
# are the nmap names that actually appear in the XML.
NMAP_SERVICE_ALIASES: dict[str, tuple[str, ...]] = {
    "smb": ("microsoft-ds", "netbios-ssn"),
    "rdp": ("ms-wbt-server",),
    "winrm": ("wsman",),
    "ldap": ("ldap", "ldaps", "globalcatLDAP"),
    "mssql": ("ms-sql-s",),
    "rpc": ("msrpc",),
    "ssh": ("ssh",),
    "http": ("http", "http-alt", "http-proxy", "ssl|http"),
}

UA_CAPABLE_TOOLS: frozenset[str] = frozenset({
    "curl", "nuclei", "httpx", "ffuf", "katana", "dalfox", "arjun",
    "feroxbuster", "gobuster", "dirsearch", "nikto", "wpscan", "tplmap",
    "jsluice", "kr", "kiterunner", "git-dumper",
})

RATE_LIMIT_FLAGS: dict[str, tuple[str, ...]] = {
    "nuclei": ("-rl", "-rate-limit", "-bs", "-bulk-size"),
    "katana": ("-rl", "-rate-limit"),
    "ffuf": ("-p ", "-rate", "-t "),
    "feroxbuster": ("--rate-limit", "-q"),
    "nmap": ("--max-rate", "--scan-delay", "-T0", "-T1", "-T2"),
    "sqlmap": ("--delay", "--threads=1", "--timeout"),
    "dalfox": ("--delay", "--waf-evasion", "--only-poc"),
    "nikto": ("-maxtime", "-Tuning"),
    "git-dumper": ("-j ", "--jobs"),
}

# curl's own -w format strings use the same braces as our placeholders
# (%{http_code}, %{redirect_url}). They are data, not context keys, and the
# ACT-time fail-closed gate cannot see the difference — so the static check
# is where they get recognized.
_LITERAL_BRACE_RE = re.compile(r"%\{[A-Za-z_][A-Za-z0-9_]*\}")
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Asset/entity fields the engine itself owns (written by the orchestrator or
# the CLI rather than by a parser). AST picks most of these up; the set is the
# belt-and-braces declaration so a refactor that moves a write site cannot
# silently turn a live fact into a "dead" one.
ENGINE_OWNED_FIELDS: frozenset[str] = frozenset({
    "id", "kind", "engagement_id", "state", "value", "type", "source",
    "frontier", "expansion_count", "attempts_by_rule", "created_at",
    "updated_at", "dedup_key", "confidence", "priority",
})

ENGINE_STAMPED_FIELDS: frozenset[str] = frozenset({
    "enumerated_host", "enumerated_domain", "crawled_host", "nmap_host",
    "robots_host", "canary_paths", "crawl_delay",
    "enumeration_completed",
})

# Tools that run inside the kali container; their binaries are not on the host
# so ``resolve_tool`` cannot see them. Verified against the container image by
# ``motoko doctor``, not here (static check, no live container).
_CONTAINER_RUNTIME = "container"


@dataclass
class RuleIssue:
    severity: str
    code: str
    rule_id: str
    message: str
    evidence: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        return {"severity": self.severity, "code": self.code,
                "rule_id": self.rule_id, "message": self.message,
                "evidence": self.evidence, "fix": self.fix}


@dataclass
class CorpusModel:
    """The producer/consumer model derived from ``core/`` source.

    ``written_keys`` = asset/observation fields a PARSER module can stamp
    (dict literal / subscript / setdefault evidence from ``core/parsers/``
    only — A2-5); fields the engine itself owns live in the declared floors
    ENGINE_OWNED_FIELDS / ENGINE_STAMPED_FIELDS.
    """

    written_keys: set[str] = field(default_factory=set)
    hyp_keys: set[str] = field(default_factory=set)
    ctx_keys: set[str] = field(default_factory=set)
    ctx_conditional: dict[str, str] = field(default_factory=dict)
    written_kinds: set[str] = field(default_factory=set)
    produced_classes: set[str] = field(default_factory=set)
    parser_tools: set[str] = field(default_factory=set)
    fact_keys: set[str] = field(default_factory=set)
    fact_fields: dict[str, set[str]] = field(default_factory=dict)
    fact_kinds: dict[str, set[str]] = field(default_factory=dict)
    chain_consumers: set[str] = field(default_factory=set)
    chain_hint_consumers: set[str] = field(default_factory=set)

    # -- derived views --------------------------------------------------
    @property
    def producible_fields(self) -> set[str]:
        """Asset fields anything in the engine can actually write."""
        return self.written_keys | ENGINE_OWNED_FIELDS | ENGINE_STAMPED_FIELDS

    @property
    def producible_ctx(self) -> set[str]:
        """Placeholder names the engine supplies at ACT time UNCONDITIONALLY.

        A hypothesis key renders only when it is ALSO a declared context key:
        ``_command_ctx`` copies nothing else off the hypothesis,
        ``render_command`` substitutes nothing else, and the ACT gate
        inspects nothing else — ``{asset_id}``/``{engagement_id}`` ride on
        every hypothesis yet would enter argv verbatim with neither side
        objecting (A2-5), so hyp_keys counts intersected with CTX_KEYS.

        A key injected only under a runtime condition (``{oob}`` exists only
        when the engagement declares an OOB domain) is not producible in
        general: the ACT gate refuses the action on every engagement that
        lacks it, which is a configuration gap worth reporting, not a fact
        about the corpus.
        """
        return ((self.hyp_keys & set(cmd.CTX_KEYS))
                | (self.ctx_keys - set(self.ctx_conditional)))

    def fact_producible(self, fact: str) -> bool:
        """Can this fact ever carry a non-empty value?

        A fact is producible when at least one of the asset fields it reads is
        writable, or when it reads no asset field at all (computed from the
        asset list, the services table, or a literal). Facts that read entity
        kinds nobody creates (``level`` <- ``access``) are not producible.
        """
        kinds = self.fact_kinds.get(fact) or set()
        if kinds and not (kinds & self.written_kinds):
            return False
        fields = self.fact_fields.get(fact)
        if not fields:
            return True
        return bool(fields & self.producible_fields)


def _modules(core_dir: Path):
    for p in sorted(core_dir.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        try:
            yield p, ast.parse(p.read_text(), filename=str(p))
        except (SyntaxError, OSError):
            continue


def _const(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def derive_model(core_dir: Path | None = None) -> CorpusModel:
    """Extract the producer/consumer model from the engine source by AST."""
    core_dir = Path(core_dir or Path(__file__).resolve().parent)
    m = CorpusModel()
    m.parser_tools = set(_REGISTRY)

    for path, tree in _modules(core_dir):
        in_parsers = path.parent.name == "parsers"
        for node in ast.walk(tree):
            # dict literals: every string key is a candidate field name, and
            # ``kind``'s value is an entity kind something can create.
            # A2-5: field-name evidence comes from PARSER modules only — the
            # blanket scan counted every dict literal in core/ (309 keys,
            # including this checker's own report rows) as "a parser writes
            # this asset field", certifying facts producible on a naming
            # coincidence. Engine-owned writes keep their declared floors
            # (ENGINE_OWNED_FIELDS / ENGINE_STAMPED_FIELDS); entity KINDS and
            # hypothesis placeholders stay global — their writers legitimately
            # live outside parsers/ (hypothesis_engine mints hypotheses,
            # _expand stamps hyp keys).
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    ks = _const(k)
                    if not ks:
                        continue
                    if in_parsers:
                        m.written_keys.add(ks)
                    if ks == "kind":
                        vs = _const(v)
                        if vs:
                            m.written_kinds.add(vs)
            # subscript assignment: extra["waf"] = vendor
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if (isinstance(t, ast.Subscript)
                            and isinstance(t.value, ast.Name)
                            and t.value.id not in ("facts", "ctx", "env")):
                        ks = _const(t.slice)
                        if ks:
                            if in_parsers:
                                m.written_keys.add(ks)
                            if ks == "kind":
                                vs = _const(node.value)
                                if vs:
                                    m.written_kinds.add(vs)
            # x.setdefault("key", ...)
            elif isinstance(node, ast.Call):
                f = node.func
                if (isinstance(f, ast.Attribute) and f.attr == "setdefault"
                        and isinstance(f.value, ast.Name) and node.args):
                    ks = _const(node.args[0])
                    if ks:
                        if in_parsers:
                            m.written_keys.add(ks)
                        if f.value.id == "hyp":
                            m.hyp_keys.add(ks)
                        if ks == "kind" and len(node.args) > 1:
                            vs = _const(node.args[1])
                            if vs:
                                m.written_kinds.add(vs)
                # class_="x.y" on a parser's finding factory
                for kw in node.keywords:
                    if kw.arg == "class_":
                        cs = _const(kw.value)
                        if cs:
                            m.produced_classes.add(cs)
                # services live in their own table, so no dict literal ever
                # carries kind="service"; the write site is add_service().
                if isinstance(f, ast.Attribute) and f.attr in (
                        "add_service", "add_access"):
                    m.written_kinds.add(
                        "service" if f.attr == "add_service" else "access")
        if in_parsers:
            m.produced_classes |= _parser_class_literals(tree)
        if path.name == "orchestrator.py":
            _derive_fact_view(tree, m)
    # _command_ctx's injected keys
    for _path, tree in _modules(core_dir):
        keys, cond = _derive_ctx_keys(tree)
        m.ctx_keys |= keys
        m.ctx_conditional.update(cond)
    m.chain_consumers, m.chain_hint_consumers = _derive_chain_consumers(core_dir)
    return m


def _parser_class_literals(tree: ast.AST) -> set[str]:
    'Finding classes a parser can emit, beyond the ``class_=`` kwarg form.'
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            targets, value = [], None
        for t in targets:
            if isinstance(t, ast.Name) and "CLASS_MAP" in t.id.upper():
                for elt in getattr(value, "elts", []):
                    if isinstance(elt, ast.Tuple) and len(elt.elts) >= 2:
                        cs = _const(elt.elts[1])
                        if cs:
                            out.add(cs)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if "class" in node.name.lower():
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Return):
                        cs = _const(sub.value)
                        if cs:
                            out.add(cs)
    return out


def _iter_sources(it: ast.AST) -> tuple[set[str], set[str]]:
    """(asset-fields-readable, entity-kinds) implied by an iteration source.

    ``assets`` and ``self.writer.get_services(...)`` yield asset-ish rows;
    ``query_entities(kind="access")`` yields that entity kind and nothing else.
    """
    fields: set[str] = set()
    kinds: set[str] = set()
    for sub in ast.walk(it):
        if isinstance(sub, ast.Name) and sub.id == "assets":
            fields.add("*asset")
        if isinstance(sub, ast.Attribute) and sub.attr == "get_services":
            kinds.add("service")
        if isinstance(sub, ast.Attribute) and sub.attr == "query_entities":
            kinds.add("*query")
        if isinstance(sub, ast.keyword) and sub.arg == "kind":
            ks = _const(sub.value)
            if ks:
                kinds.add(ks)
    return fields, kinds


def _derive_fact_view(tree: ast.AST, m: CorpusModel) -> None:
    """Which facts ``_fact_view`` emits, and what each one reads.

    Four things have to be modelled or the analysis lies:

    1. the opening dict literal (``facts = {"url": ..., "ip": ...}``) — without
       it two of the most-used facts look unknown and every rule that gates on
       them would be wrongly condemned;
    2. ``facts.setdefault("param", ...)`` — a fact written conditionally;
    3. row variables (``for e in assets``, ``for acc in query_entities(...)``)
       — ``host_crawled`` reads ``crawled_host`` off ``e``, not off ``asset``,
       and ``level``'s only dependency is that an ``access`` entity exists;
    4. intermediate locals (``host = asset.get("value")...`` then
       ``facts["host_crawled"] = bool(host and ...)``).

    A field read is attributed to the asset only when the receiver is the
    asset itself or a variable bound from ``assets``; entity rows contribute
    their KIND, which is checked against the kinds anything can create.
    """
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_fact_view":
            fn = node
            break
    if fn is None:
        return

    # -- pass 1: row variables ------------------------------------------
    asset_vars: set[str] = {"asset"}
    row_kinds: dict[str, set[str]] = {}
    for node in ast.walk(fn):
        pairs: list[tuple[ast.AST, ast.AST]] = []
        if isinstance(node, ast.For):
            pairs.append((node.target, node.iter))
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            pairs.extend((g.target, g.iter) for g in node.generators)
        for tgt, it in pairs:
            if not isinstance(tgt, ast.Name):
                continue
            fields, kinds = _iter_sources(it)
            if "*asset" in fields:
                asset_vars.add(tgt.id)
            kinds.discard("*query")
            if kinds:
                row_kinds.setdefault(tgt.id, set()).update(kinds)
            if "service" in kinds:
                asset_vars.add(tgt.id)      # get_services -> service rows

    def reads(node: ast.AST) -> tuple[set[str], set[str]]:
        """(asset fields, entity kinds) an expression depends on."""
        fields: set[str] = set()
        kinds: set[str] = set()
        for sub in ast.walk(node):
            owner = None
            key = None
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "get"
                    and isinstance(sub.func.value, ast.Name) and sub.args):
                owner, key = sub.func.value.id, _const(sub.args[0])
            elif (isinstance(sub, ast.Subscript)
                  and isinstance(sub.value, ast.Name)):
                owner, key = sub.value.id, _const(sub.slice)
            if owner and key:
                if owner in asset_vars:
                    fields.add(key)
                elif owner in row_kinds:
                    kinds |= row_kinds[owner]
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                for kw in sub.keywords:
                    if kw.arg == "kind":
                        ks = _const(kw.value)
                        if ks:
                            kinds.add(ks)
        return fields, kinds

    # -- pass 2: locals, then the facts they feed ------------------------
    local_fields: dict[str, set[str]] = {}
    local_kinds: dict[str, set[str]] = {}

    def record(key: str, expr: ast.AST) -> None:
        m.fact_keys.add(key)
        fields, kinds = reads(expr)
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name) and sub.id in local_fields:
                fields |= local_fields[sub.id]
                kinds |= local_kinds.get(sub.id, set())
        if key in row_kinds:
            kinds |= row_kinds[key]
        m.fact_fields.setdefault(key, set()).update(fields)
        m.fact_kinds.setdefault(key, set()).update(kinds)

    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "facts" \
                        and isinstance(node.value, ast.Dict):
                    for k, v in zip(node.value.keys, node.value.values):
                        key = _const(k)
                        if key:
                            record(key, v)
                elif isinstance(t, ast.Name):
                    f_, k_ = reads(node.value)
                    local_fields[t.id] = f_
                    local_kinds[t.id] = k_ | row_kinds.get(t.id, set())
                elif (isinstance(t, ast.Subscript)
                      and isinstance(t.value, ast.Name)
                      and t.value.id == "facts"):
                    key = _const(t.slice)
                    if key:
                        record(key, node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.target.id == "facts" and isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                key = _const(k)
                if key:
                    record(key, v)
        elif isinstance(node, ast.Call):
            f_ = node.func
            if (isinstance(f_, ast.Attribute) and f_.attr == "setdefault"
                    and isinstance(f_.value, ast.Name)
                    and f_.value.id == "facts" and node.args):
                key = _const(node.args[0])
                if key:
                    record(key, node.args[1] if len(node.args) > 1 else node)
        elif isinstance(node, ast.For):
            # facts written inside the loop body (level/principal) inherit the
            # loop variable's entity kind, recorded in pass 1.
            if isinstance(node.target, ast.Name):
                local_kinds[node.target.id] = row_kinds.get(node.target.id, set())


def _derive_ctx_keys(tree: ast.AST) -> tuple[set[str], dict[str, str]]:
    """Placeholder names ``_command_ctx`` injects, and which are conditional.

    Every injection site is guarded by ``if "<key>" not in ctx``; the key is
    unconditional when that compare is the whole test, and conditional when
    the test carries anything else (``and getattr(self, "oob_domain", "")``).
    Deriving this is what keeps ``{oob}`` from being reported as producible on
    an engagement that has no canary backend.
    """
    keys: set[str] = set()
    conditional: dict[str, str] = {}
    fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_command_ctx":
            fn = node
            break
    if fn is None:
        return keys, conditional

    def guarded_keys(test: ast.AST) -> list[str]:
        found = []
        for sub in ast.walk(test):
            if (isinstance(sub, ast.Compare) and isinstance(sub.ops[0], ast.NotIn)
                    and isinstance(sub.left, ast.Constant)):
                ks = _const(sub.left)
                if ks:
                    found.append(ks)
        return found

    for sub in ast.walk(fn):
        if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) \
                and sub.value.id == "ctx":
            ks = _const(sub.slice)
            if ks:
                keys.add(ks)
        if isinstance(sub, ast.If):
            gk = guarded_keys(sub.test)
            if not gk:
                continue
            # anything in the test beyond the `not in ctx` guard is a
            # runtime condition on the key's existence
            def is_guard(v: ast.AST) -> bool:
                return (isinstance(v, ast.Compare)
                        and isinstance(v.ops[0], ast.NotIn))

            extra = [ast.unparse(v) for v in ast.walk(sub.test)
                     if isinstance(v, ast.Compare) and not is_guard(v)]
            if isinstance(sub.test, ast.BoolOp):
                extra += [ast.unparse(v) for v in sub.test.values
                          if not is_guard(v)]
            if extra:
                for ks in gk:
                    conditional.setdefault(ks, "; ".join(dict.fromkeys(extra)))
    return keys, conditional


# --------------------------------------------------------------------------
# corpus loading
# --------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    path: Path
    data: dict

    @property
    def when(self) -> dict:
        w = self.data.get("when")
        return w if isinstance(w, dict) else {}

    @property
    def then(self) -> dict:
        t = self.data.get("then")
        return t if isinstance(t, dict) else {}

    @property
    def actions(self) -> list[dict]:
        a = self.then.get("actions")
        if not isinstance(a, list):
            return []
        return [x for x in a if isinstance(x, dict)]

    def cmds(self) -> list[tuple[str, str]]:
        """(field, template) for every command variant the rule carries."""
        out = []
        for i, a in enumerate(self.actions):
            for k, v in a.items():
                if k.startswith("cmd") and isinstance(v, str):
                    out.append((f"actions[{i}].{k}", v))
            if isinstance(a.get("obs_url"), str):
                out.append((f"actions[{i}].obs_url", a["obs_url"]))
        return out


def load_corpus(rules_dir: Path) -> list[Rule]:
    rules: list[Rule] = []
    for p in sorted(Path(rules_dir).rglob("*.json")):
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError) as e:
            rules.append(Rule(id=f"<unparseable:{p.name}>", path=p,
                              data={"_error": str(e)}))
            continue
        if not isinstance(data, dict):
            # A2-2: a top-level list/string/number used to be skipped WITHOUT
            # A SINGLE ISSUE — the file silently left the census. It is a rule
            # file that does not describe a rule: report it like a parse error.
            rules.append(Rule(
                id=f"<non-dict:{p.name}>", path=p,
                data={"_error": f"top-level JSON is "
                                f"{type(data).__name__}, not an object"}))
            continue
        rules.append(Rule(id=str(data.get("id") or f"<no-id:{p.name}>"),
                          path=p, data=data))
    return rules


def _structure_defects(data: dict) -> list[str]:
    """Type-confusion shapes the checks cannot reason about (A2-2).

    Every one of these used to RAISE somewhere downstream (``{"all": 5}`` →
    TypeError in ``_leaves``; ``then``/``actions`` of the wrong type →
    AttributeError in the Rule properties' callers). The docstring's "never
    raises on a bad rule" only holds if structural corruption is detected
    here and reported as ``unparseable_rule`` instead.
    """
    defects: list[str] = []

    def walk_when(cond, where: str) -> None:
        if not isinstance(cond, dict):
            defects.append(f"{where} is {type(cond).__name__}, not an object")
            return
        for key in ("all", "any"):
            if key not in cond:
                continue
            group = cond[key]
            if not isinstance(group, list):
                defects.append(f"{where}.{key} is {type(group).__name__}, "
                               "not a list")
                continue
            for i, child in enumerate(group):
                walk_when(child, f"{where}.{key}[{i}]")
        if "not" in cond:
            walk_when(cond["not"], f"{where}.not")

    if "when" in data:
        walk_when(data["when"], "when")
    then = data.get("then")
    if then is not None and not isinstance(then, dict):
        defects.append(f"then is {type(then).__name__}, not an object")
    elif isinstance(then, dict) and "actions" in then:
        actions = then["actions"]
        if not isinstance(actions, list):
            defects.append(f"then.actions is {type(actions).__name__}, "
                           "not a list")
        else:
            for i, a in enumerate(actions):
                if not isinstance(a, dict):
                    defects.append(f"then.actions[{i}] is "
                                   f"{type(a).__name__}, not an object")
    return defects


def _leaves(cond: dict) -> list[dict]:
    """Every leaf condition in a (possibly nested) when-tree.

    Defensive against structurally corrupt trees (``{"all": 5}``, string
    children): ``_structure_defects`` reports those; this function must not
    raise on them because the corpus-level checks call it for EVERY rule.
    """
    if not isinstance(cond, dict):
        return []
    for key in ("all", "any"):
        if key in cond:
            group = cond[key]
            if not isinstance(group, list):
                return []
            out = []
            for c in group:
                out.extend(_leaves(c))
            return out
    if "not" in cond:
        return _leaves(cond["not"])
    return [cond] if cond.get("fact") else []


# --------------------------------------------------------------------------
# the checks
# --------------------------------------------------------------------------

@dataclass
class RuleReport:
    issues: list[RuleIssue] = field(default_factory=list)
    rules_total: int = 0
    unfireable: list[str] = field(default_factory=list)
    fireable: list[str] = field(default_factory=list)
    model: CorpusModel | None = None

    def add(self, severity: str, code: str, rule_id: str, message: str,
            evidence: str = "", fix: str = "") -> None:
        self.issues.append(RuleIssue(severity, code, rule_id, message,
                                     evidence, fix))

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "HIGH")

    def count(self, severity: str) -> int:
        return sum(1 for i in self.issues if i.severity == severity)

    def by_code(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for i in self.issues:
            out[i.code] = out.get(i.code, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "rules_total": self.rules_total,
            "fireable": len(self.fireable),
            "unfireable": sorted(self.unfireable),
            "counts": {s: self.count(s) for s in SEVERITIES},
            "by_code": self.by_code(),
            "issues": [i.to_dict() for i in self.issues],
        }

    def json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def markdown(self) -> str:
        lines = [
            "# rule corpus check",
            f"rules: {self.rules_total} | fireable {len(self.fireable)} | "
            f"never-fires {len(self.unfireable)}",
            f"issues: HIGH {self.count('HIGH')} / MEDIUM {self.count('MEDIUM')}"
            f" / LOW {self.count('LOW')}",
        ]
        if self.unfireable:
            lines.append("\n## rules that can never fire")
            for rid in sorted(self.unfireable):
                why = sorted({i.code for i in self.issues
                              if i.rule_id == rid and i.severity == "HIGH"})
                lines.append(f"- `{rid}` — {', '.join(why) or 'see issues'}")
        for sev in SEVERITIES:
            rows = [i for i in self.issues if i.severity == sev]
            if not rows:
                continue
            lines.append(f"\n## [{sev}] {len(rows)}")
            for i in sorted(rows, key=lambda x: (x.code, x.rule_id)):
                lines.append(f"- **{i.code}** `{i.rule_id}`: {i.message}")
                if i.evidence:
                    lines.append(f"  - evidence: {i.evidence}")
                if i.fix:
                    lines.append(f"  - fix: {i.fix}")
        return "\n".join(lines)


def check_corpus(rules_dir: Path, *, core_dir: Path | None = None,
                 resolve_tools: bool = True) -> RuleReport:
    """Run every static check over the corpus. Never raises on a bad rule.

    A2-2 made that promise true: structural corruption (a non-dict top level,
    ``{"all": 5}``, string actions) lands as an ``unparseable_rule`` HIGH
    instead of a TypeError/AttributeError or a silent skip.
    """
    rules_dir = Path(rules_dir)
    report = RuleReport()
    model = derive_model(core_dir)
    report.model = model
    rules = load_corpus(rules_dir)
    report.rules_total = len(rules)

    seen_ids: dict[str, Path] = {}
    signatures: dict[tuple, list[str]] = {}
    declared_by: dict[str, set[str]] = {}
    for r in rules:
        hit = (r.then or {}).get("on_hit_class")
        if isinstance(hit, str) and hit:
            declared_by.setdefault(hit, set()).add(r.id)
    declared_classes: set[str] = set(declared_by)

    for r in rules:
        if r.data.get("_error"):
            report.add("HIGH", "unparseable_rule", r.id,
                       f"rule file does not parse: {r.data['_error']}",
                       evidence=str(r.path),
                       fix="repair the JSON or retire the file")
            continue
        defects = _structure_defects(r.data)
        if defects:
            # A2-2: type confusion is a broken rule, not a crash and not a
            # silent skip — one HIGH, then the per-rule checks are skipped
            # (their preconditions do not hold on a corrupt structure).
            report.add("HIGH", "unparseable_rule", r.id,
                       "rule structure is corrupt: " + "; ".join(defects),
                       evidence=_rel(r),
                       fix="repair the JSON or retire the file")
            continue
        _check_identity(r, seen_ids, report)
        _check_when(r, model, report, declared_by)
        _check_actions(r, model, report, resolve_tools)
        sig = _signature(r)
        if sig:
            signatures.setdefault(sig, []).append(r.id)

    _check_chain_wire(rules, model, report)
    _check_class_coverage(rules, model, declared_classes, report)
    _check_duplicates(signatures, report)
    _dedupe(report)
    return report


def _dedupe(report: RuleReport) -> None:
    """One row per (severity, code, rule, message).

    A rule carrying cmd/cmd_stealth/cmd_aggressive would otherwise report the
    same missing placeholder three times, which buries the distinct findings.
    """
    seen: set[tuple] = set()
    out: list[RuleIssue] = []
    for i in report.issues:
        k = (i.severity, i.code, i.rule_id, i.message)
        if k in seen:
            continue
        seen.add(k)
        out.append(i)
    report.issues = out


def _rel(r: Rule) -> str:
    try:
        return str(r.path.relative_to(r.path.parents[2]))
    except (IndexError, ValueError):
        return r.path.name


def _check_identity(r: Rule, seen: dict[str, Path], report: RuleReport) -> None:
    if r.id in seen:
        report.add("HIGH", "duplicate_rule_id", r.id,
                   f"rule id {r.id!r} is defined twice — every asset gets the "
                   "action twice",
                   evidence=f"{seen[r.id]} and {_rel(r)}",
                   fix="retire one copy to the retired-rules area and record "
                       "the reason in its README")
        return
    seen[r.id] = r.path
    if not r.data.get("category"):
        report.add("MEDIUM", "no_category", r.id,
                   "no category — the hypothesis lands outside every reserved "
                   "ACT slot and competes on priority alone",
                   evidence=_rel(r),
                   fix='add "category": one of vuln/scan/context/tech/'
                       'injection/access/chain')


def _check_when(r: Rule, model: CorpusModel, report: RuleReport,
                declared_by: dict[str, set[str]]) -> None:
    when = r.when
    if not when:
        report.add("HIGH", "no_when", r.id,
                   "no when clause — hypothesis_engine refuses to match it, "
                   "so the rule can never fire",
                   evidence=_rel(r), fix="declare explicit conditions")
        return
    leaves = _leaves(when)
    if not leaves:
        report.add("HIGH", "no_leaves", r.id,
                   "when clause contains no fact leaf — nothing to match on",
                   evidence=json.dumps(when, ensure_ascii=False)[:160],
                   fix='each leaf needs {"fact": ..., "op": ..., "value": ...}')

    dead: set[str] = set()          # facts that can never carry a value
    dead_leaves: set[int] = set()   # leaves whose VALUE nothing can produce
    for leaf in leaves:
        fact = str(leaf.get("fact"))
        op = str(leaf.get("op", "eq"))
        if fact not in model.fact_keys:
            report.add("HIGH", "unknown_fact", r.id,
                       f"when gates on fact {fact!r}, which _fact_view never "
                       "emits — the leaf is silently False forever",
                       evidence=f"{_rel(r)} op={op}",
                       fix=f"produce the fact, or gate on one of: "
                           f"{', '.join(sorted(model.fact_keys))}")
            dead.add(fact)
            continue
        if not model.fact_producible(fact):
            fields = sorted(model.fact_fields.get(fact) or [])
            kinds = sorted(model.fact_kinds.get(fact) or [])
            why = (f"no parser or engine path writes asset field "
                   f"{fields}" if fields else
                   f"nothing creates a {kinds} entity")
            report.add("HIGH", "fact_unproducible", r.id,
                       f"fact {fact!r} is emitted but can never carry a value: "
                       f"{why}",
                       evidence=f"{_rel(r)} op={op} value={leaf.get('value')!r}",
                       fix="write the fact from a parser (the waf/http2 "
                           "pattern), or retire the rule")
            dead.add(fact)
            continue
        if _check_leaf_value(r, leaf, model, report, declared_by):
            dead_leaves.add(id(leaf))

    # reachability: an `all` group with one dead leaf kills the whole rule;
    # an `any` group only dies when every branch is dead.
    if _rule_is_unfireable(when, dead, dead_leaves):
        report.unfireable.append(r.id)
    else:
        report.fireable.append(r.id)


def _rule_is_unfireable(when: dict, dead: set[str],
                        dead_leaves: set[int]) -> bool:
    """Conservative satisfiability test over the boolean tree.

    Only claims "unfireable" when it can prove it: an ``all`` dies if any
    child dies, an ``any`` dies only if every child dies, and a ``not`` is
    always treated as satisfiable (negating a dead leaf is exactly how a rule
    expresses "no WAF here").
    """
    def ev(cond: dict) -> bool:
        if not isinstance(cond, dict):
            return False
        if "all" in cond:
            return any(ev(c) for c in cond["all"])
        if "any" in cond:
            return bool(cond["any"]) and all(ev(c) for c in cond["any"])
        if "not" in cond:
            return False
        fact = cond.get("fact")
        if fact is None:
            return False
        return str(fact) in dead or id(cond) in dead_leaves

    return ev(when)


def _check_leaf_value(r: Rule, leaf: dict, model: CorpusModel,
                      report: RuleReport,
                      declared_by: dict[str, set[str]]) -> bool:
    'A fact that exists but whose VALUE nothing can ever produce.'
    declared_all = set(declared_by)
    # what a DIFFERENT rule could mint for this one, and what only r itself can
    declared_others = {c for c, owners in declared_by.items() if owners - {r.id}}
    declared_self = {c for c, owners in declared_by.items() if r.id in owners}
    fact = str(leaf.get("fact"))
    value = leaf.get("value")
    op = str(leaf.get("op", "eq"))
    dead = False
    if op not in SUPPORTED_OPS:
        report.add("HIGH", "unknown_op", r.id,
                   f"when uses op {op!r}, which _eval does not implement — it "
                   "raises ValueError on every asset instead of matching "
                   "nothing",
                   evidence=f"{_rel(r)} fact={fact}",
                   fix=f"use one of: {', '.join(sorted(SUPPORTED_OPS))}")
        return True
    if op == "matches":
        if isinstance(value, str):
            try:
                re.compile(value)
            except re.error as e:
                report.add("HIGH", "bad_regex", r.id,
                           f"when op=matches with an uncompilable pattern — "
                           f"re.error({e}) on every asset",
                           evidence=f"{_rel(r)} pattern={value!r}",
                           fix="escape the pattern, or use contains")
                return True
        else:
            # A2-6: runtime is re.search(value, ...) — a non-str pattern
            # raises TypeError on every asset. bad_regex never saw this shape
            # because it only compiles str values.
            report.add("HIGH", "matches_value_not_str", r.id,
                       f"when op=matches with a {type(value).__name__} value — "
                       "re.search raises TypeError on every asset instead of "
                       "matching",
                       evidence=f"{_rel(r)} fact={fact} value={value!r}",
                       fix="use a string pattern, or contains/intersects")
            return True
    if fact == "class":
        # A2-6: the class fact is ALWAYS a list (every finding class on the
        # asset). _eval's `in` compares the WHOLE list against the value's
        # members, and eq/contains with a list value compare list-against-str
        # (or the value's repr) — none of these can ever match an element.
        # They used to slip past the isinstance(value, str) guard and count
        # as fireable.
        if op == "in" or (op in ("eq", "==", "contains")
                          and isinstance(value, list)):
            report.add("HIGH", "class_op_runtime_dead", r.id,
                       f"when gates the class LIST with op={op!r} "
                       f"value={value!r} — _eval compares the whole list (or "
                       "its repr), never element-wise, so the leaf can never "
                       "match",
                       evidence=_rel(r),
                       fix="use contains with a string value (substring per "
                           "element) or intersects with a list (membership)")
            dead = True
        else:
            if op == "intersects":
                members = ([str(x) for x in value]
                           if isinstance(value, list) else [str(value)])
                member_op = "eq"          # intersects is set membership
            elif isinstance(value, str):
                members, member_op = [value], op
            else:
                members, member_op = [], op   # ne+list etc.: always-true at
                                              # runtime, nothing to validate
            if members and not any(
                    _class_producible(mv, model.produced_classes, member_op)
                    for mv in members):
                declared_hit = any(
                    _class_producible(mv, declared_others, member_op)
                    for mv in members)
                self_hit = any(
                    _class_producible(mv, declared_self, member_op)
                    for mv in members)
                if not declared_hit and self_hit:
                    names = ', '.join(sorted(declared_self))
                    if _rule_is_unfireable(r.when, set(), {id(leaf)}):
                        report.add("HIGH", "class_self_declared", r.id,
                                   f"when gates on class {value!r}, whose only "
                                   f"producer is this rule's own on_hit_class "
                                   f"({names}) — the mint follows a hit and the "
                                   "hit requires the fire, and no other branch "
                                   "of the when clause is satisfiable, so the "
                                   "rule can never start",
                                   evidence=_rel(r),
                                   fix="give the class an external producer (a "
                                       "parser class-map row, or another rule "
                                       "that declares it), re-gate the when "
                                       "clause on a producible fact, or retire "
                                       "the rule")
                        dead = True
                    else:
                        # The leaf is dead but the rule survives on another
                        # branch. Not a HIGH (nothing is broken today) and not
                        # silence either: if that branch is ever removed or its
                        # fact stops being produced, the rule dies quietly.
                        report.add("MEDIUM", "class_leaf_self_declared", r.id,
                                   f"the class leaf {value!r} can never match — "
                                   f"its only producer is this rule's own "
                                   f"on_hit_class ({names}); the rule fires "
                                   "only through its other branches",
                                   evidence=_rel(r),
                                   fix="give the class an external producer, or "
                                       "drop the dead leaf so the when clause "
                                       "says what actually fires the rule")
                elif declared_hit and model.chain_consumers:
                    pass
                elif declared_hit:
                    report.add("HIGH", "class_needs_on_hit_wire", r.id,
                               f"when gates on class {value!r}, which another "
                               "rule declares as on_hit_class — but nothing "
                               "in core/ consumes that field, so no finding "
                               "of that class is ever minted and the chain "
                               "cannot start",
                               evidence=_rel(r),
                               fix="wire on_hit_class into the finding minted "
                                   "on a rule hit (orchestrator._act), which "
                                   "revives every rule in this shape")
                    dead = True
                else:
                    report.add("HIGH", "class_unproducible", r.id,
                               f"when gates on class {value!r}, which no "
                               "parser emits and no rule declares — the leaf "
                               "can never match",
                               evidence=f"{_rel(r)} op={op}; declared "
                                        f"upstream: "
                                        f"{', '.join(sorted(declared_all)) or 'none'}",
                               fix="declare it as some rule's on_hit_class, "
                                   "add it to a parser's class map, or retire "
                                   "the rule")
                    dead = True
    if fact == "service" and isinstance(value, str):
        low = value.lower()
        for want, real in NMAP_SERVICE_ALIASES.items():
            if want in low and not any(x in low for x in real):
                report.add("HIGH", "service_name_mismatch", r.id,
                           f"when gates on service {value!r}; nmap reports "
                           f"{'/'.join(real)} for that protocol, so the leaf "
                           "never matches a real host",
                           evidence=_rel(r),
                           fix='gate on the nmap name, or on the services '
                               'LIST with op=intersects (service is only '
                               'svcs[0], the lowest open port)')
                dead = True
    if fact == "service":
        report.add("MEDIUM", "service_fact_truncated", r.id,
                   "gating on `service` reads only svcs[0] (the lowest open "
                   "port) — a DC with 53/80/443 open never exposes kerberos "
                   "there",
                   evidence=_rel(r),
                   fix='use {"fact":"services","op":"intersects","value":[...]}')
    # A2-7: the `level_requires_access_entity` advisory that used to sit here
    # was unreachable — `level` is fact_unproducible (nothing creates an
    # access entity), and _check_when continues before _check_leaf_value ever
    # runs. fact_unproducible's own message carries the cause.
    return dead


def _class_producible(value: str, produced: set[str], op: str = "contains") -> bool:
    """Could a produced class satisfy this leaf, under its own op?

    ``_eval`` semantics differ by op and the difference decides whether a
    chain rule is alive: ``contains`` on the class LIST is a case-insensitive
    substring test per element — ONE-WAY, the gated value must be a substring
    of the produced class (so gating on "idor" matches "idor.confirmed", but
    gating on "idor.confirmed" never matches a produced "idor"; A2-6 removed
    the reverse test that certified exactly that dead shape), while
    ``eq``/``in``/``intersects`` are exact membership (so "idor" matches
    nothing). ``value`` must be a str; list values are handled by the caller
    (they are runtime-dead shapes or normalized intersects members).
    """
    if not isinstance(value, str):
        return False
    for c in produced:
        if op in ("eq", "==", "in", "intersects"):
            if c == value:
                return True
        elif op in ("ne", "!="):
            if c != value:
                return True
        elif op == "matches":
            # runtime searches the pattern against the class LIST's str();
            # the class appears in it verbatim, so a pattern matching the
            # produced class matches at runtime too (anchored patterns are
            # the known fail-open edge).
            try:
                if re.search(value, c):
                    return True
            except (re.error, TypeError):
                return False          # bad_regex reports it separately
        else:                                   # contains
            if value.lower() in c.lower():
                return True
    return False


def _check_actions(r: Rule, model: CorpusModel, report: RuleReport,
                   resolve_tools: bool) -> None:
    actions = r.actions
    hits: dict[tuple, list[str]] = {}
    if not actions:
        report.add("MEDIUM", "no_actions", r.id,
                   "rule has no actions — _prioritize drops it (a hypothesis "
                   "without actions never becomes work)",
                   evidence=_rel(r),
                   fix="declare actions, or make it an LLM-proposal-only rule")
        return
    for i, a in enumerate(actions):
        tool = str(a.get("tool") or "")
        where = f"actions[{i}]"
        if not tool:
            report.add("HIGH", "no_tool", r.id, f"{where} has no tool",
                       evidence=_rel(r), fix='add "tool": "<binary name>"')
            continue
        if tool == "shell":
            report.add("HIGH", "pseudo_tool_shell", r.id,
                       f'{where} names tool "shell" — there is no such binary, '
                       "and cmd rendering is shlex-based with no shell, so "
                       "`;` and `|` become literal argv tokens",
                       evidence=f"{_rel(r)}: {str(a.get('cmd'))[:80]}",
                       fix="split into one action per binary, or run it "
                           "through a real interpreter action")
        elif a.get("runtime") == _CONTAINER_RUNTIME:
            # A2-7: container binaries are not on the host, so resolve_tool
            # cannot see them — skipping host resolution is the whole check.
            # The old container_tool_unverified advisory needed a
            # container_tools manifest no caller ever passed (dead since day
            # one); image contents are verified by `motoko doctor`, live.
            pass
        elif resolve_tools:
            from . import executor
            if not executor.resolve_tool(tool):
                report.add("HIGH", "tool_unresolvable", r.id,
                           f"{where} names {tool!r}, which resolves to nothing "
                           "(~/.local/bin -> $MOTOKO_TOOLS-or-package-tools "
                           "bin/ -> nuclei/ -> PATH — executor."
                           "_known_tool_dirs order) — the action records "
                           "exit 127 and burns three strikes per asset",
                           evidence=_rel(r),
                           fix=f"install/anchor {tool}, or retire the rule")
        if tool not in model.parser_tools:
            report.add("HIGH", "tool_without_parser", r.id,
                       f"{where} runs {tool!r} but no parser is registered for "
                       "it — even a successful run dead-letters and yields "
                       "zero graph",
                       evidence=f"{_rel(r)}; registered: "
                                f"{', '.join(sorted(model.parser_tools))}",
                        fix=f"write core/parsers/{tool.replace('-', '_')}.py, "
                            "or route the output through a tool that has one")
        if tool != "shell":
            own_cmd = f"actions[{i}].cmd"
            for field_name, template in r.cmds():
                # obs_url is a URL, not an invocation: argv[0] of a rendered
                # obs_url becomes the observation URL (see _check_opsec_flags).
                if not field_name.startswith(own_cmd):
                    continue
                try:
                    first = shlex.split(template)[0]
                except (ValueError, IndexError):
                    continue   # unbalanced quote / empty cmd: other rows own it
                if first != tool:
                    report.add("HIGH", "cmd_tool_mismatch", r.id,
                               f"{field_name} starts with {first!r} but the "
                               f"action declares tool={tool!r} — the executor "
                               "replaces argv[0] with the resolved binary, so "
                               f"{first!r} is silently discarded and {tool} "
                               "runs with the remaining tokens",
                               evidence=f"{_rel(r)}: {template[:90]}",
                               fix=f"start the command with {tool}, or declare "
                                   "the binary this command actually names")

        own = f"actions[{i}]."
        for field_name, template in r.cmds():
            if not field_name.startswith(own):
                continue
            from .parsers import dependency_context_keys
            intensity = field_name.split("cmd_", 1)[1] if "cmd_" in field_name else "normal"
            _collect_placeholders(model, template, field_name, a, hits,
                                  dependency_context_keys(actions, i, intensity))
            if not field_name.endswith(".obs_url"):
                _check_opsec_flags(r, report, tool, template, field_name)

    # one row per (rule, placeholder): a rule carrying cmd/cmd_stealth/
    # cmd_aggressive has one defect, not three, and the repair is the same.
    for (code, sev, name, msg, fix), fields in sorted(hits.items()):
        report.add(sev, code, r.id, msg,
                   evidence=f"{_rel(r)}; rendered by "
                            f"{', '.join(sorted(set(fields)))}",
                   fix=fix)


def _collect_placeholders(model: CorpusModel, template: str, field_name: str,
                          action: dict, hits: dict[tuple, list[str]],
                          result_keys: set[str] | None = None) -> None:
    """Accumulate placeholder defects for one command template.

    Three cases, in ascending danger:

    * producible — the engine supplies it, nothing to report;
    * declared but unproduced (``cmd.CTX_KEYS`` with no writer) — caught at ACT
      time by the fail-closed gate, so the action never runs. Costly but
      contained: the hypothesis retires as error and three strikes ban the
      (rule, asset) pair;
    * undeclared — NOT caught by the gate. ``render_command`` leaves unknown
      placeholders verbatim by design ("visible, never a silent blank"), so
      the literal text ``{token2}`` is sent to the target inside argv. This is
      the only case that puts garbage on the wire, and it is silent.

    curl's own ``-w '%{http_code}'`` format strings use the same braces; they
    are data and are excluded by span, not by name.
    """
    literal_spans = [(m.start(), m.end())
                     for m in _LITERAL_BRACE_RE.finditer(template)]
    supplied = model.producible_ctx | (result_keys or set())
    action_keys = {str(k).lower() for k in action} & set(cmd.CTX_KEYS)
    for m in _PLACEHOLDER_RE.finditer(template):
        if any(a <= m.start() < b for a, b in literal_spans):
            continue
        name = m.group(1)
        low = name.lower()
        if low in supplied or low in action_keys:
            continue
        cond = model.ctx_conditional.get(low)
        if cond:
            key = ("placeholder_conditional", "MEDIUM", name,
                   f"renders {{{name}}}, which _command_ctx injects only when "
                   f"`{cond}` — on any "
                   "engagement without it the ACT gate refuses the action and "
                   "the hypothesis retires as error",
                   "make the backend a doctor requirement, or gate the rule on "
                   "a fact that proves the backend exists")
        elif low in cmd.CTX_KEYS:
            key = ("placeholder_no_producer", "HIGH", name,
                   f"renders {{{name}}}, a declared context key with no "
                   "producer — the ACT fail-closed gate refuses the action, "
                   "the hypothesis retires as error, and after three strikes "
                   "the (rule, asset) pair is banned forever",
                   f"supply {{{name}}} from the hypothesis/asset, or retire "
                   "the rule")
        else:
            key = ("placeholder_verbatim", "HIGH", name,
                   f"renders {{{name}}}, which is not a context key — the ACT "
                   "gate does not catch it, so the literal braces are sent to "
                   "the target inside argv",
                   f"add {name} to cmd.CTX_KEYS with a producer, or remove the "
                   "placeholder")
        hits.setdefault(key, []).append(field_name)


def _check_opsec_flags(r: Rule, report: RuleReport, tool: str,
                       template: str, field_name: str) -> None:
    low = template.lower()
    if tool in UA_CAPABLE_TOOLS and "{ua}" not in low \
            and "user-agent" not in low:
        report.add("MEDIUM", "missing_ua", r.id,
                   f"{field_name} drives {tool} without rendering {{ua}} — "
                   "the tool ships its own scanner fingerprint (the internal doctrine "
                   "requires one UA per engagement on every rule)",
                   evidence=f"{_rel(r)}: {template[:90]}",
                   fix="add the tool's UA/header flag with {ua}")
    patterns = RATE_LIMIT_FLAGS.get(tool)
    if patterns and not any(p in low for p in patterns):
        report.add("MEDIUM", "missing_rate_limit", r.id,
                   f"{field_name} drives {tool} at its default cadence "
                   f"(none of {', '.join(patterns)} present) — the internal doctrine "
                   "throttling is not applied",
                   evidence=f"{_rel(r)}: {template[:90]}",
                   fix="add rate limiting, or a cmd_stealth variant")


# Modules that touch the chain fields without being a runtime consumer:
# hypothesis_engine WRITES them onto the hypothesis, graph_health reads the
# rule FILES to report orphans, and this module is the static checker itself.
_NON_CONSUMERS = frozenset({"hypothesis_engine.py", "graph_health.py",
                            "rulecheck.py"})


def _derive_chain_consumers(core_dir: Path) -> tuple[set[str], set[str]]:
    """Which modules actually READ on_hit_class / chain_hint at runtime."""
    hit, hint = set(), set()
    for path, tree in _modules(core_dir):
        if path.name in _NON_CONSUMERS:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript):
                ks = _const(node.slice)
                if ks == "on_hit_class":
                    hit.add(path.name)
                elif ks == "chain_hint":
                    hint.add(path.name)
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr == "get" and node.args):
                ks = _const(node.args[0])
                if ks == "on_hit_class":
                    hit.add(path.name)
                elif ks == "chain_hint":
                    hint.add(path.name)
    return hit, hint


def _check_chain_wire(rules: list[Rule], model: CorpusModel,
                      report: RuleReport) -> None:
    """Corpus-level: does the chaining subsystem have a consumer at all?

    Reported once, not per rule — the defect is one missing wire, and 29
    identical rows would bury it.
    """
    declarers = {r.id: str(r.then.get("on_hit_class"))
                 for r in rules if r.then.get("on_hit_class")}
    if declarers and not model.chain_consumers:
        declared = set(declarers.values())
        # "blocked" means dead UNTIL THE WIRE EXISTS — a leaf some parser
        # already satisfies is alive today and must not inflate the wire's
        # revival statistics (audit A2: with the AnnAssign fix, LFI/SSTI/
        # ACTUATOR left this list because nuclei produces their classes).
        blocked = sorted({
            r.id for r in rules
            for leaf in _leaves(r.when)
            if str(leaf.get("fact")) == "class"
            and isinstance(leaf.get("value"), str)
            and str(leaf.get("op", "eq")) != "in"   # runtime-dead on a list
            and _class_producible(leaf["value"], declared,
                                  str(leaf.get("op", "eq")))
            and not _class_producible(leaf["value"], model.produced_classes,
                                      str(leaf.get("op", "eq")))})
        report.add(
            "HIGH", "chain_wire_missing", "<corpus>",
            f"{len(declarers)} rules declare on_hit_class; no module outside "
            "the rule loader reads it, so a rule hit never becomes a finding "
            "of that class and the corpus cannot chain — every TECH rule that "
            "exists to feed a VULN rule feeds nothing",
            evidence="declares: " + ", ".join(sorted(declarers))[:220],
            fix="in orchestrator._act, when a hypothesis from a rule carrying "
                "on_hit_class lands a hit, mint a finding with that class "
                "(the parsers already do this via class_=)")
        if blocked:
            report.add(
                "HIGH", "chain_wire_blocks_rules", "<corpus>",
                f"{len(blocked)} rules gate on a class only on_hit_class "
                f"could produce: {', '.join(blocked)}",
                evidence="these are dead until the wire exists",
                fix="land chain_wire_missing first, then re-run --report")
    hinters = sorted({r.id for r in rules if r.then.get("chain_hint")})
    if hinters and not model.chain_hint_consumers:
        report.add(
            "LOW", "chain_hint_unconsumed", "<corpus>",
            f"{len(hinters)} rules declare chain_hint and nothing reads it — "
            "the scheduler does not weight hinted successors",
            evidence=", ".join(hinters)[:220],
            fix="consume chain_hint in _prioritize, or drop the declarations")


def _check_class_coverage(rules: list[Rule], model: CorpusModel,
                          declared_classes: set[str],
                          report: RuleReport) -> None:
    """Corpus-level: which produced classes nobody reacts to.

    Only AFFIRMATIVE gates consume: a ``ne`` leaf fires on the class's
    ABSENCE — it is not a follow-up to that class (A2-6: counting it hid the
    "detection lands, nothing reacts" case). Consumption is evaluated under
    each leaf's own op and in _eval's direction (gated value → produced
    class), not the old argument-inverted two-way scan.
    """
    consumed: list[tuple[str, str]] = []      # (op, gated member)
    for r in rules:
        for leaf in _leaves(r.when):
            if str(leaf.get("fact")) != "class":
                continue
            op = str(leaf.get("op", "eq"))
            if op in ("ne", "!="):
                continue
            v = leaf.get("value")
            if isinstance(v, str):
                consumed.append((op, v))
            elif isinstance(v, list) and op == "intersects":
                consumed.extend(("eq", str(x)) for x in v)
            # other list-value shapes never match at runtime
            # (class_op_runtime_dead reports them per rule); they consume
            # nothing.
    gated = sorted({v for _o, v in consumed})
    produced = set(model.produced_classes)
    if model.chain_consumers:
        produced |= declared_classes
    # Lazy import, like the executor one below: the checker must stay loadable
    # when the verification package is not (and a cycle here would be silent).
    from . import verification
    for cls in sorted(produced):
        if any(_class_producible(v, {cls}, o) for o, v in consumed):
            continue
        # Derived, not asserted: the router is the second consumer of a class,
        # and its answer belongs in the row. Saying "nothing follows up" — the
        # wording this shipped with — was false for all 26 live rows and points
        # at the wrong fix (write a rule per class, or silence the check).
        validator = verification.pick_validator({"class": cls})
        report.add("MEDIUM", "class_without_response", "<corpus>",
                   f"class {cls!r} is produced (parser or on_hit_class wire) "
                   "but no RULE gates on it — the finding is still verified "
                   f"(validator: {validator}) and still reaches digest and "
                   "reports; what is absent is a rule-side follow-up step",
                   evidence="gated classes: "
                            f"{', '.join(gated) or 'none'}"
                            f" | declared classes: "
                            f"{', '.join(sorted(declared_classes)) or 'none'}",
                   fix=f"add a chain/verification rule for {cls} ONLY if a "
                       "follow-up action exists in this engine — the finding "
                       "may be terminal by design (a confirmed hit needs no "
                       "further probe), and the post-ex channel the retired "
                       "`access` rules needed does not exist here")


def _signature(r: Rule) -> tuple | None:
    """Identity for duplicate detection: the when-tree plus every command."""
    if r.data.get("_error"):
        return None
    cmds = tuple(t for _f, t in sorted(r.cmds()))
    if not cmds:
        return None
    return (json.dumps(r.when, sort_keys=True, ensure_ascii=False), cmds)


def _check_duplicates(signatures: dict[tuple, list[str]],
                      report: RuleReport) -> None:
    for sig, ids in signatures.items():
        if len(ids) < 2:
            continue
        report.add("MEDIUM", "duplicate_rule", ids[0],
                   f"rules {', '.join(sorted(ids))} share an identical when "
                   "clause AND identical commands — they mint twice, fire "
                   "twice, and double the request volume on the target",
                   evidence=json.dumps(sig[1], ensure_ascii=False)[:120],
                   fix="merge into one rule with both actions, or retire one")


_RETIRED_ACK = re.compile(r"\bretire|退休|退役", re.IGNORECASE)
_GHOST_ACK = ("never existed", "从未存在", "从不存在")


def _doc_blocks(text: str) -> list[tuple[int, int]]:
    """(start, end) offsets of each blank-line-delimited block, in order."""
    blocks: list[tuple[int, int]] = []
    start = 0
    for m in re.finditer(r"\n\s*\n", text):
        blocks.append((start, m.start()))
        start = m.end()
    blocks.append((start, len(text)))
    return blocks


def check_docs_drift(rules_dir: Path, docs: list[Path]) -> list[RuleIssue]:
    'Every rule id a doc claims exists must exist (tool-registry drift).'
    have = {r.id for r in load_corpus(rules_dir)}
    attic = Path(rules_dir).resolve().parent / _ATTIC_DIRNAME
    retired = ({r.id for r in load_corpus(attic)}
               if attic.is_dir() else set())
    # General shape, not a prefix allowlist: an allowlist silently stops
    # matching the day a new category directory appears, which is exactly how
    # tool-registry.md drifted. R-<CATEGORY>-<NAME> is the corpus convention.
    pattern = re.compile(r"\bR-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+")
    out: list[RuleIssue] = []
    for doc in docs:
        try:
            text = doc.read_text()
        except OSError:
            continue
        blocks = _doc_blocks(text)
        bi = 0
        for m in pattern.finditer(text):
            rid = m.group(0)
            if rid in have:
                continue
            while bi + 1 < len(blocks) and blocks[bi + 1][0] <= m.start():
                bi += 1
            block = text[blocks[bi][0]:blocks[bi][1]]
            line = text.count("\n", 0, m.start()) + 1
            where = f"{_rel_to_root(doc)}:{line}"
            if rid in retired:
                if _RETIRED_ACK.search(block):
                    continue
                out.append(RuleIssue(
                    "LOW", "doc_references_retired_rule", rid,
                    f"{where} cites retired rule {rid} with no "
                    "acknowledgment — it reads as a live rule",
                    evidence=where,
                    fix="say the rule is retired at the mention and point "
                        "at the retired-rules area (the attic README carries the "
                        "reason)"))
            else:
                if any(a in block for a in _GHOST_ACK):
                    continue
                out.append(RuleIssue(
                    "LOW", "doc_references_missing_rule", rid,
                    f"{where} documents rule {rid}, which does "
                    "not exist in the corpus",
                    evidence=where,
                    fix="write the rule, or correct the doc"))
    return out


def docs_for(rules_dir: Path) -> list[Path]:
    """The docs that ship WITH this corpus, not the global repo root.

    Deriving from ``rules_dir`` keeps ``--rules-dir`` honest: pointing the
    checker at a synthetic corpus must not report drift against the real
    ``engine/docs``.
    """
    engine = Path(rules_dir).resolve().parent      # .../engine
    out = sorted((engine / "docs").glob("*.md"))
    for cand in (engine.parent / "the internal design notes", engine / "the internal design notes"):
        if cand.exists():
            out.append(cand)
    return out


def _rel_to_root(p: Path) -> str:
    """Doc paths relative to the repo root, so the report stays readable."""
    try:
        return str(p.relative_to(util.motoko_root()))
    except ValueError:
        return p.name


def rules_dir_default() -> Path:
    """Thin wrapper kept for existing callers; the resolver is util's."""
    return util.default_rules_dir()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_rules(args) -> int:
    """``motoko rules`` — static corpus check. Exit 2 only on a broken corpus."""
    rules_dir = Path(args.rules_dir or rules_dir_default())
    if not rules_dir.is_dir():
        print(f"rules dir not found: {rules_dir}", file=sys.stderr)
        return 2
    report = check_corpus(rules_dir, resolve_tools=not args.no_resolve)
    if args.docs:
        report.issues.extend(check_docs_drift(rules_dir, docs_for(rules_dir)))

    if args.json:
        print(report.json())
    elif args.report:
        print(report.markdown())
    else:
        counts = {s: report.count(s) for s in SEVERITIES}
        print(f"rules {report.rules_total} | fireable {len(report.fireable)}"
              f" | never-fires {len(report.unfireable)}")
        print(f"HIGH {counts['HIGH']} / MEDIUM {counts['MEDIUM']} / "
              f"LOW {counts['LOW']}")
        for code, n in sorted(report.by_code().items(),
                              key=lambda x: (-x[1], x[0])):
            print(f"  {n:4} {code}")
        if report.unfireable:
            print("\nnever fires:")
            for rid in sorted(report.unfireable):
                codes = sorted({i.code for i in report.issues
                                if i.rule_id == rid and i.severity == "HIGH"})
                print(f"  {rid:30} {', '.join(codes)}")
        print("\n--report full text | --json machine-readable | "
              "--strict fails CI on HIGH")

    if args.strict and report.high_count:
        print(f"\nstrict: {report.high_count} HIGH issue(s)", file=sys.stderr)
        return 1
    return 0
