"The VERIFY beat — independent verification of loop findings.\n\nThe independence is STRUCTURAL here, not a promise. The two forms this module\nruns are both machine checks that never consult the finding's own claim about\nitself:\n\n2. **Static-tool mapping.** The finding's ``evidence`` must name a file:line\n   that a real static tool (pyflakes, same run ``_static_analysis`` measures)\n   reports on. A citation that maps to nothing is an unbacked claim.\n\n3. **Minimal PoC execution** — deliberately NOT built. Sandboxed execution is\n   a channel this engine has never had, and inventing one here would be the\n   post-execution side that retired the whole ``access`` pack. Findings that\n   need it land in the backlog as ``unverifiable``.\n\n* reproduced      -> ``verified_true``   (promoted, scored)\n* unreproducible  -> ``verified_false`` + severity demoted to LOW, source\n                     label kept, ``unreproduced`` marker appended. Entries are\n                     NEVER deleted — a demoted row is evidence about the leg\n                     that produced it, which is what the reputation score\n                     consumes.\n* neither form    -> ``unverifiable``    (backlogged)\n\n``verified_true`` is produced ONLY here. ``_round_findings`` stamps\n``consensus_confirmed`` for everything else, and both statuses block\nconvergence equally (``loop_evaluate.CONFIRMED_STATUSES``) — the distinction is\nabout evidence strength, not about strictness.\n"

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .loop_evaluate import VERIFY_BUDGET

VERIFIED_TRUE = "verified_true"
VERIFIED_FALSE = "verified_false"
UNVERIFIABLE = "unverifiable"

DEMOTED_SEVERITY = "LOW"
UNREPRODUCED = "unreproduced"

# The three verification forms, named so a result can say which one fired.
FORM_REPRO = "repro_test"
FORM_STATIC = "static_mapping"

# evidence lines that cite a location: "core/loop.py:1083" or "path:12:3"
_LOC = re.compile(r"([^\s:;,)\]]+\.py):(\d+)")


# Exit classes that mean "the test suite reproduced the defect", as opposed to
# "the probe could not run". pytest: 0 ok, 1 tests failed, 2 interrupted,
# 3 internal error, 4 usage error, 5 no tests collected. unittest: 0 ok,
# 1 failures/errors, 2 bad invocation. Only 1 is evidence of a defect: a usage
# error (exit 4, e.g. `pytest tests/no_such_file.py`) or a missing binary
# (127) is a broken probe, and treating it as proof is exactly how a claimant
# mints verified_true out of `false` or `exit 1`.
_EVIDENCE_EXIT = frozenset({1})

_TEST_RUNNER = re.compile(
    r"(^|[\s/])(pytest|py\.test|unittest)([\s/]|$)|-m\s+(pytest|unittest)\b")


@dataclass
class VerifyResult:
    """What the beat decided about ONE queue entry, and on what form."""
    finding_id: str
    status: str
    form: str | None = None
    reason: str = ""
    evidence: str = ""


@dataclass
class VerifyReport:
    ''
    results: list[VerifyResult] = field(default_factory=list)
    backlog: list[dict] = field(default_factory=list)
    budget: int = VERIFY_BUDGET

    @property
    def verified_ids(self) -> set[str]:
        return {r.finding_id for r in self.results
                if r.status == VERIFIED_TRUE}

    @property
    def refuted_ids(self) -> set[str]:
        return {r.finding_id for r in self.results
                if r.status == VERIFIED_FALSE}


def build_queue(fixes: list[dict], deferred: list[dict] | None = None) -> list[dict]:
    'The findings the beat must look at, in priority order.\n\n    * ``deferred`` — items the adjudicator explicitly parked for VERIFY;\n    * uncorroborated fixes — a single-lens claim does not move the convergence\n      needle and is "never dropped (it goes to VERIFY)".\n\n    A fix that already carries cross-lens consensus is NOT queued for\n    re-proof: ``consensus_confirmed`` already blocks convergence with equal\n    force, and spending the budget re-checking it would starve the single-lens\n    items that only this beat can rescue.'
    from .loop import _is_confirmed

    queued: list[dict] = []
    seen: set[str] = set()
    for f in list(deferred or []) + list(fixes or []):
        if not isinstance(f, dict):
            continue
        if f in (fixes or []) and _is_confirmed(f):
            continue
        fid = str(f.get("id", f"fix-{len(queued)}"))
        if fid in seen:
            continue
        seen.add(fid)
        queued.append(f)
    return sorted(queued, key=order_key)


def order_key(fix: dict) -> tuple:
    """Deterministic queue order: worst severity first, then the source label."""
    rank = {"p0": 0, "critical": 0, "high": 1, "medium": 2,
            "low": 3, "nit": 4}
    sev = str(fix.get("severity", "")).lower()
    return (rank.get(sev, 2), str(fix.get("consensus", "")),
            str(fix.get("id", "")))


def red_command_verdict(fix: dict, *, runner=None,
                        cwd: str | Path | None = None) -> VerifyResult:
    "Form 1: run the fix's ``red_command`` — a repro TEST, not any command.\n\n    At VERIFY time the fix is unlanded, so the command is expected to FAIL,\n    and a failing run is the existence proof. Three gates stand between a\n    non-zero exit and ``verified_true``, because the exit code of an\n    arbitrary command proves nothing about a defect:\n\n    A probe that fails any of these is ``UNVERIFIABLE`` — it proves nothing in\n    EITHER direction, so it also cannot refute. That symmetry matters more\n    than the confirmation half: a spurious refutation demotes a real finding\n    and can flip a convergence predicate.\n\n    ``runner`` is injectable so tests never execute a real command. The default\n    runs argv WITHOUT a shell and with ``cwd`` pinned — the command is\n    model-authored text, and ``shell=True`` would hand it a parser it does not\n    need (the same discipline ``core/executor.py`` holds — see ``_run_cli``).\n    "
    fid = str(fix.get("id", ""))
    raw = str(fix.get("red_command") or "").strip()
    if not raw:
        return VerifyResult(fid, UNVERIFIABLE, None,
                            "no red_command on this finding")
    try:
        argv = shlex.split(raw)
    except ValueError as exc:
        return VerifyResult(fid, UNVERIFIABLE, None,
                            f"red_command does not lex: {exc}")
    if not argv:
        return VerifyResult(fid, UNVERIFIABLE, None, "red_command is empty")
    if not _TEST_RUNNER.search(raw):
        return VerifyResult(fid, UNVERIFIABLE, None,
                            "red_command is not a test-run invocation — a "
                            "repro TEST is the only thing that can reproduce "
                            "or refute a defect")
    try:
        code, tail = (runner or _default_runner)(argv, cwd=cwd)
    except Exception as exc:            # noqa: BLE001 - a broken probe is not a refutation
        return VerifyResult(fid, UNVERIFIABLE, None,
                            f"red_command could not run: {type(exc).__name__}: {exc}")
    if code == 0:
        return VerifyResult(fid, VERIFIED_FALSE, FORM_REPRO,
                            "repro test passes before any fix — nothing to "
                            "reproduce",
                            evidence=tail or raw)
    if code not in _EVIDENCE_EXIT:
        return VerifyResult(fid, UNVERIFIABLE, None,
                            f"probe exit {code} is not a tests-failed class "
                            f"({_EVIDENCE_EXIT}) — the probe did not decide",
                            evidence=tail)
    return VerifyResult(fid, VERIFIED_TRUE, FORM_REPRO,
                        f"repro test failed (exit {code}) before any fix — "
                        "the defect exists",
                        evidence=tail or raw)


def _default_runner(argv: list[str], *, cwd: str | Path | None = None
                    ) -> tuple[int, str]:
    """Run argv with no shell; return ``(exit_code, output_tail)``.

    ``cwd`` defaults to the engine root — the same pin ``_run_test_suite``
    holds. The tail is captured so a verdict carries the evidence it rests on
    instead of a bare exit number.
    """
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=300,
                          shell=False, cwd=None if cwd is None else str(cwd))
    tail = (proc.stderr or proc.stdout or "").strip()[-2000:]
    return int(proc.returncode), tail


def static_mapping_verdict(fix: dict,
                           static_rows: list[tuple] | None,
                           ) -> VerifyResult:
    """Form 2: the finding's ``evidence`` must cite a file:line a static tool
    really reports, and the tool must be talking about the SAME thing.

    ``static_rows`` is a list of ``(path, line)`` or ``(path, line, message)``
    from the same pyflakes run ``_static_analysis`` counts. The message is not
    decoration: a bare "this line exists in a tool dump" is not corroboration.
    ``evidence="core/loop.py:1700 is SQL injection"`` against an
    ``undefined name`` row used to mint ``verified_true``; the relevance
    check below is what stops that. Rows carrying no message (a 2-tuple) are
    accepted without a relevance constraint and are documented as weaker.

    Form 2 confirms a citation, not a vulnerability: for engine defects the
    static tool's report IS the defect class, which is why this is a real
    instrument for them. It is never a substitute for form 1's repro.
    """
    fid = str(fix.get("id", ""))
    evidence = str(fix.get("evidence") or "")
    cited = {(m.group(1), int(m.group(2))) for m in _LOC.finditer(evidence)}
    if not cited:
        return VerifyResult(fid, UNVERIFIABLE, None,
                            "evidence cites no file:line to map against")
    claim = " ".join([evidence, str(fix.get("summary", "")),
                      str(fix.get("why", ""))])
    claim_tokens = _tokens(claim)
    known: list[tuple[str, int, str | None]] = []
    for row in (static_rows or []):
        if len(row) >= 3:
            known.append((str(row[0]), int(row[1]), str(row[2])))
        elif len(row) == 2:
            known.append((str(row[0]), int(row[1]), None))
    for path, line in sorted(cited):
        for kpath, kline, msg in known:
            if not (kpath.endswith(path) or path.endswith(kpath)):
                continue
            if kline != line:
                continue
            if msg is not None and claim_tokens and not (
                    claim_tokens & _tokens(msg)):
                return VerifyResult(
                    fid, UNVERIFIABLE, None,
                    f"static tool reports {path}:{line} as {msg!r}, which is "
                    "not what this finding claims — a matching line number "
                    "is not corroboration",
                    evidence=evidence)
            return VerifyResult(fid, VERIFIED_TRUE, FORM_STATIC,
                                f"static tool reports {path}:{line}"
                                + (f": {msg}" if msg else ""),
                                evidence=evidence)
    return VerifyResult(fid, UNVERIFIABLE, None,
                        f"cited location {sorted(cited)} is not among the "
                        f"static tool's {len(known)} finding(s)")


def _tokens(text: str) -> set[str]:
    """Substantive lowercase word tokens, for a coarse relevance check."""
    return {w for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", text.lower())
            if w not in _STOPWORDS}


_STOPWORDS = frozenset({
    "this", "that", "with", "from", "into", "which", "where", "when", "then",
    "than", "file", "line", "core", "code", "rule", "rules", "test", "tests",
    "wrong", "issue", "report", "reports", "finding", "evidence", "assert",
})


def verify(fixes: list[dict], *, deferred: list[dict] | None = None,
           static_rows: list[tuple[str, int]] | None = None,
           runner=None, cwd: str | Path | None = None,
           budget: int = VERIFY_BUDGET) -> VerifyReport:
    """Run the beat over the queue. Never raises; never fabricates.

    Every queued entry gets exactly one outcome, and anything the budget could
    not reach is backlogged rather than guessed at. A finding is never deleted
    and never silently upgraded: only an actual repro failure or a real static
    mapping earns ``verified_true``.
    """
    report = VerifyReport(budget=budget)
    queue = build_queue(fixes, deferred)
    for fix in queue[:max(0, budget)]:
        res = red_command_verdict(fix, runner=runner, cwd=cwd)
        if res.status == UNVERIFIABLE and static_rows is not None:
            alt = static_mapping_verdict(fix, static_rows)
            if alt.status != UNVERIFIABLE:
                res = alt
        if res.status == UNVERIFIABLE:
            report.backlog.append(_backlog_row(fix, res))
        report.results.append(res)
    for fix in queue[max(0, budget):]:
        report.backlog.append(_backlog_row(
            fix, VerifyResult(str(fix.get("id", "")), UNVERIFIABLE, None,
                              f"beyond verify_budget={budget}")))
    return report


def _backlog_row(fix: dict, res: VerifyResult) -> dict:
    return {"id": res.finding_id,
            "severity": fix.get("severity"),
            "status": UNVERIFIABLE,
            "source": fix.get("consensus", ""),
            "why": res.reason}


def apply(report: VerifyReport, findings: list[dict]) -> list[dict]:
    """Stamp the beat's decisions onto the finding rows.

    Entries are never deleted and the source label is never rewritten: a
    refuted row keeps who claimed it and gains the ``unreproduced`` marker,
    because that pair is exactly what the leg-reputation update consumes.
    """
    by_id = {r.finding_id: r for r in report.results}
    out: list[dict] = []
    for f in findings:
        row = dict(f)
        res = by_id.get(str(row.get("id", "")))
        if res is None:
            out.append(row)
            continue
        if res.status == VERIFIED_TRUE:
            row["status"] = VERIFIED_TRUE
            row["verify_form"] = res.form
            row["verify_reason"] = res.reason
        elif res.status == VERIFIED_FALSE:
            row["status"] = VERIFIED_FALSE
            row["severity"] = DEMOTED_SEVERITY
            markers = list(row.get("markers") or [])
            if UNREPRODUCED not in markers:
                markers.append(UNREPRODUCED)
            row["markers"] = markers
            row["verify_form"] = res.form
            row["verify_reason"] = res.reason
        else:
            row["status"] = UNVERIFIABLE
            row["verify_reason"] = res.reason
        out.append(row)
    return out
