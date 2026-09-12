"""Real-run proof 4: ROLLBACK — sandbox git repo, checkpoint, verdict execution."""
import json, os, subprocess as sp, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
os.chdir(str(Path(__file__).resolve().parents[2] / "engine"))
from motoko import loop

sandbox = Path(tempfile.mkdtemp(prefix="e2e-rb-"))
work = sandbox / "engine"; work.mkdir()
env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
def git(*a): return sp.run(["git", *a], cwd=work, capture_output=True, text=True, env=env)
git("init", "-q"); git("config", "user.email", "t@t"); git("config", "user.name", "t")
(work / "engine.py").write_text("VALUE = 1\n")
git("add", "."); git("commit", "-qm", "checkpoint r1 (argmax reward)")
checkpoint = git("rev-parse", "HEAD").stdout.strip()
# round-2 "landing" that regresses
(work / "engine.py").write_text("VALUE = 2\nBUG = True\n")
git("commit", "-qam", "round-2 landing")
print("before revert:", (work / "engine.py").read_text().split())

runner = loop.LoopRunner("e", engine_root=work, rules_dir=work / "rules",
                         config={"auditors": []}, root=sandbox)
runner._last_fixes = [{"id": "F1", "summary": "regressing fix", "severity": "HIGH"}]
summary = runner.apply_verdict(
    {"action": "ROLLBACK", "best_checkpoint": checkpoint, "rollback": True},
    round_dir=sandbox / "round-2")
print("summary:", summary)
print("after revert:", (work / "engine.py").read_text().split())
rb = json.loads((sandbox / "round-2" / "rollback.json").read_text())
print("rollback.json:", {k: rb[k] for k in ("action", "reverted_to")})
print("requeued:", rb["requeued_fixes"])
assert summary["reverted_to"] == checkpoint
assert "BUG" not in (work / "engine.py").read_text()

# refusal path: no checkpoint
try:
    runner.apply_verdict({"action": "ROLLBACK", "best_checkpoint": None})
    print("REFUSAL: FAILED TO RAISE")
except loop.LoopRollbackError as e:
    print("refusal raises LoopRollbackError:", str(e)[:60], "...")
print("E2E-ROLLBACK-OK")
