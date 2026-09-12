"""Real-run proof: mock endpoints drive run_round full chain to a real verdict."""
import json, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
os_cwd = Path(str(Path(__file__).resolve().parents[2] / "engine"))
import os
os.chdir(os_cwd)
from motoko import loop

ADJ = json.dumps({
    "verdict": "go",
    "fixes": [
        {"id": "F1", "summary": "loop.py G0 signature mismatch", "severity": "P0",
         "evidence": "motoko/loop.py:376", "consensus": "both"},
        {"id": "F2", "summary": "thinking param missing on anthropic leg", "severity": "HIGH",
         "evidence": "motoko/loop.py:240", "consensus": "both"},
        {"id": "F3", "summary": "nit: docstring typo", "severity": "LOW",
         "evidence": "motoko/cli.py:1", "consensus": "single"}],
    "deferred": []})

class H(BaseHTTPRequestHandler):
    calls = 0
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        H.calls += 1
        # echo a marker proving the thinking param reached the wire
        thinking_ok = body.get("thinking", {}).get("budget_tokens") == 8192
        text = ("AUDIT-LEG-REPORT thinking_ok=%s\n" % thinking_ok) if "audit" in body.get("model","") or H.calls <= 2 else ("裁决：\n" + ADJ)
        event = json.dumps({"type": "content_block_delta",
                            "delta": {"type": "text_delta", "text": text}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(f"data: {event}\n".encode() + b'data: {"type": "message_stop"}\n')
    def log_message(self, *a):
        pass

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{srv.server_port}"
cfg = {"auditors": [
        {"name": "qwen-leg", "protocol": "anthropic", "base_url": base, "model": "mock-qwen", "timeout": 30},
        {"name": "kimi-leg", "protocol": "anthropic", "base_url": base, "model": "mock-kimi", "timeout": 30}],
       "adjudicator": {"name": "grok-adj", "protocol": "anthropic", "base_url": base, "model": "mock-grok", "timeout": 30}}
tmp = Path(tempfile.mkdtemp(prefix="e2e-loop-"))
wave = tmp / "waves" / "wave-e2e"
runner = loop.LoopRunner("eng-e2e", engine_root=os_cwd, rules_dir=os_cwd / "rules", config=cfg, root=tmp)

# R1: full chain with adjudicated fixes
r1 = runner.run_round(wave / "round-1")
vj1 = json.loads((wave / "round-1" / "verdict.json").read_text())
print("=== ROUND 1 verdict.json ===")
print(json.dumps(vj1, ensure_ascii=False, indent=2))
assert "error" not in vj1, vj1
assert vj1["round"] == 1 and vj1["action"] in ("CONTINUE", "ROLLBACK", "STOP")
print("audits:", len(r1["audits"]), "| fixes:", len(r1["fixes"]), "| verdict:", r1["verdict"])
print("leg files:", sorted(p.name for p in (wave/'round-1').glob('*.md')))

# R2: previous history exists; same mocks -> history accumulates
r2 = runner.run_round(wave / "round-2")
vj2 = json.loads((wave / "round-2" / "verdict.json").read_text())
print("=== ROUND 2 verdict.json (round=%s, reward=%s, action=%s, reason=%s) ===" % (vj2["round"], vj2["reward"], vj2["action"], vj2["reason"]))
assert vj2["round"] == 2
hist = json.loads((wave / "loop-history.json").read_text())
print("history rounds:", [h["round"] for h in hist["rounds"]], "rewards:", [h["reward"] for h in hist["rounds"]])
m = hist["rounds"][-1]["metrics"]
print("metrics keys:", sorted(k for k in m if not k.startswith("_")))
srv.shutdown()
print("E2E-OK")
