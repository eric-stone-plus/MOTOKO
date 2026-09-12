"""Real-run proof 3: BUDGET_EXHAUSTED STOP at round 5 + residual risks."""
import io, json, os, sys, tempfile, threading, contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
os.chdir(str(Path(__file__).resolve().parents[2] / "engine"))
from motoko import cli

ADJ = json.dumps({"verdict": "go", "fixes": [
    {"id": "F-UNFIXED", "summary": "unresolved HIGH confirmed finding",
     "severity": "HIGH", "evidence": "loop.py:99", "consensus": "both"}]})

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        json.loads(self.rfile.read(n))
        text = ("AUDIT REPORT" if H.phase == "audit" else ("裁决：\n" + ADJ))
        H.phase = "adjudicated"
        event = json.dumps({"type": "content_block_delta",
                            "delta": {"type": "text_delta", "text": text}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(f"data: {event}\n".encode() + b'data: {"type": "message_stop"}\n')
    def log_message(self, *a):
        pass

H.phase = "audit"
srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{srv.server_port}"
root = Path(tempfile.mkdtemp(prefix="e2e-fuse-"))
os.environ["MOTOKO_HOME"] = str(root)
os.environ["MOTOKO_LOOP_METRICS_CHILD"] = "1"
cfgp = root / "loop.yaml"
cfgp.write_text(f"""auditors:
  - name: leg-a
    protocol: anthropic
    base_url: {base}
    model: m
    timeout: 20
adjudicator:
  name: adj
  protocol: anthropic
  base_url: {base}
  model: m
  timeout: 20
""")
wave = root / "plans" / "waves" / "wave-fuse"
out, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    rc = cli.main(["loop", "eng-e2e", "--config", str(cfgp),
                   "--rounds", "5", "--out", str(wave)])
tail = out.getvalue()
print("round lines:")
for line in tail.splitlines():
    if line.startswith('{"round"'):
        print("  ", line)
start = tail.index('{\n  "rounds_run"')
payload = json.loads(tail[start:])
print("rounds_run:", payload["rounds_run"], "stopped:", payload["stopped"])
last = payload["rounds"][-1]
print("last:", last["action"], "/", last["reason"])
rr = json.loads((wave / "round-5" / "residual_risks.json").read_text())
print("residual:", rr["residual_risks"])
print("best_checkpoint:", rr["best_checkpoint"])
assert payload["stopped"] is True and payload["rounds_run"] == 5
assert last["action"] == "STOP" and last["reason"] == "BUDGET_EXHAUSTED"
srv.shutdown()
print("E2E-FUSE-OK")
