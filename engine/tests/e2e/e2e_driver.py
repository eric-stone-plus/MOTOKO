"""Real-run proof 2: the CLI driver over mock endpoints — CONTINUE path and
STOP (BUDGET_EXHAUSTED) path with residual_risks."""
import io, json, os, sys, tempfile, threading, contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
os.chdir(str(Path(__file__).resolve().parents[2] / "engine"))
from motoko import cli

ADJ = json.dumps({"verdict": "go", "fixes": [
    {"id": "F1", "summary": "demo fix", "severity": "HIGH",
     "evidence": "loop.py:1", "consensus": "both"}]})

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        json.loads(self.rfile.read(n))
        text = "AUDIT REPORT" if H.phase == "audit" else ("裁决：\n" + ADJ)
        H.phase = "audit"          # adjudicator answered; legs next round
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
root = Path(tempfile.mkdtemp(prefix="e2e-driver-"))
os.environ["MOTOKO_HOME"] = str(root)
os.environ["MOTOKO_LOOP_METRICS_CHILD"] = "1"

cfgp = root / "loop.yaml"
cfgp.write_text(f"""auditors:
  - name: qwen-leg
    protocol: anthropic
    base_url: {base}
    model: mock-qwen
    timeout: 20
  - name: kimi-leg
    protocol: anthropic
    base_url: {base}
    model: mock-kimi
    timeout: 20
adjudicator:
  name: grok-adj
  protocol: anthropic
  base_url: {base}
  model: mock-grok
  timeout: 20
""")
wave = root / "plans" / "waves" / "wave-e2e"
out, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    rc = cli.main(["loop", "eng-e2e", "--config", str(cfgp),
                   "--rounds", "5", "--out", str(wave)])
print("rc:", rc)
tail = out.getvalue()
print("round lines:")
for line in tail.splitlines():
    if line.startswith('{"round"'):
        print("  ", line)
start = tail.index('{\n  "rounds_run"')
payload = json.loads(tail[start:])
print("rounds_run:", payload["rounds_run"], "stopped:", payload["stopped"])
last = payload["rounds"][-1]
print("last round:", last["action"], last["reason"])
stop_dir = wave / f"round-{payload['rounds_run']}"
rr = json.loads((stop_dir / "residual_risks.json").read_text())
print("residual_risks.json:")
print(json.dumps(rr, ensure_ascii=False, indent=2)[:600])
sums = (wave / "round-1" / "SHA256SUMS").read_text()
print("SHA256SUMS round-1 lines:", len(sums.strip().splitlines()))
# verify one hash
import hashlib
first_hash, first_name = sums.strip().splitlines()[0].split("  ", 1)
assert hashlib.sha256((wave / "round-1" / first_name).read_bytes()).hexdigest() == first_hash
print("sha256 verify: OK")
srv.shutdown()
print("E2E-DRIVER-OK")
