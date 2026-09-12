"""Real-run proof 5: --rounds hard cap (8 -> 5) + invalid config named errors."""
import io, json, os, sys, tempfile, threading, contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "engine"))
os.chdir(str(Path(__file__).resolve().parents[2] / "engine"))
from motoko import cli

ADJ_TEXT = "裁决：\n" + json.dumps({"verdict": "go", "fixes": [
    {"id": "F1", "summary": "s", "severity": "HIGH", "evidence": "f:1",
     "consensus": "both"}]})

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
        event = json.dumps({"type": "content_block_delta",
                            "delta": {"type": "text_delta", "text": ADJ_TEXT}})
        self.send_response(200); self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(f"data: {event}\n".encode() + b'data: {"type": "message_stop"}\n')
    def log_message(self, *a): pass

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{srv.server_port}"
root = Path(tempfile.mkdtemp(prefix="e2e-cap-"))
os.environ["MOTOKO_HOME"] = str(root)
os.environ["MOTOKO_LOOP_METRICS_CHILD"] = "1"
cfgp = root / "loop.yaml"
cfgp.write_text(f"""auditors:
  - name: a
    protocol: anthropic
    base_url: {base}
    model: m
    timeout: 10
adjudicator:
  name: adj
  protocol: anthropic
  base_url: {base}
  model: m
  timeout: 10
""")
out, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    rc = cli.main(["loop", "eng", "--config", str(cfgp), "--rounds", "8",
                   "--out", str(root / "w")])
lines = [l for l in out.getvalue().splitlines() if l.startswith('{"round"')]
print("requested 8 rounds -> ran:", len(lines), "(cap 5)")
assert len(lines) == 5, len(lines)
# invalid config: named problems
bad = root / "bad.yaml"
bad.write_text("auditors:\n  - name: x\n")
err2 = io.StringIO()
with contextlib.redirect_stderr(err2), contextlib.redirect_stdout(io.StringIO()):
    rc2 = cli.main(["loop", "eng", "--config", str(bad)])
print("invalid config rc:", rc2)
print(err2.getvalue())
assert rc2 == 2
srv.shutdown()
print("E2E-CAPS-OK")
