"interactsh-backed canary manager — the OOB validator's real IO.\n\nSo the session is owned here, across findings, for the life of the orchestrator:\npayloads are pre-generated with `-n`, `issue()` hands out a distinct one per\ncall (the validator needs two, and reads a repeat as an infrastructure anomaly\nrather than a negative), `trigger()` delivers through an injected sender, and\n`poll()` reads the JSONL the client writes with `-json -o`.\n\nCaptured shapes this code depends on (fixtures in `tests/fixtures/interactsh-*`):\n\n* stderr registration: `[INF] Listing N payload for OOB Testing` then one\n  `[INF] <correlation-id>.oast.<tld>` line per payload, wrapped in ANSI colour;\n* JSONL interaction: one object per line with `protocol` (`dns` | `http` |\n  `smtp`), `unique-id`, `full-id`, `raw-request`, `remote-address`, `timestamp`.\n\nA DNS interaction is weaker evidence than an HTTP one — a resolver anywhere on\nthe path can produce it — so the protocol is recorded in the verdict evidence\ninstead of being collapsed into a bare boolean.\n\nProcess discipline follows the standing rule: the client is started in its own\nsession (`start_new_session`) and its PID recorded, and `close()` signals that\nnumeric PID's process group. Nothing here ever matches a process by command\nline — the pattern would be sitting in the argv of whatever ran it.\n\nDeployment notes, recorded rather than hidden:"

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path

from .. import executor, util

# `[INF] <cid>.oast.site` — the client colourises its own level token, so the
# payload is taken from anywhere on the line rather than from a fixed column.
_PAYLOAD_RE = re.compile(r"\b([a-z0-9]{16,}(?:\.[a-z0-9-]+)+\.[a-z]{2,})\b")
_LISTING_RE = re.compile(r"Listing \d+ payload", re.IGNORECASE)
_DEFAULT_SERVERS = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"
_DEAD_LEN = 500


class CanaryUnavailable(RuntimeError):
    'The session could not be established. Infrastructure, never evidence.'


class InteractshCanary:
    """A canary manager over one long-lived `interactsh-client` session."""

    def __init__(self, *, workdir, binary: str | None = None,
                 server: str | None = None, count: int = 8,
                 poll_interval: int = 5, startup_timeout: float = 30.0,
                 sender=None):
        self.workdir = Path(workdir)
        self.binary = binary
        self.server = server or os.environ.get(
            "MOTOKO_INTERACTSH_SERVER", _DEFAULT_SERVERS)
        self.count = max(2, int(count))     # the validator needs two distinct
        self.poll_interval = poll_interval
        self.startup_timeout = startup_timeout
        # callable(url) -> response|None. Injected by the orchestrator so
        # delivery rides the replay fetcher's egress gate and bind_ip pinning.
        self.sender = sender
        self._proc = None
        self._payloads: list[str] = []
        self._issued: set[str] = set()
        self._err_path: Path | None = None
        self._jsonl_path: Path | None = None
        self.start_error = ""

    # -- lifecycle -----------------------------------------------------
    @property
    def jsonl_path(self) -> Path:
        return self._jsonl_path or (self.workdir / "interactsh.jsonl")

    def resolve_binary(self) -> str | None:
        if self.binary:
            return str(self.binary)
        try:
            return executor.resolve_tool("interactsh-client")
        except Exception:      # noqa: BLE001 - a backend probe must never raise
            return None

    def start(self) -> None:
        """Register the session and read its payloads. Idempotent.

        Raises `CanaryUnavailable` with the reason; the caller (the validator)
        turns that into an inconclusive verdict, never into a strike.
        """
        if self._proc is not None:
            return
        binary = self.resolve_binary()
        if not binary:
            self.start_error = "interactsh-client is not installed or not resolvable"
            raise CanaryUnavailable(self.start_error)
        try:
            self.workdir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.start_error = f"cannot create the session directory: {e}"
            raise CanaryUnavailable(self.start_error)
        err_path = self.workdir / "interactsh.stderr"
        jsonl = self.jsonl_path
        argv = [
            binary,
            "-auth=false",                 # no projectdiscovery cloud key here
            "-duc",                         # no update check on a probe path
            "-n", str(self.count),
            "-pi", str(self.poll_interval),
            "-s", self.server,
            "-json", "-o", str(jsonl),
        ]
        try:
            with open(err_path, "wb") as errfh:
                self._proc = subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,   # everything lands on stderr
                    stderr=errfh,
                    cwd=str(self.workdir),
                    start_new_session=True,      # own pgid: close() can signal it
                )
        except (OSError, ValueError) as e:
            self._proc = None
            self.start_error = f"cannot start interactsh-client: {e}"
            raise CanaryUnavailable(self.start_error)
        self._err_path = err_path
        self._jsonl_path = jsonl
        self._payloads = self._await_payloads(err_path)
        if not self._payloads:
            reason = self.start_error or (
                "interactsh-client registered no payload within "
                f"{self.startup_timeout:.0f}s (server unreachable, or its "
                "output format moved — see the session stderr)")
            self.close()
            self.start_error = reason
            raise CanaryUnavailable(reason)

    def _await_payloads(self, err_path: Path) -> list[str]:
        """Read registration lines until `count` payloads or the deadline."""
        deadline = time.monotonic() + self.startup_timeout
        seen: list[str] = []
        listing = False
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                self.start_error = (
                    f"interactsh-client exited {self._proc.returncode} during "
                    f"registration: {self._tail(err_path)}")
                return []
            try:
                text = err_path.read_text(errors="replace")
            except OSError:
                text = ""
            listing = listing or bool(_LISTING_RE.search(text))
            for match in _PAYLOAD_RE.finditer(text):
                payload = match.group(1)
                if payload not in seen:
                    seen.append(payload)
            if len(seen) >= self.count:
                return seen[:self.count]
            time.sleep(0.5)
        if not listing and not seen:
            self.start_error = (
                "interactsh-client printed no listing line — output format "
                f"moved or the server refused: {self._tail(err_path)}")
        return seen

    @staticmethod
    def _tail(path: Path | None, limit: int = _DEAD_LEN) -> str:
        if path is None:
            return ""
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return ""
        # Strip the ANSI level colouring so the reason stays readable in an
        # event payload, and keep the tail: the useful line is the last one.
        text = re.sub(r"\x1b\[[0-9;]*m", "", text)
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return " | ".join(lines[-3:])[:limit]

    def close(self) -> None:
        """Stop the session by its recorded PID's process group. Never by name."""
        proc, self._proc = self._proc, None
        if proc is None:
            return
        if proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.terminate()
            except OSError:
                return
        try:
            proc.wait(timeout=5.0)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_exc):
        self.close()

    # -- the three injected callables ----------------------------------
    def issue(self) -> str:
        """A distinct canary payload, or raise. Never repeats within a session."""
        self.start()
        for payload in self._payloads:
            if payload not in self._issued:
                self._issued.add(payload)
                return payload
        raise CanaryUnavailable(
            f"canary pool exhausted ({len(self._payloads)} payload(s) "
            "registered, all issued)")

    def trigger(self, finding: dict, canary: str, *, sender=None) -> None:
        "Deliver the canary through the finding's own injection point."
        deliver = sender or self.sender
        if deliver is None:
            raise CanaryUnavailable(
                "no delivery sender is wired: the OOB validator may not open "
                "its own socket to a target (egress gate lives in one place)")
        point = util.ssrf_injection_point(str(finding.get("url") or ""))
        if not point:
            raise CanaryUnavailable(
                "the finding carries no injectable query point, so the canary "
                "cannot be delivered through it")
        base, param = point
        url = f"{base}?{param}=http://{canary}/"
        response = deliver(url)
        if response is None:
            # The fetcher returns None when it refuses to send (no asserted
            # egress, unpinned bind_ip, transport error). All three are
            # infrastructure: the target proved nothing either way.
            raise IOError(
                "the canary injection did not go out (egress refused, "
                "unpinned, or transport error)")

    def poll(self, canary: str) -> bool:
        """Did this canary receive ANY interaction? Reads the client's JSONL."""
        return bool(self.interactions(canary))

    def interactions(self, canary: str) -> list[dict]:
        'Interaction rows for one canary, in the order the client wrote them.\n\n        Matching is on the correlation id, and a subdomain of it counts: a\n        target that fetches `<anything>.<cid>.oast.site` still proves the\n        callback. A row whose id merely CONTAINS the canary does not.'
        cid = str(canary or "").strip().lower()
        if not cid:
            return []
        bare = cid.split(".")[0] or cid
        path = self.jsonl_path
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return []
        out: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            full = str(row.get("full-id") or "").lower()
            uniq = str(row.get("unique-id") or "").lower()
            if not any(candidate in (full, uniq) or full.endswith("." + candidate)
                       or uniq.endswith("." + candidate)
                       for candidate in (cid, bare)):
                continue
            out.append({
                "protocol": str(row.get("protocol") or "unknown"),
                "remote_address": str(row.get("remote-address") or ""),
                "timestamp": str(row.get("timestamp") or ""),
            })
        return out
