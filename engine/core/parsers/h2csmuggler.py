"h2csmuggler — an h2c upgrade probe whose exit code lies in both directions.\n\n* success — exit 0, `[INFO] h2c stream established successfully.` then\n  `[INFO] Success! <url> can be used for tunneling`;\n* refused — exit **1**, `[INFO] Failed to upgrade: <url>`;\n* invocation defect — exit 1, the tool's own usage complaint\n  (`Please specify scheme (e.g., http[s]://) for: …`);\n* crash — exit 1, a Python traceback on stderr and **empty stdout**\n  (`ConnectionRefusedError` when nothing listens).\n\nTwo properties of the tool are recorded rather than papered over:"

from __future__ import annotations

import re

from . import Parser, register

# `[INFO] Success! http://h/ can be used for tunneling`
_SUCCESS = re.compile(r"^\[INFO\]\s+Success!\s+(\S+)\s+can be used for tunneling\s*$")
# `[INFO] Failed to upgrade: http://h/`
_FAILED = re.compile(r"^\[INFO\]\s+Failed to upgrade:\s+(\S+)\s*$")
_ESTABLISHED = "[INFO] h2c stream established successfully."
# The tool's own usage complaints: OUR command line was wrong, not the target.
_USAGE = (
    "Please provide a server for tunneling",
    "Please specify the '-t' flag or provide smuggled URL",
    "Please specify scheme (e.g., http[s]://) for:",
)
_TRACEBACK = "Traceback (most recent call last):"
_DEAD_LEN = 200


@register
class H2cSmugglerParser(Parser):
    tool = "h2csmuggler"

    def execution_succeeded(self, exit_code, stdout, stderr, action):
        """Accept a non-zero exit only when the probe reached a verdict.

        Called by the executor for exit != 0 alone (exit 0 is accepted before
        the parser is consulted), so every branch here is a non-zero code.
        """
        if exit_code == 0:
            return True
        if exit_code != 1:
            return False
        if _TRACEBACK in (stderr or ""):
            return False
        text = (stdout or "").strip()
        if not text:
            return False
        if any(line.strip().startswith(_USAGE) for line in text.splitlines()):
            return False
        return bool(_FAILED.search(text) or _SUCCESS.search(text))

    def parse(self, stdout, stderr="", action=None):
        dead: list[str] = []
        text = stdout or ""
        success_url = ""
        failed_url = ""
        established = False
        usage: list[str] = []
        chatter = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _SUCCESS.match(line)
            if m:
                success_url = m.group(1)
                continue
            if line == _ESTABLISHED:
                established = True
                continue
            m = _FAILED.match(line)
            if m:
                failed_url = m.group(1)
                continue
            if any(line.startswith(u) for u in _USAGE):
                usage.append(line[:_DEAD_LEN])
                continue
            if line.startswith("[INFO]") or line.startswith("[ERROR]"):
                chatter += 1
            # Smuggled-response bodies and headers land here unprefixed; they
            # are evidence, so they are kept rather than summarised away.
            dead.append(line[:_DEAD_LEN])

        err = (stderr or "").strip()
        crashed = _TRACEBACK in err
        if err:
            # The traceback's last line carries the exception type, which is
            # the part worth reading; keep the tail, not the frame list.
            tail = [ln.strip() for ln in err.splitlines() if ln.strip()]
            dead.append(tail[-1][:_DEAD_LEN] if tail else err[:_DEAD_LEN])

        if usage:
            # Never a statement about the target: we invoked it wrongly.
            return self._result(
                "h2csmuggler: invocation defect — the tool rejected its own "
                "command line, nothing was probed",
                dead_letter=usage + dead)
        if crashed and not (success_url or failed_url or established):
            return self._result(
                "h2csmuggler: tool raised before reaching a verdict — no "
                "conclusion about the target",
                dead_letter=dead)
        if success_url or established:
            url = success_url or str((action or {}).get("url") or "")
            findings = []
            if url:
                findings.append(self._finding(
                    class_="smuggling.h2",
                    title="h2c upgrade accepted — endpoint can be used for "
                          "tunnelling",
                    url=url,
                    severity="unknown",
                ))
            else:
                # A hit we cannot aim at is not deliverable evidence (M2).
                dead.append("h2c upgrade succeeded but the tool echoed no URL")
            return self._result(
                "h2csmuggler: h2c stream established — upgrade accepted"
                + ("" if findings else " (no URL echoed, no finding minted)"),
                findings=findings, dead_letter=dead)
        if failed_url:
            return self._result(
                f"h2csmuggler: {failed_url} refused the h2c upgrade — no "
                "tunnelling surface",
                dead_letter=dead)
        if chatter:
            # Every line was the tool's own prefix and none was recognisable:
            # the format moved. Say so instead of reporting a clean negative.
            dead.append("h2csmuggler output format not recognised — "
                        f"{chatter} `[INFO]`/`[ERROR]` line(s), no upgrade verdict")
            return self._result(
                "h2csmuggler: unrecognised output format — no verdict read",
                dead_letter=dead)
        return self._result(
            "h2csmuggler: no output — nothing probed", dead_letter=dead)
