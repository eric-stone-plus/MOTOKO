"""Parse offline jwt_tool generation without treating a token as a finding.

jwt_tool 2.3 emits bare or ``[+]``-prefixed tokens and exits 1 even after
successful generation. Only its narrow offline generation modes can use that
exit convention; errors and online invocations retain their failure status.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import shlex

from . import Parser, register

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_TOKEN_LINE = re.compile(r"(?:\[\+\]\s+)?([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)")


def _mode(action: dict) -> str | None:
    try:
        argv = shlex.split(action.get("cmd", ""))
    except (ValueError, TypeError):
        return None
    if not argv or argv[0] != "jwt_tool":
        return None
    positional, mode = [], None
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg in ("-b", "--bare"):
            i += 1
        elif arg in ("-X", "--exploit") and i + 1 < len(argv) and mode is None:
            mode = argv[i + 1]
            i += 2
        elif arg.startswith("-"):
            return None
        else:
            positional.append(arg)
            i += 1
    return mode if len(positional) == 1 and mode in {"a", "i"} else None


def _generated_tokens(text: str, mode: str) -> list[str]:
    tokens = []
    for line in _ANSI.sub("", text or "").splitlines():
        line = line.strip()
        if len(line) > 8200:
            continue
        match = _TOKEN_LINE.fullmatch(line)
        if not match:
            continue
        token = match.group(1)
        try:
            header, payload, signature = token.split(".")
            def decode(part):
                return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            head, claims = decode(header), decode(payload)
            if not isinstance(head, dict) or not isinstance(claims, dict):
                continue
            if mode == "a" and (str(head.get("alg")).lower() != "none" or signature):
                continue
            if mode == "i" and (not signature or not isinstance(head.get("jwk"), dict)):
                continue
        except (ValueError, UnicodeError, binascii.Error):
            continue
        if token not in tokens:
            tokens.append(token)
    return tokens


@register
class JwtToolParser(Parser):
    tool = "jwt_tool"

    def context_keys(self, action):
        return frozenset({"tampered"}) if _mode(action) == "a" else frozenset()

    def execution_succeeded(self, exit_code, stdout, stderr, action):
        mode = _mode(action)
        if mode:
            tokens = _generated_tokens(stdout, mode)
            # A partial alg-none transcript can precede an exception. Require
            # the complete four-variant result before accepting exit 1.
            expected = 4 if mode == "a" else 1
            return exit_code in (0, 1) and len(tokens) == expected and not stderr.strip()
        return exit_code == 0

    def parse(self, stdout, stderr="", action=None):
        mode = _mode(action or {})
        if not mode:
            return self._result("jwt_tool: unsupported output mode",
                                dead_letter=["No offline generation contract for this invocation"])
        tokens = _generated_tokens(stdout, mode)
        context = {"tampered": tokens[0]} if mode == "a" and tokens else {}
        # Never quote rejected output: it may contain original credentials or
        # decoded claims. The owner-only raw artifact remains the audit source.
        return self._result(f"jwt_tool: {len(tokens)} generated token(s)", context=context,
                            dead_letter=[] if tokens else ["No valid generated JWT"])
