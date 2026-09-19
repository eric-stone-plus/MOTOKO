'Rule commands are templates (``"sqlmap -u {url} --batch"``). Two rules apply:\n\n* **Never a shell.** ``render_command`` splits the template with shlex\n  semantics and returns an ``argv`` LIST. This module spawns nothing itself\n  and offers no shell-string form, so a target value containing ``;``, ``|``\n  or backticks cannot become a second command. The audit summary persisted to\n  ``tool_run.command`` is built with ``shlex.join`` (i.e. every token\n  ``shlex.quote``-d), so re-parsing the summary returns the same tokens.\n* **Credentials never ride in argv.** Placeholder names that denote secrets\n  (ak/sk/token/password/...) are diverted to the environment as\n  ``MOTOKO_SECRET_<NAME>``; the argv slot keeps only an ``@env:NAME``\n  reference, and the summary shows ``***``.'

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

SECRET_KEYS = frozenset({
    "ak", "sk", "token", "password", "passwd", "secret", "api_key", "apikey",
    "access_key", "secret_key", "session_token", "credential", "creds",
    "canary", "bearer",
})

ENV_PREFIX = "MOTOKO_SECRET_"

# A template slot. The `(?<!%)` guard keeps curl's own `-w '%{redirect_url}'`
# write-out format out of the match: R-VULN-REDIRECT-001 renders that literal
# in both its normal and stealth commands, and reading it as a placeholder
# would either corrupt the format string or (since the ACT gate refuses
# unrendered slots) refuse a correct rule on every fire. rulecheck has always
# exempted this shape (`_LITERAL_BRACE_RE`); the renderer and the gate now do.
_PLACEHOLDER = re.compile(r"(?<!%)\{([A-Za-z_][A-Za-z0-9_]*)\}")

CTX_KEYS = (
    "url", "host", "ip", "domain", "dc", "wordlist", "wordlist_dir",
    "out", "oob",
    "ssrf_url", "tampered", "param", "canary", "user", "username", "ak", "sk",
    "token", "password", "port", "ua",
)


def placeholder_names(template: str) -> list[str]:
    """Template slot names in a command string, in order, `%{...}` exempt.

    The single notion of "is a placeholder" shared by the renderer, the ACT
    fail-closed gate and the corpus lock — before this, the gate had its own
    regex and filtered on CTX_KEYS membership, so an invented name like
    `{token2}` was invisible to it and rode to the target verbatim.
    """
    return _PLACEHOLDER.findall(template or "")


def is_secret(name: str) -> bool:
    """Is this placeholder a credential? Segment-wise, suffix tolerant."""
    text = str(name).lower()
    if text in SECRET_KEYS:
        return True
    for segment in re.split(r"[_\-]", text):
        if segment.rstrip("0123456789") in SECRET_KEYS:
            return True
    return False


def env_name(name: str) -> str:
    return f"{ENV_PREFIX}{str(name).upper()}"


def _fill_slot(token: str, name: str, replacement: str) -> str:
    """Substitute one template slot, leaving any `%{name}` form untouched."""
    # concatenation, not %-formatting: the lookbehind's own `%` would be read
    # as a conversion spec (`%)` -> ValueError)
    pattern = r"(?<!%)\{" + re.escape(name) + r"\}"
    return re.sub(pattern, lambda _m: replacement, token)


@dataclass
class RenderedCommand:
    """argv + env for the executor, plus the masked audit summary."""

    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    summary: str = ""
    secrets: tuple[str, ...] = ()   # names only, never values
    secret_bindings: dict[int, list[tuple[int, int, str]]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.argv)


def render_command(template: str, ctx: dict | None = None) -> RenderedCommand:
    """Render a rule command template into ``(argv, env, masked summary)``.

    * One template token stays one argv element (no word splitting of values).
    * Secret placeholders go to ``env``; argv holds ``@env:NAME`` instead.
    * Unknown placeholders are left verbatim (visible, never a silent blank) —
      and the caller refuses the action rather than executing it.
    """
    values = {str(k).lower(): v for k, v in dict(ctx or {}).items()}
    argv: list[str] = []
    masked: list[str] = []
    env: dict[str, str] = {}
    used_secrets: list[str] = []
    bindings: dict[int, list[tuple[int, int, str]]] = {}

    for token in shlex.split(template or "", posix=True):
        # Substitute original template spans once. Values are never templates:
        # braces or @env markers supplied by a target cannot become bindings.
        argv_token, masked_token, cursor = "", "", 0
        for match in _PLACEHOLDER.finditer(token):
            argv_token += token[cursor:match.start()]
            masked_token += token[cursor:match.start()]
            cursor = match.end()
            key = match.group(1).lower()
            if key not in values:
                argv_token += match.group()
                masked_token += match.group()
                continue
            text = str(values[key])
            if is_secret(key):
                var = env_name(key)
                env[var] = text               # credential rides the environment
                ref = f"@env:{var}"
                bindings.setdefault(len(argv), []).append((len(argv_token), len(argv_token) + len(ref), var))
                if key not in used_secrets:
                    used_secrets.append(key)
                argv_token += ref
                masked_token += "***"
            else:
                argv_token += text
                masked_token += text
        argv_token += token[cursor:]
        masked_token += token[cursor:]
        argv.append(argv_token)
        masked.append(masked_token)

    return RenderedCommand(
        argv=argv,
        env=env,
        summary=shlex.join(masked),   # shlex.quote per token — audit-safe
        secrets=tuple(used_secrets),
        secret_bindings=bindings,
    )
