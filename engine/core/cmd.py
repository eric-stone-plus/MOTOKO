"""Command rendering for rule actions (F09).

Rule commands are templates (``"sqlmap -u {url} --batch"``). Two rules apply:

* **Never a shell.** ``render_command`` splits the template with shlex
  semantics and returns an ``argv`` LIST. This module spawns nothing itself
  and offers no shell-string form, so a target value containing ``;``, ``|``
  or backticks cannot become a second command. The audit summary persisted to
  ``tool_run.command`` is built with ``shlex.join`` (i.e. every token
  ``shlex.quote``-d), so re-parsing the summary returns the same tokens.
* **Credentials never ride in argv.** Placeholder names that denote secrets
  (ak/sk/token/password/...) are diverted to the environment as
  ``MOTOKO_SECRET_<NAME>``; the argv slot keeps only an ``@env:NAME``
  reference, and the summary shows ``***``.

Values for unknown placeholders are left verbatim so a missing context key is
visible in the audit trail instead of silently executing as an empty string.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

# Placeholder/context names treated as credentials. Case-insensitive.
SECRET_KEYS = frozenset({
    "ak", "sk", "token", "password", "passwd", "secret", "api_key", "apikey",
    "access_key", "secret_key", "session_token", "credential", "creds",
    "canary", "bearer",
})

ENV_PREFIX = "MOTOKO_SECRET_"

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Context keys the orchestrator may pass for a rule action's placeholders.
# wordlist_dir is engine-injected (_command_ctx): rules reference
# {wordlist_dir}/<file> instead of absolute home paths. ua is engine-injected
# too (opsec.DEFAULT_UA / MOTOKO_UA): rules never hardcode a User-Agent.
CTX_KEYS = (
    "url", "host", "ip", "domain", "dc", "wordlist", "wordlist_dir",
    "out", "oob",
    "ssrf_url", "tampered", "canary", "user", "username", "ak", "sk",
    "token", "password", "port", "ua",
)


def is_secret(name: str) -> bool:
    return str(name).lower() in SECRET_KEYS


def env_name(name: str) -> str:
    return f"{ENV_PREFIX}{str(name).upper()}"


@dataclass
class RenderedCommand:
    """argv + env for the executor, plus the masked audit summary."""

    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    summary: str = ""
    secrets: tuple[str, ...] = ()   # names only, never values

    def __bool__(self) -> bool:
        return bool(self.argv)


def render_command(template: str, ctx: dict | None = None) -> RenderedCommand:
    """Render a rule command template into ``(argv, env, masked summary)``.

    * One template token stays one argv element (no word splitting of values).
    * Secret placeholders go to ``env``; argv holds ``@env:NAME`` instead.
    * Unknown placeholders are left verbatim (visible, never a silent blank).
    """
    values = {str(k).lower(): v for k, v in dict(ctx or {}).items()}
    argv: list[str] = []
    masked: list[str] = []
    env: dict[str, str] = {}
    used_secrets: list[str] = []

    for token in shlex.split(template or "", posix=True):
        names = _PLACEHOLDER.findall(token)
        if not names:
            argv.append(token)
            masked.append(token)
            continue
        argv_token, masked_token = token, token
        for name in names:
            key = name.lower()
            if key not in values:
                continue                      # leave the placeholder visible
            text = str(values[key])
            if key in SECRET_KEYS:
                var = env_name(key)
                env[var] = text               # credential rides the environment
                if key not in used_secrets:
                    used_secrets.append(key)
                argv_token = argv_token.replace("{%s}" % name, f"@env:{var}")
                masked_token = masked_token.replace("{%s}" % name, "***")
            else:
                argv_token = argv_token.replace("{%s}" % name, text)
                masked_token = masked_token.replace("{%s}" % name, text)
        argv.append(argv_token)
        masked.append(masked_token)

    return RenderedCommand(
        argv=argv,
        env=env,
        summary=shlex.join(masked),   # shlex.quote per token — audit-safe
        secrets=tuple(used_secrets),
    )
