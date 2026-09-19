"""Tool-specific credential transports that keep values off OS command lines."""

from __future__ import annotations

import json
import os
import runpy
import sys
from contextlib import contextmanager
from pathlib import Path


def _resolve(token: str, spans: list, env: dict) -> str:
    for start, end, name in reversed(spans):
        if (not name.startswith("MOTOKO_SECRET_") or name not in env or
                token[start:end] != "@env:" + name):
            raise ValueError("invalid credential binding")
        token = token[:start] + env[name] + token[end:]
    return token


@contextmanager
def prepare(tool: str, argv: list[str], env: dict, bindings: dict, *, tools_root: Path):
    """Only renderer-owned placeholder positions may resolve credentials.

    curl reads header values through inherited anonymous files. jwt_tool has
    only a positional token interface; load its Python entry point in a child
    whose in-memory sys.argv is filled after exec. Unsupported transports
    refuse rather than silently sending a placeholder or exposing a value.
    """
    fds = []
    result = list(argv)
    try:
        if not bindings:
            yield result, ()
            return
        if tool == "curl":
            for raw_index, spans in bindings.items():
                index = int(raw_index)
                if index <= 0 or index >= len(result) or result[index - 1] not in ("-H", "--header"):
                    raise ValueError("curl credential requires a header-file transport")
                value = _resolve(result[index], spans, env)
                if any(c in value for c in "\r\n\x00"):
                    raise ValueError("credential contains forbidden header bytes")
                fd = os.memfd_create("motoko-header", flags=os.MFD_CLOEXEC)
                fds.append(fd)
                os.write(fd, (value + "\n").encode())
                os.lseek(fd, 0, os.SEEK_SET)
                result[index] = f"@/proc/self/fd/{fd}"
        elif tool == "jwt_tool":
            script = Path(os.environ.get("MOTOKO_JWT_TOOL_SCRIPT") or tools_root / "web/jwt_tool/jwt_tool.py")
            python = Path(os.environ.get("MOTOKO_JWT_TOOL_PYTHON") or tools_root / "web/venv/bin/python")
            if not script.is_file() or not python.is_file():
                raise ValueError("configure the jwt_tool Python entry point for private token transport")
            env["MOTOKO_SECRET_BINDINGS"] = json.dumps(bindings)
            result = [str(python), str(Path(__file__).resolve()), str(script), *argv[1:]]
        else:
            raise ValueError(f"no private credential transport for {tool}")
        yield result, tuple(fds)
    finally:
        for fd in fds:
            os.close(fd)


def _python_entry() -> None:
    script, *args = sys.argv[1:]
    argv = [script, *args]
    bindings = json.loads(os.environ.pop("MOTOKO_SECRET_BINDINGS"))
    for index, spans in bindings.items():
        argv[int(index)] = _resolve(argv[int(index)], spans, os.environ)
    sys.argv = argv
    sys.path.insert(0, str(Path(script).resolve().parent))
    runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":
    _python_entry()
