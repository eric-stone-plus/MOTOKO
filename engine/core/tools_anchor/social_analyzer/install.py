#!/usr/bin/env python3
"""Install the pinned external detector and a narrow CLI; never edit shell startup files."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from profile import HERE, PIN, Refused, verify_source

MARKER = "# motoko-social-profile: managed external-tool wrapper"


def command(*args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, timeout=600, **kwargs)


def wrapper_text(toolbox):
    # Absolute exec targets remain visible to the static wrapper doctor.
    runtime = toolbox / ".social-analyzer-runtime" / "venv/bin/python"
    driver = HERE / "profile.py"
    return ("#!/bin/sh\n" + MARKER + "\nset -eu\n"
            + f"TOOLS_DEFAULT={shlex.quote(str(toolbox))}\n"
            + 'export MOTOKO_TOOLS="${MOTOKO_TOOLS:-$TOOLS_DEFAULT}"\n'
            + f'exec {shlex.quote(str(runtime))} -I -B {shlex.quote(str(driver))} "$@"\n')


def install(args):
    toolbox = args.tools_dir.expanduser().resolve()
    source = toolbox / "social-analyzer"
    runtime = toolbox / ".social-analyzer-runtime"
    wrapper = args.bin_dir.expanduser().resolve() / "motoko-social-profile"
    skill = HERE.parents[2] / "skills/social-profile"
    skill_link = args.skill_dir.expanduser().resolve() / skill.name
    if not (skill / "SKILL.md").is_file():
        raise Refused("install from an engine checkout/export with the accompanying skill")
    if wrapper.exists() or wrapper.is_symlink():
        if wrapper.is_symlink() or MARKER not in wrapper.read_text():
            raise Refused("existing command is not this installer's managed wrapper")
    if skill_link.exists() or skill_link.is_symlink():
        if not skill_link.is_symlink() or skill_link.resolve() != skill.resolve():
            raise Refused("existing skill path belongs to another installation")
    if runtime.exists() and not (runtime / "managed").is_file():
        raise Refused("runtime path belongs to another installation")
    created_source, created_runtime, created_link = False, False, False
    temporary = wrapper.with_name(wrapper.name + ".installing")
    if temporary.exists():
        raise Refused("unfinished wrapper staging file already exists")
    try:
        toolbox.mkdir(parents=True, exist_ok=True)
        if not source.exists():
            created_source = True
            command("git", "clone", "--no-local", "--single-branch", "--branch", PIN["branch"],
                    args.source or PIN["origin"], source)
            command("git", "-C", source, "checkout", "-B", PIN["branch"], PIN["revision"])
            command("git", "-C", source, "remote", "set-url", "origin", PIN["origin"])
        verify_source(source)
        if not runtime.exists():
            runtime.mkdir(mode=0o700)
            (runtime / "managed").write_text("motoko-social-profile\n")
            created_runtime = True
        interpreter = runtime / "venv/bin/python"
        if created_runtime:
            command("uv", "venv", "--python", PIN["python"], runtime / "venv")
        command("uv", "pip", "sync", "--python", interpreter, "--require-hashes",
                HERE / "requirements.lock")
        env = dict(os.environ, MOTOKO_TOOLS=str(toolbox))
        command(interpreter, "-I", "-B", HERE / "profile.py", "doctor", env=env)
        # No deployment links are changed until source and dependencies pass.
        wrapper.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("x") as handle:
            handle.write(wrapper_text(toolbox))
        temporary.chmod(0o755)
        skill_link.parent.mkdir(parents=True, exist_ok=True)
        if not skill_link.is_symlink():
            skill_link.symlink_to(skill, target_is_directory=True)
            created_link = True
        temporary.replace(wrapper)
    except BaseException:
        # Remove only partial objects created by this invocation.
        temporary.unlink(missing_ok=True)
        if created_link:
            skill_link.unlink()
        if created_runtime:
            shutil.rmtree(runtime)
        if created_source:
            shutil.rmtree(source)
        raise
    print(f"installed {wrapper}\nskill {skill_link}\nsource {source}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools-dir", type=Path,
                        default=Path(os.environ.get("MOTOKO_TOOLS", HERE.parents[3] / "tools")))
    parser.add_argument("--bin-dir", type=Path, default=Path.home() / ".local/bin")
    parser.add_argument("--skill-dir", type=Path, default=Path.home() / ".config/opencode/skills")
    parser.add_argument("--source", help="optional reviewed local clone; revision and hashes still enforced")
    args = parser.parse_args()
    install(args)


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, subprocess.SubprocessError) as exc:
        print(f"install failed: {type(exc).__name__}; no unverified launcher installed", file=sys.stderr)
        raise SystemExit(2)
