"""Host-neutral MOTOKO/1 client for local or SSH stdio. No sockets or graph access."""
from __future__ import annotations

import contextlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

PROTOCOL = "motoko/1"
FRAME_LIMIT = 64 * 1024
TRANSPORTS = {"local", "ssh"}
OPERATIONS = {"capabilities", "doctor", "rules", "digest", "query", "events", "health", "run"}
KINDS = {"asset", "finding", "hypothesis", "evidence", "access", "path"}
STATES = {"active", "candidate", "triaged", "reproduced", "verified", "exploitable",
          "confirmed_impact", "false_positive", "duplicate", "out_of_scope", "wont_test",
          "proposed", "testing", "done", "rejected", "error", "timeout", "failed"}
ERRORS = {"invalid_request_or_result", "deadline_exceeded", "cancelled", "response_too_large",
          "engine_unavailable", "engagement_not_found", "engine_failed", "engine_closed_pipe",
          "invalid_arguments", "configuration_required", "runtime_permissions",
          "incompatible_engine", "invalid_exit_status", "unsupported_platform",
          "local_transport_failed", "invalid_response", "transport_failed"}
SAFE_ENV = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR",
            "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "http_proxy", "https_proxy", "all_proxy",
            "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}

_REMOTE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*(?:@[A-Za-z0-9][A-Za-z0-9_.-]*)?$")
_REMOTE_TOKEN = re.compile(r"^[A-Za-z0-9_./-]+$")


class ClientError(Exception):
    """Only constant error codes may cross the host boundary."""


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _number(value, low, high):
    return type(value) in (float, int) and math.isfinite(value) and low <= value <= high


def _absolute_path(value, *, kind, required=True, private=False, reject_symlink=False):
    """Validate an owner-supplied path without accepting a symlink endpoint."""
    if value == "" and not required:
        return None
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise ClientError("configuration_required")
    path = Path(value)
    if reject_symlink and path.is_symlink():
        raise ClientError("configuration_required")
    if kind == "file":
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ClientError("engine_unavailable")
    elif kind in {"known_hosts", "identity_file", "config"}:
        if (not path.is_file() or path.stat().st_mode & 0o077
                or path.stat().st_uid != os.getuid()):
            raise ClientError("configuration_required")
    elif kind == "dir":
        if not path.is_dir() or (private and (path.stat().st_mode & 0o077
                                              or path.stat().st_uid != os.getuid())):
            raise ClientError("configuration_required")
    return str(path)


def _remote_token(value, *, absolute=False):
    if not isinstance(value, str) or (absolute and not value.startswith("/")):
        raise ClientError("configuration_required")
    if (not _REMOTE_TOKEN.fullmatch(value) or "//" in value or
            any(part == ".." for part in value.split("/"))):
        raise ClientError("configuration_required")
    return value


def request(operation, engagement_id=None, options=None):
    """Validate independently of model schema enforcement before any process starts."""
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ClientError("invalid_arguments")
    if options is not None and not isinstance(options, dict):
        raise ClientError("invalid_arguments")
    opts = dict(options or {})
    if operation in {"capabilities", "doctor", "rules"}:
        if engagement_id is not None:
            raise ClientError("invalid_arguments")
    elif not isinstance(engagement_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", engagement_id):
        raise ClientError("invalid_arguments")
    allowed = {"query": {"kind", "state", "limit", "after"}, "events": {"limit", "after"},
               "run": {"max_cycles", "wave_cycles", "max_waves", "timeout", "wall_timeout"}}
    if set(opts) - allowed.get(operation, set()):
        raise ClientError("invalid_arguments")
    for key, high in (("max_cycles", 1000), ("wave_cycles", 100), ("max_waves", 100), ("limit", 100)):
        if key in opts and not _integer(opts[key], 1, high):
            raise ClientError("invalid_arguments")
    if "after" in opts and not _integer(opts["after"], 0, 2**63 - 1):
        raise ClientError("invalid_arguments")
    for key, choices in (("kind", KINDS), ("state", STATES)):
        if key in opts and (not isinstance(opts[key], str) or opts[key] not in choices):
            raise ClientError("invalid_arguments")
    for key in ("timeout", "wall_timeout"):
        if key in opts and not _number(opts[key], 0.001, 3600):
            raise ClientError("invalid_arguments")
    if operation == "run":
        for key, default in (("max_cycles", 20), ("wave_cycles", 5), ("max_waves", 4), ("timeout", 300), ("wall_timeout", 600)):
            opts.setdefault(key, default)
    result = {"protocol": PROTOCOL, "operation": operation, "options": opts}
    if engagement_id is not None:
        result["engagement_id"] = engagement_id
    return result


def settings(get_config):
    transport = get_config("transport", "local")
    if transport not in TRANSPORTS:
        raise ClientError("configuration_required")
    result = {"transport": transport}
    # runtime_root is always local: it is the private supervisor working
    # directory and the location of the numeric PID records. Remote graph
    # state is selected independently by remote_root below.
    result["runtime_root"] = _absolute_path(
        get_config("runtime_root", ""), kind="dir", private=True, reject_symlink=True)
    if transport == "local":
        result["executable"] = _absolute_path(get_config("executable", ""), kind="file")
    else:
        result["ssh_binary"] = _absolute_path(
            get_config("ssh_binary", "/usr/bin/ssh"), kind="file")
        host = get_config("remote_host", "")
        if not isinstance(host, str) or not _REMOTE_HOST.fullmatch(host):
            raise ClientError("configuration_required")
        result["remote_host"] = host
        result["remote_executable"] = _remote_token(
            get_config("remote_executable", "/usr/local/bin/motoko"), absolute=True)
        result["remote_root"] = _remote_token(get_config("remote_root", ""), absolute=True)
        port = get_config("ssh_port", 22)
        if not _integer(port, 1, 65535):
            raise ClientError("configuration_required")
        result["ssh_port"] = port
        known_hosts = get_config("known_hosts", "")
        if not known_hosts:
            raise ClientError("configuration_required")
        result["known_hosts"] = _absolute_path(
            known_hosts, kind="known_hosts", reject_symlink=True)
        result["identity_file"] = _absolute_path(
            get_config("identity_file", ""), kind="identity_file", reject_symlink=True)
        for key in ("remote_tools_root", "remote_wordlist_dir"):
            value = get_config(key, "")
            if value:
                result[key] = _remote_token(value, absolute=True)
    for key in ("tools_root", "wordlist_dir"):
        value = get_config(key, "")
        if value == "":
            continue
        result[key] = _absolute_path(value, kind="dir")
    mode = get_config("egress_mode", "proxy")
    replay = get_config("allow_direct_replay", False)
    if mode not in ("proxy", "direct") or type(replay) is not bool:
        raise ClientError("configuration_required")
    result.update(egress_mode=mode, allow_direct_replay=replay)
    return result


def child_env(config):
    # Keep this client host-neutral: Hermes and Pi both use it. The allowlist
    # removes model credentials and arbitrary engine overrides before either a
    # local child or an SSH client is spawned.
    env = {key: value for key, value in os.environ.items() if key in SAFE_ENV}
    env.update(PYTHONUNBUFFERED="1", PYTHONNOUSERSITE="1")
    if config["transport"] == "local":
        env.update(MOTOKO_HOME=config["runtime_root"], MOTOKO_EGRESS_MODE=config["egress_mode"])
    for key, target in (("tools_root", "MOTOKO_TOOLS"), ("wordlist_dir", "MOTOKO_WORDLIST_DIR")):
        if key in config:
            env[target] = config[key]
    if config["transport"] == "local":
        env["MOTOKO_ALLOW_DIRECT_REPLAY"] = "1" if config["allow_direct_replay"] else "0"
    return env


def _ssh_argv(config):
    """Build a fixed SSH argv; no caller-controlled shell command is accepted."""
    argv = [config["ssh_binary"], "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "RequestTTY=no",
            "-o", "ClearAllForwardings=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "ForwardAgent=no",
            "-o", "PermitLocalCommand=no", "-o", "GlobalKnownHostsFile=/dev/null",
            "-i", config["identity_file"]]
    if config.get("known_hosts"):
        argv.extend(["-o", f"UserKnownHostsFile={config['known_hosts']}"])
    argv.extend(["-p", str(config["ssh_port"]), config["remote_host"], "exec", "env",
                 f"MOTOKO_HOME={config['remote_root']}",
                 f"MOTOKO_EGRESS_MODE={config['egress_mode']}",
                 "MOTOKO_ALLOW_DIRECT_REPLAY=" + ("1" if config["allow_direct_replay"] else "0")])
    if config.get("remote_tools_root"):
        argv.append(f"MOTOKO_TOOLS={config['remote_tools_root']}")
    if config.get("remote_wordlist_dir"):
        argv.append(f"MOTOKO_WORDLIST_DIR={config['remote_wordlist_dir']}")
    argv.extend([config["remote_executable"], "adapter", "--stdio", "--disconnect-cancels"])
    return argv


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ClientError("invalid_response")
        value[key] = item
    return value


def _constant(_value):
    raise ClientError("invalid_response")


def response(raw, operation, request_id):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ClientError("invalid_response") from None
    if (not isinstance(value, dict) or value.get("protocol") != PROTOCOL
            or type(value.get("request_id")) is not int or value["request_id"] != request_id
            or type(value.get("ok")) is not bool or not _integer(value.get("exit_code"), 0, 255)
            or value["ok"] != (value["exit_code"] == 0)
            or value.get("operation", operation) != operation
            or set(value) - {"protocol", "request_id", "operation", "ok", "exit_code", "error", "result", "summary"}):
        raise ClientError("invalid_response")
    if ("result" if operation == "run" else "summary") in value:
        raise ClientError("invalid_response")
    if "error" in value and (not isinstance(value["error"], str) or value["error"] not in ERRORS):
        raise ClientError("invalid_response")
    from .schema import check_result
    field = "summary" if operation == "run" else "result"
    if field in value:
        data = value[field]
        if not check_result(operation, data, value["ok"]):
            raise ClientError("invalid_response")
    elif value["ok"] or "error" not in value:
        raise ClientError("invalid_response")
    return value


def _stop(proc):
    """Only our recorded PID/group; allow engine finally blocks to reap scanners."""
    # Closing the lease triggers remote cleanup too; killing only local ssh
    # cannot reliably deliver a signal through a non-PTY channel.
    with contextlib.suppress(OSError):
        proc.stdin.close()
    if proc.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=3)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The recorded group can outlive its leader.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait(timeout=2)


def _exchange(proc, payload, deadline, interrupted):
    outgoing = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode() + b"\n"
    incoming = bytearray()
    if len(outgoing) > FRAME_LIMIT:
        raise ClientError("invalid_arguments")
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdin, selectors.EVENT_WRITE)
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            if interrupted():
                raise ClientError("cancelled")
            left = deadline - time.monotonic()
            if left <= 0:
                raise ClientError("deadline_exceeded")
            for key, mask in selector.select(min(left, 0.1)):
                if mask & selectors.EVENT_WRITE:
                    try:
                        written = os.write(key.fd, outgoing)
                    except BlockingIOError:
                        continue
                    outgoing = outgoing[written:]
                    if not outgoing:
                        selector.unregister(proc.stdin)
                else:
                    try:
                        block = os.read(key.fd, min(8192, FRAME_LIMIT + 1 - len(incoming)))
                    except BlockingIOError:
                        continue
                    if not block:
                        raise ClientError("engine_closed_pipe")
                    incoming.extend(block)
                    if len(incoming) > FRAME_LIMIT:
                        raise ClientError("response_too_large")
                    if b"\n" in incoming:
                        if outgoing or not incoming.endswith(b"\n") or incoming.count(b"\n") != 1:
                            raise ClientError("invalid_response")
                        return response(bytes(incoming), payload["operation"], payload["request_id"])


def invoke(config, payload, *, interrupted=lambda: False):
    """One short-lived session per host tool call; negotiate before dispatch."""
    if not isinstance(config, dict) or not isinstance(payload, dict):
        raise ClientError("invalid_arguments")
    config = settings(config.get)
    if (set(payload) - {"protocol", "operation", "engagement_id", "options"}
            or payload.get("protocol") != PROTOCOL):
        raise ClientError("invalid_arguments")
    payload = request(payload.get("operation"), payload.get("engagement_id"), payload.get("options"))
    if interrupted():
        raise ClientError("cancelled")
    runtime = Path(config["runtime_root"])
    try:
        runtime_info = runtime.lstat()
    except OSError:
        raise ClientError("runtime_permissions") from None
    if (stat.S_ISLNK(runtime_info.st_mode) or not stat.S_ISDIR(runtime_info.st_mode)
            or runtime_info.st_mode & 0o077 or runtime_info.st_uid != os.getuid()):
        raise ClientError("runtime_permissions")
    record_dir = runtime / ".host-processes"
    record_dir.mkdir(mode=0o700, exist_ok=True)
    if (record_dir.is_symlink() or record_dir.stat().st_mode & 0o077
            or record_dir.stat().st_uid != os.getuid()):
        raise ClientError("runtime_permissions")
    argv = ([config["executable"], "adapter", "--stdio", "--disconnect-cancels"] if config["transport"] == "local"
            else _ssh_argv(config))
    proc = subprocess.Popen(argv,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=child_env(config), cwd=config["runtime_root"], start_new_session=True, bufsize=0)
    record = record_dir / f"{proc.pid}.pid"
    try:
        fd = os.open(record, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(str(proc.pid) + "\n")
        os.set_blocking(proc.stdin.fileno(), False)
        os.set_blocking(proc.stdout.fileno(), False)
        hello = _exchange(proc, {"protocol": PROTOCOL, "request_id": 1, "operation": "capabilities"},
                          time.monotonic() + 10, interrupted)
        caps = hello.get("result", {})
        if (not hello["ok"] or caps.get("transport") != "stdio" or
                payload["operation"] not in caps.get("operations", []) or caps.get("mutating_operations") != ["run"]
                or caps.get("disconnect_cancels") is not True):
            raise ClientError("incompatible_engine")
        if payload["operation"] == "capabilities":
            result = hello
        else:
            payload = {**payload, "request_id": 2}
            timeout = payload["options"].get("wall_timeout", 90)
            result = _exchange(proc, payload, time.monotonic() + timeout + 2, interrupted)
        proc.stdin.close()
        # Drain to EOF, rejecting delayed extra frames instead of accepting
        # one plausible response followed by uncontrolled stdout.
        finish = time.monotonic() + 5
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                if interrupted():
                    raise ClientError("cancelled")
                if time.monotonic() >= finish:
                    raise ClientError("deadline_exceeded")
                if selector.select(.1):
                    if os.read(proc.stdout.fileno(), 1):
                        raise ClientError("invalid_response")
                    break
        proc.wait(timeout=max(.01, finish - time.monotonic()))
        if proc.returncode != result["exit_code"]:
            raise ClientError("invalid_exit_status")
        return result
    finally:
        _stop(proc)
        for pipe in (proc.stdin, proc.stdout):
            pipe.close()
        with contextlib.suppress(FileNotFoundError):
            record.unlink()
