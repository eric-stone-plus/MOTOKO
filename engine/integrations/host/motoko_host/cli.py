"""One bounded host request on stdin, one validated response on stdout."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import select
import signal
import sys
import time

from . import client


def main(argv=None):
    parser = argparse.ArgumentParser(prog="motoko-host")
    parser.add_argument("--config", required=True, help="Private JSON transport configuration")
    parser.add_argument("--disconnect-cancels", action="store_true",
                        help="Keep stdin open until exit; closing it cancels the downstream session")
    args = parser.parse_args(argv)
    cancelled = False

    def stop(_signum, _frame):
        nonlocal cancelled
        cancelled = True

    saved = {s: signal.signal(s, stop) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    record = None
    try:
        path = client._absolute_path(args.config, kind="config", reject_symlink=True)
        with open(path, "rb") as stream:
            raw = stream.read(client.FRAME_LIMIT + 1)
        if len(raw) > client.FRAME_LIMIT:
            raise client.ClientError("configuration_required")
        config = json.loads(raw, object_pairs_hook=client._object, parse_constant=client._constant)
        if not isinstance(config, dict):
            raise client.ClientError("configuration_required")
        config = client.settings(config.get)
        records = Path(config["runtime_root"]) / ".host-processes"
        records.mkdir(mode=0o700, exist_ok=True)
        client._absolute_path(str(records), kind="dir", private=True, reject_symlink=True)
        record = records / f"{os.getpid()}.supervisor.pid"
        with os.fdopen(os.open(record, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as stream:
            stream.write(str(os.getpid()) + "\n")
        raw = bytearray()
        deadline = time.monotonic() + 10
        while b"\n" not in raw:
            if cancelled:
                raise client.ClientError("cancelled")
            if time.monotonic() >= deadline:
                raise client.ClientError("deadline_exceeded")
            if not select.select([sys.stdin.buffer], [], [], .1)[0]:
                continue
            chunk = os.read(sys.stdin.fileno(), min(8192, client.FRAME_LIMIT + 1 - len(raw)))
            if not chunk:
                raise client.ClientError("invalid_arguments")
            raw.extend(chunk)
            if len(raw) > client.FRAME_LIMIT:
                raise client.ClientError("invalid_arguments")
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise client.ClientError("invalid_arguments")
        payload = json.loads(raw, object_pairs_hook=client._object, parse_constant=client._constant)
        lease = select.poll()
        lease.register(sys.stdin.fileno(), select.POLLHUP | select.POLLERR)
        result = client.invoke(config, payload, interrupted=lambda: cancelled or
                               (args.disconnect_cancels and bool(lease.poll(0))))
        code = result["exit_code"]
    except client.ClientError as exc:
        code = 2
        result = {"ok": False, "error": str(exc) if str(exc) in client.ERRORS else "transport_failed"}
    except (Exception, KeyboardInterrupt):
        code, result = 3, {"ok": False, "error": "transport_failed"}
    finally:
        if record is not None:
            with contextlib.suppress(FileNotFoundError):
                record.unlink()
        for sig, handler in saved.items():
            signal.signal(sig, handler)
    with contextlib.suppress(BrokenPipeError):
        sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False) + "\n")
        sys.stdout.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
