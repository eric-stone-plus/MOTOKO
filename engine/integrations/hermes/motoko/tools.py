"""Typed Hermes tools for the local MOTOKO supervisor protocol."""
from __future__ import annotations

import json
import sys
from motoko_host import client


def _schema(name, description, properties, required):
    return {"name": name, "description": description, "parameters": {
        "type": "object", "properties": properties, "required": required, "additionalProperties": False}}


ENGAGEMENT = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
              "description": "Existing, authorized engagement identifier. Never a path."}
STATUS = _schema("motoko_status", "Inspect MOTOKO capabilities and aggregate engagement state. "
    "No raw evidence is returned. Doctor defaults to scan scope; full also checks the audit loop. "
    "Check failures=0 and rules HIGH=0, then verify authorization and actual egress.", {
    "operation": {"type": "string", "enum": sorted(client.OPERATIONS - {"run"})},
    "scope": {"type": "string", "enum": ["scan", "full"],
              "description": "Doctor only: scan (default) or full, including audit-loop dependencies."},
    "engagement_id": ENGAGEMENT, "kind": {"type": "string", "enum": sorted(client.KINDS)},
    "state": {"type": "string", "enum": sorted(client.STATES)},
    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
    "after": {"type": "integer", "minimum": 0, "maximum": 2**63 - 1}}, ["operation"])
RUN = _schema("motoko_run", "Run a bounded MOTOKO wave budget for an existing, authorized engagement. "
    "The engine chooses tools, enforces scope, writes evidence and adapts priorities. "
    "Read stop_reason and pending; waiting requires respecting retry_after_s before resuming.", {
    "engagement_id": ENGAGEMENT,
    "max_cycles": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 20},
    "wave_cycles": {"type": "integer", "minimum": 1, "maximum": 100, "default": 5},
    "max_waves": {"type": "integer", "minimum": 1, "maximum": 100, "default": 4},
    "timeout": {"type": "number", "exclusiveMinimum": 0, "maximum": 3600, "default": 300},
    "wall_timeout": {"type": "number", "exclusiveMinimum": 0, "maximum": 3600, "default": 600}}, ["engagement_id"])


def register_tools(ctx):
    def available():
        try:
            client.settings(ctx.get_config)
            return sys.platform == "linux"
        except Exception:
            return False

    def handler(schema, fixed_operation=None):
        def call(args, **_kwargs):
            try:
                if sys.platform != "linux":
                    raise client.ClientError("unsupported_platform")
                if not isinstance(args, dict) or set(args) - set(schema["parameters"]["properties"]):
                    raise client.ClientError("invalid_arguments")
                operation = fixed_operation or args.get("operation")
                if not fixed_operation and operation == "run":
                    raise client.ClientError("invalid_arguments")
                options = {k: v for k, v in args.items() if k not in {"operation", "engagement_id"}}
                payload = client.request(operation, args.get("engagement_id"), options)
                from tools.interrupt import is_interrupted
                result = client.invoke(client.settings(ctx.get_config), payload, interrupted=is_interrupted)
            except client.ClientError as exc:
                result = {"ok": False, "error": str(exc)}
            except Exception:
                result = {"ok": False, "error": "local_transport_failed"}
            return json.dumps(result, ensure_ascii=True, allow_nan=False)
        return call

    for schema, operation in ((STATUS, None), (RUN, "run")):
        ctx.register_tool(name=schema["name"], toolset="motoko", schema=schema,
                          handler=handler(schema, operation), check_fn=available)
