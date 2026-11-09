"""Audit log: one JSON line per tool call on stderr.

Dynatrace only sees the service identity this server uses, so this log is the record
of which person or application ran which tool with which arguments.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

from .caller import Caller

# Free-text content that may hold sensitive data: only its length is logged
REDACTED_ARGS = frozenset({"body", "message"})
MAX_ARG_CHARS = 2000


def _sanitize(args: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in args.items():
        if key in REDACTED_ARGS and isinstance(value, str):
            out[key] = f"<redacted {len(value)} chars>"
        elif isinstance(value, str) and len(value) > MAX_ARG_CHARS:
            out[key] = value[:MAX_ARG_CHARS] + f"...<truncated {len(value) - MAX_ARG_CHARS} chars>"
        else:
            out[key] = value
    return out


class AuditLogger:
    def __init__(self, enabled: bool = True, include_args: bool = True) -> None:
        self.enabled = enabled
        self.include_args = include_args

    def tool_call(
        self,
        caller: Caller,
        tool: str,
        args: dict[str, Any] | None,
        outcome: str,
        duration_ms: float | None = None,
        detail: str | None = None,
    ) -> None:
        if not self.enabled:
            return
        entry: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": "tool_call",
            "tool": tool,
            "outcome": outcome,  # ok | error | forbidden
            "caller_id": caller.id,
            "caller_name": caller.name,
            "auth": caller.auth,
            "token_type": caller.token_type,
            "app_id": caller.app_id,
            "roles": sorted(caller.roles),
        }
        if duration_ms is not None:
            entry["duration_ms"] = round(duration_ms, 1)
        if detail:
            entry["detail"] = detail[:500]
        if self.include_args and args:
            entry["args"] = _sanitize(args)
        print("AUDIT " + json.dumps(entry, default=str), file=sys.stderr, flush=True)
