"""MCP middleware that enforces the tool policy for every request.

* ``tools/list``: only the tools the caller may use are returned.
* ``tools/call``: calls to tools the caller may not use are refused before the
  tool runs, and every call is written to the audit log.

The caller comes from the HTTP layer (stored in the ASGI scope after token
validation). Requests without an HTTP request (stdio, in-memory) use the
``default_caller`` configured at startup.
"""

from __future__ import annotations

import time
from typing import Any

from mcp import types

from .audit import AuditLogger
from .caller import SCOPE_CALLER_KEY, Caller, reset_current_caller, set_current_caller
from .roles import ToolPolicy


def caller_from_request(request: Any) -> Caller | None:
    scope = getattr(request, "scope", None)
    if isinstance(scope, dict):
        caller = scope.get(SCOPE_CALLER_KEY)
        if isinstance(caller, Caller):
            return caller
    return None


def _forbidden(tool: str, caller: Caller, policy: ToolPolicy) -> types.CallToolResult:
    needed = ", ".join(sorted(policy.allowed_roles(tool))) or "none configured"
    return types.CallToolResult(
        content=[
            types.TextContent(
                type="text",
                text=f"Forbidden: '{caller.name}' is not allowed to call '{tool}'. Required role (any of): {needed}.",
            )
        ],
        is_error=True,
    )


def _filter_tools(result: Any, allowed: frozenset[str]) -> Any:
    if isinstance(result, types.ListToolsResult):
        return result.model_copy(update={"tools": [t for t in result.tools if t.name in allowed]})
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return {**result, "tools": [t for t in result["tools"] if (t.get("name") if isinstance(t, dict) else None) in allowed]}
    return result


def _is_error(result: Any) -> bool:
    if isinstance(result, types.CallToolResult):
        return bool(result.is_error)
    if isinstance(result, dict):
        return bool(result.get("isError") or result.get("is_error"))
    return False


class AuthorizationMiddleware:
    def __init__(self, policy: ToolPolicy, default_caller: Caller, audit: AuditLogger) -> None:
        self.policy = policy
        self.default_caller = default_caller
        self.audit = audit

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        caller = caller_from_request(getattr(ctx, "request", None)) or self.default_caller
        token = set_current_caller(caller)
        try:
            method = getattr(ctx, "method", None)
            if method == "tools/list":
                return _filter_tools(await call_next(ctx), self.policy.allowed_tools(caller))
            if method == "tools/call":
                return await self._call_tool(ctx, call_next, caller)
            return await call_next(ctx)
        finally:
            reset_current_caller(token)

    async def _call_tool(self, ctx: Any, call_next: Any, caller: Caller) -> Any:
        params = getattr(ctx, "params", None) or {}
        tool = params.get("name") if isinstance(params, dict) else getattr(params, "name", None)
        args = params.get("arguments") if isinstance(params, dict) else getattr(params, "arguments", None)
        tool = str(tool or "")
        args = args if isinstance(args, dict) else {}

        # Unknown tool names fall through so the SDK reports "unknown tool" as usual.
        if tool in self.policy.known_tools and not self.policy.is_allowed(caller, tool):
            self.audit.tool_call(caller, tool, args, "forbidden")
            return _forbidden(tool, caller, self.policy)

        start = time.monotonic()
        try:
            result = await call_next(ctx)
        except Exception as e:
            self.audit.tool_call(caller, tool, args, "error", (time.monotonic() - start) * 1000, repr(e))
            raise
        self.audit.tool_call(caller, tool, args, "error" if _is_error(result) else "ok", (time.monotonic() - start) * 1000)
        return result
