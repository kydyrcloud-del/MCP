"""The authenticated identity behind the current MCP request."""

from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
from typing import Literal

# Key under which the HTTP layer stores the Caller in the ASGI scope
SCOPE_CALLER_KEY = "dynatrace_mcp.caller"


@dataclass(frozen=True)
class Caller:
    id: str  # stable identifier: Entra object ID (oid), or a fixed id for bearer / stdio
    name: str  # human-readable: UPN / preferred_username / app id
    auth: Literal["entra", "bearer", "stdio", "anonymous"]
    roles: frozenset[str] = field(default_factory=frozenset)
    app_id: str | None = None  # Entra client application (azp / appid)
    token_type: Literal["user", "app"] | None = None  # delegated (user) or app-only token
    tenant_id: str | None = None


ANONYMOUS = Caller(id="anonymous", name="anonymous", auth="anonymous")

_current_caller: contextvars.ContextVar[Caller] = contextvars.ContextVar("dynatrace_mcp_caller", default=ANONYMOUS)


def get_current_caller() -> Caller:
    """Caller of the request being handled (set by AuthorizationMiddleware)."""
    return _current_caller.get()


def set_current_caller(caller: Caller) -> contextvars.Token[Caller]:
    return _current_caller.set(caller)


def reset_current_caller(token: contextvars.Token[Caller]) -> None:
    _current_caller.reset(token)
