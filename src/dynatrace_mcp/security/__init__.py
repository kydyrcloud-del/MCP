"""Client authentication (Entra ID / static bearer) and per-tool authorization."""

from .audit import AuditLogger
from .caller import ANONYMOUS, SCOPE_CALLER_KEY, Caller, get_current_caller
from .entra import AuthenticationError, AuthenticationUnavailable, EntraTokenVerifier
from .middleware import AuthorizationMiddleware
from .roles import ALL_ROLES, ALL_TOOLS, ROLE_ADMIN, ROLE_QUERY, ROLE_READ, ROLE_WRITE, ToolPolicy

__all__ = [
    "ALL_ROLES",
    "ALL_TOOLS",
    "ANONYMOUS",
    "ROLE_ADMIN",
    "ROLE_QUERY",
    "ROLE_READ",
    "ROLE_WRITE",
    "SCOPE_CALLER_KEY",
    "AuditLogger",
    "AuthenticationError",
    "AuthenticationUnavailable",
    "AuthorizationMiddleware",
    "Caller",
    "EntraTokenVerifier",
    "ToolPolicy",
    "get_current_caller",
]
