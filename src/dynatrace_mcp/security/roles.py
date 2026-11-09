"""Roles and the tool -> role policy.

Each tool lists the roles that may call it. A caller may call a tool when it holds
at least one of those roles. Tools that are not in the policy are denied (fail closed).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .caller import Caller

ROLE_READ = "Dynatrace.Read"
ROLE_QUERY = "Dynatrace.Query"
ROLE_WRITE = "Dynatrace.Write"
ROLE_ADMIN = "Dynatrace.Admin"
ALL_ROLES: tuple[str, ...] = (ROLE_READ, ROLE_QUERY, ROLE_WRITE, ROLE_ADMIN)

# Read-only tools that run fixed, bounded queries or metadata calls
READ_TOOLS = frozenset(
    {
        "get_environment_info",
        "list_problems",
        "list_vulnerabilities",
        "list_exceptions",
        "find_entity_by_name",
        "verify_dql",
        "list_deployments",
        "get_entity_details",
        "get_service_health",
    }
)

ALL_TOOLS = READ_TOOLS


def default_tool_roles() -> dict[str, frozenset[str]]:
    policy: dict[str, frozenset[str]] = {}
    for tool in READ_TOOLS:
        policy[tool] = frozenset({ROLE_READ, ROLE_QUERY, ROLE_ADMIN})
    return policy


class ToolPolicy:
    """Decides which tools a caller may list and call."""

    def __init__(self, overrides: Mapping[str, Iterable[str]] | None = None) -> None:
        self._map = default_tool_roles()
        for tool, roles in (overrides or {}).items():
            self._map[tool] = frozenset(roles)

    @property
    def known_tools(self) -> frozenset[str]:
        return frozenset(self._map)

    @property
    def known_roles(self) -> frozenset[str]:
        return frozenset(r for roles in self._map.values() for r in roles)

    def allowed_roles(self, tool: str) -> frozenset[str]:
        return self._map.get(tool, frozenset())

    def is_allowed(self, caller: Caller, tool: str) -> bool:
        return bool(caller.roles & self.allowed_roles(tool))

    def allowed_tools(self, caller: Caller) -> frozenset[str]:
        return frozenset(t for t in self._map if self.is_allowed(caller, t))

    def as_dict(self) -> dict[str, list[str]]:
        return {t: sorted(r) for t, r in sorted(self._map.items())}
