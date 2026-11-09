"""Dynatrace MCP Server: tool definitions, runtime wiring, CLI and startup.

Run with stdio (default) or as a stateless Streamable-HTTP server (--http).
"""

import argparse
import asyncio
import functools
import json
import os
import sys
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__
from .auth import create_dt_client
from .capabilities import queries
from .capabilities.execute_dql import (
    DEFAULT_HTTP_MAX_POLL_SECONDS,
    DEFAULT_MAX_POLL_SECONDS,
    set_max_poll_seconds,
    verify_dql_statement,
)
from .client import DynatraceApiError, DynatraceClient
from .config import DynatraceEnv, SecuritySettings, get_dynatrace_env, get_security_settings
from .security import ANONYMOUS, AuditLogger, AuthorizationMiddleware, Caller, ToolPolicy
from .utils.dql_sanitize import check_timeframe_limit
from .utils.entity_types import get_entity_type_from_id

DT_MCP_AUTH_CODE_FLOW_OAUTH_CLIENT_ID = "dt0s12.local-dt-mcp-server"

SCOPES_BASE = ["app-engine:apps:run"]

ALL_REQUIRED_SCOPES = SCOPES_BASE + [
    # Grail storage
    "storage:events:read",
    "storage:user.events:read",
    "storage:buckets:read",
    "storage:security.events:read",
    "storage:entities:read",
    "storage:smartscape:read",
    "storage:metrics:read",
]


def log(msg: str = "") -> None:
    """All logging goes to stderr: stdout is reserved for the MCP stdio protocol."""
    print(msg, file=sys.stderr, flush=True)


# =============================================================================
# Runtime state shared by all tools
# =============================================================================


class Runtime:
    def __init__(
        self,
        env: DynatraceEnv,
        oauth_redirect_port: int | None,
        security: SecuritySettings | None = None,
    ) -> None:
        self.env = env
        self.oauth_redirect_port = oauth_redirect_port
        self.security = security or get_security_settings({}, http_mode=False)
        self.policy = ToolPolicy(self.security.tool_roles_override)
        self.audit = AuditLogger(self.security.audit_log, self.security.audit_log_args)
        # Used when a request carries no authenticated caller. In HTTP mode every request is
        # authenticated by the HTTP layer, so the fallback has no roles (fail closed).
        self.default_caller = (
            ANONYMOUS
            if self.security.http_mode
            else Caller(id="stdio", name="local-stdio-user", auth="stdio", roles=frozenset(self.security.stdio_roles))
        )

    @property
    def dt_environment(self) -> str:
        return self.env.dt_environment

    async def client(self, scopes: list[str]) -> DynatraceClient:
        """Authenticated Dynatrace client. The auth-code flow always requests all scopes so one login covers every tool."""
        e = self.env
        auth_code_flow = bool(e.oauth_client_id and not e.oauth_client_secret)
        return await create_dt_client(
            e.dt_environment,
            ALL_REQUIRED_SCOPES if auth_code_flow else scopes,
            e.oauth_client_id,
            e.oauth_client_secret,
            e.dt_platform_token,
            self.oauth_redirect_port,
        )


# =============================================================================
# Tool helpers
# =============================================================================


def guarded(fn: Callable[..., Awaitable[str]]) -> Callable[..., Awaitable[str]]:
    """Uniform error handling for every tool: API and unexpected errors become MCP tool errors.

    Rate limiting is not done here: it is expected in front of the server (e.g. Azure API Management).
    """

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            return await fn(*args, **kwargs)
        except ToolError:
            raise
        except DynatraceApiError as e:
            raise ToolError(str(e)) from e
        except Exception as e:
            log(f"Tool {fn.__name__} failed: {e!r}")
            raise ToolError(f"Error: {e}") from e

    return wrapper


def _short(value: Any, limit: int = 200) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text if len(text) <= limit else text[:limit] + "…"


def _fields(record: dict[str, Any], skip: tuple[str, ...] = ()) -> str:
    """All non-empty fields of a record as `key=value`, for records whose schema varies."""
    return ", ".join(f"{k}={_short(v)}" for k, v in record.items() if k not in skip and v not in (None, "", [], {}))


def _fmt(value: float | None, unit: str = "", digits: int = 1) -> str:
    return "n/a" if value is None else f"{value:,.{digits}f}{unit}"


def _change(now: float | None, before: float | None) -> str:
    if now is None or before is None or before == 0:
        return "n/a"
    return f"{(now - before) / before * 100:+.0f}%"


# =============================================================================
# Server + tools
# =============================================================================


def build_server(rt: Runtime) -> MCPServer:
    mcp = MCPServer(
        name="Dynatrace MCP Server",
        version=__version__,
        middleware=[AuthorizationMiddleware(rt.policy, rt.default_caller, rt.audit)],
    )
    dt_env = rt.dt_environment
    max_tf = rt.env.max_query_timeframe

    # ------------------------------------------------------------------ environment

    @mcp.tool(
        name="get_environment_info",
        title="Get Environment Info",
        description="Get information about the connected Dynatrace Environment (Tenant) and verify the connection and authentication.",
        annotations=ToolAnnotations(read_only_hint=True),
    )
    @guarded
    async def get_environment_info() -> str:
        client = await rt.client(SCOPES_BASE)
        info = await client.get("/platform/management/v1/environment")
        return f"Environment Information (also referred to as tenant):\n{json.dumps(info)}\nYou can reach it via {dt_env}\n"

    # ------------------------------------------------------------------ vulnerabilities

    @mcp.tool(
        name="list_vulnerabilities",
        title="List Vulnerabilities",
        description="Retrieve all active (non-muted) vulnerabilities from Dynatrace. An additional filter can be provided using DQL filter (filter for a specific entity type and id).",
        annotations=ToolAnnotations(read_only_hint=True),
    )
    @guarded
    async def list_vulnerabilities(
        timeframe: Annotated[str, Field(description=f'Timeframe to query vulnerabilities (e.g., "12h", "24h", "7d", "30d"). Maximum: "{max_tf}". Default: "30d".')] = "30d",
        riskScore: Annotated[float, Field(description="Minimum risk score of vulnerabilities to list (default: 8.0)")] = 8.0,
        additionalFilter: Annotated[
            str | None,
            Field(
                description="Additional DQL-based filter, e.g. 'dt.entity.<service|host|application|$type> == \"<entity-id>\"', "
                "'affected_entity.name contains \"<entity-name>\"', 'entity_tags == array(\"dt.owner:team-foobar\")', "
                "'vulnerability.stack == \"CODE_LIBRARY\"', 'vulnerability.risk.level == \"CRITICAL\"' or "
                "'vulnerability.davis_assessment.exposure_status == \"PUBLIC_NETWORK\"'"
            ),
        ] = None,
        maxVulnerabilitiesToDisplay: Annotated[int, Field(description="Maximum number of vulnerabilities to display in the response.")] = 25,
    ) -> str:
        check_timeframe_limit(timeframe, max_tf)
        client = await rt.client(SCOPES_BASE + ["storage:events:read", "storage:buckets:read", "storage:security.events:read"])
        result = await queries.list_vulnerabilities(client, additionalFilter, riskScore, timeframe)
        if not result:
            return f"No vulnerabilities found in the last {timeframe}"

        resp = f"Found {len(result)} vulnerabilities in the last {timeframe}! Displaying the top {maxVulnerabilitiesToDisplay} vulnerabilities:\n"
        resp += "".join(f"\n* {v}" for v in result[:maxVulnerabilitiesToDisplay])
        resp += (
            "\nNext Steps:"
            f'\n1. For specific vulnerabilities, fetch more details in a Dynatrace notebook with the following query:\n'
            f'"fetch security.events, from: now()-{timeframe}, to: now()\n'
            '  | filter event.provider=="Dynatrace" AND event.type=="VULNERABILITY_STATE_REPORT_EVENT" AND event.level=="ENTITY"\n'
            '  | filter vulnerability.id == "<vulnerability-id>"\n'
            "  | dedup {vulnerability.display_id, affected_entity.id}, sort:{timestamp desc}\n"
            "  | fields vulnerability.external_id, vulnerability.display_id, vulnerability.external_url, vulnerability.cvss.vector, "
            "vulnerability.type, vulnerability.risk.score, vulnerability.stack, vulnerability.remediation.description, "
            "vulnerability.parent.davis_assessment.score, affected_entity.name, affected_entity.affected_processes.names, "
            "affected_entity.vulnerable_functions, related_entities.databases.count, related_entities.databases.ids, "
            "related_entities.hosts.ids, related_entities.hosts.names, related_entities.kubernetes_clusters.names, "
            "related_entities.kubernetes_workloads.count, related_entities.services.count, vulnerability.resolution.status, "
            "vulnerability.parent.mute.status, vulnerability.mute.status, vulnerability.description, vulnerability.technology, "
            'vulnerability.code_location.name, entry_points.entry_point_jsons"'
            "\nThis will give you more details about the vulnerability, including the affected entity, risk score, code-level insights, and remediation actions."
            f"\n2. Last but not least, tell the user to visit {dt_env}/ui/apps/dynatrace.security.vulnerabilities/vulnerabilities/<vulnerability-id> for full details."
        )
        return resp

    # ------------------------------------------------------------------ problems

    @mcp.tool(
        name="list_problems",
        title="List Problems",
        description='List all problems (based on "fetch dt.davis.problems") known on Dynatrace, sorted by their recency.',
        annotations=ToolAnnotations(read_only_hint=True),
    )
    @guarded
    async def list_problems(
        timeframe: Annotated[str, Field(description=f'Timeframe to query problems (e.g., "12h", "24h", "7d", "30d"). Maximum: "{max_tf}". Default: "24h".')] = "24h",
        status: Annotated[
            Literal["ACTIVE", "CLOSED", "ALL"],
            Field(description='"ACTIVE": only active problems, "CLOSED": only closed problems, "ALL": both (default)'),
        ] = "ALL",
        additionalFilter: Annotated[
            str | None,
            Field(
                description="Additional DQL filter for dt.davis.problems - filter by entity type (preferred), like "
                "'dt.entity.<service|host|application|$type> == \"<entity-id>\"', or by entity tags "
                "'entity_tags == array(\"dt.owner:team-foobar\", \"tag:tag\")'"
            ),
        ] = None,
        maxProblemsToDisplay: Annotated[int, Field(ge=1, le=5000, description="Maximum number of problems to display in the response.")] = 10,
    ) -> str:
        check_timeframe_limit(timeframe, max_tf)
        client = await rt.client(SCOPES_BASE + ["storage:events:read", "storage:buckets:read"])
        result = await queries.list_problems(client, additionalFilter, status, timeframe)
        if not result or not result.records:
            return "No problems found"

        resp = f"Found {len(result.records)} problems! Displaying the top {maxProblemsToDisplay} problems:\n"
        for p in result.records[:maxProblemsToDisplay]:
            if p:
                resp += (
                    f"Problem {p.get('display_id')} (please refer to this problem with `problemId` or `event.id` {p.get('problem_id')}) "
                    f"with event.status {p.get('event.status')}, event.category {p.get('event.category')}: {p.get('event.name')} - "
                    f"affects {p.get('affected_users_count')} users and {p.get('affected_entities_count')} entities "
                    f"for a duration of {p.get('duration')}s\n"
                )
        resp += (
            "\nNext Steps:"
            f'\n1. Run the following query in a Dynatrace notebook to get more details about a specific problem:\n'
            f'"fetch dt.davis.problems, from: now()-{timeframe}, to: now() | filter event.id == \\"<problem-id>\\" | fields event.description, '
            "event.status, event.category, event.start, event.end, root_cause_entity_id, root_cause_entity_name, duration, "
            "affected_entities_count, event_count, affected_users_count, problem_id, dt.davis.mute.status, dt.davis.mute.user, "
            "entity_tags, labels.alerting_profile, maintenance.is_under_maintenance, host.name, k8s.cluster.name, k8s.namespace.name, "
            'k8s.workload.name"'
            f"\n2. Tell the user to visit {dt_env}/ui/apps/dynatrace.davis.problems/problem/<problem-id> for more details."
        )
        return resp

    # ------------------------------------------------------------------ entities

    @mcp.tool(
        name="find_entity_by_name",
        title="Find Entity By Name",
        description="Find the entityId and type of a monitored entity (service, host, process-group, application, kubernetes-node, custom-app, ...) "
        "within the topology on Dynatrace, based on the name of the entity. Run this before querying data like logs, metrics, problems, events. "
        "If no entity name is known, make an educated guess with common identifiers like package.json `id`/`name`, helm chart names, "
        "kubernetes manifest names, and alike.",
        annotations=ToolAnnotations(read_only_hint=True),
    )
    @guarded
    async def find_entity_by_name(
        entityNames: Annotated[
            list[str],
            Field(description="Names of the entities to search for - try with one name at first, and only try with multiple names if the first search was unsuccessful"),
        ],
        maxEntitiesToDisplay: Annotated[int, Field(description="Maximum number of entities to display in the response.")] = 10,
        extendedSearch: Annotated[bool, Field(description="Set this to true for a comprehensive search over all available entity types.")] = False,
    ) -> str:
        client = await rt.client(SCOPES_BASE + ["storage:entities:read", "storage:smartscape:read"])

        smartscape = await queries.find_entity_via_smartscape(client, entityNames)
        if smartscape and smartscape.records:
            valid = [e for e in smartscape.records if e and e.get("id") and e.get("type") and e.get("name")]
            shown = valid[:maxEntitiesToDisplay]
            resp = f"Found {len(valid)} monitored entities via Smartscape! Displaying the first {len(shown)} valid entities:\n"
            for e in shown:
                tags = json.dumps(e["tags"]) if e.get("tags") else "none"
                resp += (
                    f"- Entity '{e['name']}' of entity-type '{e['type']}' has entity id '{e['id']}' and tags {tags} - "
                    f"DQL Filter: '| filter dt.smartscape.{str(e['type']).lower()} == toSmartscapeId(\"{e['id']}\")'\n"
                )
            resp += (
                "\n\n**Next Steps:**\n"
                "1. Perform a sanity check that found entities are actually the ones you are looking for (name, type, technology).\n"
                "2. Find out whether any problems exist for this entity using the `list_problems` or `list_vulnerabilities` tool, and the provided DQL-Filter\n"
                '3. In Dynatrace, explore relationships with: "smartscapeEdges \\"*\\" | filter source_id == toSmartscapeId(<entity-id>) or target_id == toSmartscapeId(<entity-id>)"\n'
            )
            return resp

        result = await queries.find_entities_by_name(client, entityNames, extendedSearch)
        if not result or not result.records:
            return "No monitored entity found with the specified name. Try to broaden your search term or check for typos."

        valid = [e for e in result.records if e and e.get("id") and e.get("entity.type") and e.get("entity.name")]
        shown = valid[:maxEntitiesToDisplay]
        resp = f"Found {len(valid)} monitored entities! Displaying the first {len(shown)} entities:\n"
        for e in shown:
            entity_type = get_entity_type_from_id(str(e["id"]))
            resp += (
                f"- Entity '{e['entity.name']}' of entity-type '{e['entity.type']}' has entity id '{e['id']}' and tags "
                f"{e.get('tags') or 'none'} - DQL Filter: '| filter {entity_type} == \"{e['id']}\"'\n"
            )
        resp += (
            "\n\n**Next Steps:**\n"
            "1. Perform a sanity check that found entities are actually the ones you are looking for.\n"
            "2. Find out whether any problems exist for this entity using the `list_problems` or `list_vulnerabilities` tool, and the provided DQL-Filter\n"
        )
        return resp

    # ------------------------------------------------------------------ DQL

    @mcp.tool(
        name="verify_dql",
        title="Verify DQL",
        description="Syntactically verify a Dynatrace Query Language (DQL) statement on Dynatrace GRAIL without executing it.",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    @guarded
    async def verify_dql(dqlStatement: str) -> str:
        client = await rt.client(SCOPES_BASE)
        response = await verify_dql_statement(client, dqlStatement)
        resp = "DQL Statement Verification:\n"
        notes = response.get("notifications") or []
        if notes:
            resp += "Please consider the following notifications for adapting your DQL statement:\n"
            resp += "".join(f"* {n.get('severity')}: {n.get('message')}\n" for n in notes)
        if response.get("valid"):
            resp += "The DQL statement is valid.\n"
        else:
            resp += "The DQL statement is invalid. Please adapt your statement.\n"
        return resp

    # ------------------------------------------------------------------ exceptions

    @mcp.tool(
        name="list_exceptions",
        title="List Exceptions",
        description="List all exceptions known on Dynatrace starting with the most recent.",
        annotations=ToolAnnotations(read_only_hint=True),
    )
    @guarded
    async def list_exceptions(
        timeframe: Annotated[str, Field(description=f'Timeframe to query (e.g., "12h", "24h", "7d", "30d", "30m"). Maximum: "{max_tf}". Default: "24h".')] = "24h",
        additionalFilter: Annotated[
            str | None,
            Field(
                description="Additional DQL filter for user.events, e.g. 'error.id == \"<error.id>\"', "
                "'dt.rum.application.id == \"<id>\"', 'dt.rum.application.entity == \"<entity>\"' or 'os.name == \"<os.name>\"'."
            ),
        ] = None,
        maxExceptionsToDisplay: Annotated[int, Field(description="Maximum number of exceptions to display in the response.")] = 10,
    ) -> str:
        check_timeframe_limit(timeframe, max_tf)
        client = await rt.client(SCOPES_BASE + ["storage:user.events:read", "storage:buckets:read"])
        result = await queries.list_exceptions(client, additionalFilter, timeframe, maxExceptionsToDisplay)
        if not result or not result.records:
            return "No exceptions found"

        resp = f"Found {len(result.records)} exceptions! Displaying the top {maxExceptionsToDisplay} exceptions:\n"
        for x in result.records[:maxExceptionsToDisplay]:
            if x:
                resp += (
                    f"At start_time {x.get('start_time')} the exception with error.type {x.get('error.type')}, "
                    f"error.id {x.get('error.id')} and os.name {x.get('os.name')} happened for dt.rum.application.id "
                    f"{x.get('dt.rum.application.id')} with dt.rum.application.entity {x.get('dt.rum.application.entity')}.\n"
                    f"The exception.message is {x.get('exception.message')}\n\n"
                )
        resp += (
            "\nNext Steps:"
            '\n1. Run in a Dynatrace notebook: "fetch user.events, from: now()-<timeframe>, to: now() | filter error.id == toUid(\\"<error.id>\\")" '
            "to get all occurrences with stack traces (exception.stack_trace) of this exception."
            f"\n2. Tell the user to visit {dt_env}/ui/apps/dynatrace.error.inspector/explorer?tf=now-<timeframe>%3Bnow&perspective=impact"
            "&detailsId=<error.id>&sidebarOpen=false&expandedSections=details&tab=occurrence&group=occurrences for more details."
        )
        return resp

    # ------------------------------------------------------------------ deployments

    @mcp.tool(
        name="list_deployments",
        title="List Deployments",
        description="List deployment events (releases, version changes) known on Dynatrace, newest first. "
        "Use it to answer 'what changed?', e.g. before a problem started.",
        annotations=ToolAnnotations(read_only_hint=True),
    )
    @guarded
    async def list_deployments(
        timeframe: Annotated[str, Field(description=f'Timeframe to query (e.g., "2h", "24h", "7d"). Maximum: "{max_tf}". Default: "24h".')] = "24h",
        entityId: Annotated[
            str | None,
            Field(description='Only deployments affecting this entity, e.g. "SERVICE-1A2B3C4D5E6F7A8B". Get it with find_entity_by_name.'),
        ] = None,
        additionalFilter: Annotated[
            str | None,
            Field(description="Additional DQL filter for the deployment events, e.g. 'event.status == \"CLOSED\"'"),
        ] = None,
        maxDeploymentsToDisplay: Annotated[int, Field(ge=1, le=50, description="Maximum number of deployments to display.")] = 10,
    ) -> str:
        check_timeframe_limit(timeframe, max_tf)
        client = await rt.client(SCOPES_BASE + ["storage:events:read", "storage:buckets:read"])
        result = await queries.list_deployments(client, timeframe, entityId, additionalFilter, maxDeploymentsToDisplay)
        if not result or not result.records:
            scope = f" for {entityId}" if entityId else ""
            return f"No deployment events found{scope} in the last {timeframe}."

        resp = f"Found {len(result.records)} deployment events in the last {timeframe} (newest first):\n"
        for d in result.records[:maxDeploymentsToDisplay]:
            resp += (
                f"- {d.get('timestamp')} | {d.get('event.type')} | {d.get('event.name') or 'unnamed'}\n"
                f"  {_fields(d, skip=('timestamp', 'event.type', 'event.name'))}\n"
            )
        resp += (
            "\nNext Steps:\n1. Compare the deployment times with problem start times from `list_problems` (same entity filter).\n"
            "2. Use `get_service_health` with and without `compareToPreviousDay` to see whether a deployment changed response time or error rate.\n"
        )
        return resp

    # ------------------------------------------------------------------ entity details

    @mcp.tool(
        name="get_entity_details",
        title="Get Entity Details",
        description="Get the properties and relationships (calls, runs on, belongs to, ...) of one monitored entity by its ID. "
        "Call find_entity_by_name first to get the ID.",
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
    )
    @guarded
    async def get_entity_details(
        entityId: Annotated[str, Field(description='Entity ID, e.g. "SERVICE-1A2B3C4D5E6F7A8B" or "HOST-0123456789ABCDEF".')],
        maxRelationshipsToDisplay: Annotated[int, Field(ge=1, le=200, description="Maximum number of relationships to display.")] = 50,
    ) -> str:
        client = await rt.client(SCOPES_BASE + ["storage:entities:read", "storage:smartscape:read"])
        details = await queries.get_entity_details(client, entityId)
        entity = details["entity"]
        if not entity:
            return f"No entity found with ID {entityId}. Check the ID with find_entity_by_name."

        resp = f"Entity {entityId} (source: {details['source']}):\n{_fields(entity)}\n"
        relationships = details["relationships"]
        if relationships:
            shown = relationships[:maxRelationshipsToDisplay]
            resp += f"\nRelationships ({len(relationships)}, showing {len(shown)}):\n"
            for r in shown:
                resp += (
                    f"- {r.get('type') or 'related'}: {r.get('source_type')} {r.get('source_id')} "
                    f"-> {r.get('target_type')} {r.get('target_id')}\n"
                )
        elif details["source"] == "classic":
            resp += "\nRelationships are only available when Smartscape is enabled in this environment.\n"
        else:
            resp += "\nNo relationships found.\n"
        resp += (
            "\nNext Steps:\n1. Use `list_problems` or `list_vulnerabilities` with a filter on this entity.\n"
            "2. For a service, use `get_service_health` and `list_deployments` with this ID.\n"
        )
        return resp

    # ------------------------------------------------------------------ service health

    @mcp.tool(
        name="get_service_health",
        title="Get Service Health",
        description="Get response time, request count, failures and error rate of one service over a timeframe, "
        "optionally compared with the same window one day earlier.",
        annotations=ToolAnnotations(read_only_hint=True),
    )
    @guarded
    async def get_service_health(
        serviceId: Annotated[str, Field(description='Service entity ID, e.g. "SERVICE-1A2B3C4D5E6F7A8B". Get it with find_entity_by_name.')],
        timeframe: Annotated[str, Field(description=f'Timeframe to analyse (e.g., "30m", "2h", "24h"). Maximum: "{max_tf}". Default: "2h".')] = "2h",
        compareToPreviousDay: Annotated[bool, Field(description="Also query the same window one day earlier and show the change.")] = True,
    ) -> str:
        check_timeframe_limit(timeframe, max_tf)
        client = await rt.client(SCOPES_BASE + ["storage:metrics:read"])
        now = await queries.get_service_health(client, serviceId, timeframe)
        if not now:
            return (
                f"No request metrics found for {serviceId} in the last {timeframe}. The service may have had no traffic, "
                "or the ID is not a monitored service."
            )
        before = await queries.get_service_health(client, serviceId, timeframe, days_ago=1) if compareToPreviousDay else None

        rows = [
            ("Avg response time", "avg_response_time_ms", " ms"),
            ("Peak response time (interval avg)", "peak_response_time_ms", " ms"),
            ("Requests", "requests", ""),
            ("Failures", "failures", ""),
            ("Error rate", "error_rate_pct", " %"),
        ]
        digits = {"requests": 0, "failures": 0, "error_rate_pct": 2}
        resp = f"Service health for {serviceId}, last {timeframe}:\n\n"
        if before:
            resp += "| Metric | Now | Same window 1 day earlier | Change |\n|---|---|---|---|\n"
            for label, key, unit in rows:
                d = digits.get(key, 1)
                resp += f"| {label} | {_fmt(now[key], unit, d)} | {_fmt(before[key], unit, d)} | {_change(now[key], before[key])} |\n"
        else:
            resp += "| Metric | Value |\n|---|---|\n"
            for label, key, unit in rows:
                resp += f"| {label} | {_fmt(now[key], unit, digits.get(key, 1))} |\n"
            if compareToPreviousDay:
                resp += "\n(No data for the same window one day earlier.)\n"
        resp += (
            "\nNext Steps:\n1. If response time or error rate went up, check `list_deployments` and `list_problems` for this service.\n"
        )
        return resp

    return mcp


# =============================================================================
# Startup
# =============================================================================

def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        log(f"⚠️ {name}={raw!r} is not a number, using {default}")
        return default


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="dynatrace-mcp-python", description="Dynatrace Model Context Protocol (MCP) Server")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--http", action="store_true", help="enable HTTP server mode instead of stdio")
    p.add_argument("--server", action="store_true", help="enable HTTP server mode (alias for --http)")
    p.add_argument("-p", "--port", type=int, default=_env_int("MCP_PORT", 3000), help="port for HTTP server (default: $MCP_PORT or 3000)")
    p.add_argument(
        "-H", "--host", default=os.environ.get("MCP_HOST") or "127.0.0.1", help="bind address for HTTP server (default: $MCP_HOST or 127.0.0.1)"
    )
    p.add_argument("--oauth-redirect-port", type=int, default=None, help="fixed port for the OAuth browser-login redirect server (stdio only)")
    args, _unknown = p.parse_known_args(argv)  # tolerate extra args injected by MCP clients
    return args


async def check_connection(rt: Runtime) -> None:
    """Two-step connection test. Exits with 3 (network) or 2 (auth) on failure."""
    dt_env = rt.dt_environment
    if "abc12345" in dt_env:
        log(f"⚠️ Demo configuration detected ({dt_env}). Skipping connection tests.")
        return

    log(f"Testing connection to Dynatrace environment: {dt_env}...")
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as http:
            text = (await http.get(dt_env)).text
        if not text:
            raise RuntimeError("No response received")
        if "Authentication required" not in text:
            log(f"⚠️ Tried to contact {dt_env}, got the following response: {text[:500]}")
    except Exception as e:
        log(f"❌ Failed to connect to Dynatrace environment {dt_env}: {e}")
        sys.exit(3)

    try:
        client = await rt.client(SCOPES_BASE)
        await client.get("/platform/management/v1/environment")
        log(f"✅ Successfully connected to the Dynatrace environment at {dt_env}.")
    except Exception as e:
        log(f"❌ Failed to connect to Dynatrace environment {dt_env}: {e}")
        sys.exit(2)


def _describe_dynatrace_auth(env: DynatraceEnv) -> str:
    if env.dt_platform_token:
        return "platform token (DT_PLATFORM_TOKEN)"
    if env.oauth_client_id and env.oauth_client_secret:
        return f"OAuth client credentials ({env.oauth_client_id})"
    return "OAuth browser login (authorization code + PKCE)"


def _describe_client_auth(sec: SecuritySettings) -> str:
    if sec.auth_mode == "entra":
        clients = f", allowed clients: {', '.join(sec.entra_allowed_client_ids)}" if sec.entra_allowed_client_ids else ""
        return f"Microsoft Entra ID (tenant {sec.entra_tenant_id}, audience {', '.join(sec.entra_audiences)}{clients})"
    if sec.auth_mode == "bearer":
        return f"static bearer token (roles: {', '.join(sec.bearer_roles)})"
    return f"none - local stdio process (roles: {', '.join(sec.stdio_roles)})"


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    http_mode = bool(args.http or args.server)
    log(f"Initializing Dynatrace MCP Server (Python) v{__version__}...")

    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY")
    if proxy:
        log(f"Using proxy from environment: {proxy} (NO_PROXY is honored)")

    try:
        env = get_dynatrace_env()
        security = get_security_settings(http_mode=http_mode)
    except ValueError as e:
        log(f"❌ Configuration error: {e}")
        sys.exit(1)

    if not env.oauth_client_id and not env.oauth_client_secret and not env.dt_platform_token:
        if http_mode:
            log(
                "❌ HTTP mode needs non-interactive Dynatrace credentials: set DT_PLATFORM_TOKEN, or "
                "OAUTH_CLIENT_ID + OAUTH_CLIENT_SECRET. The browser login only works for a local stdio server."
            )
            sys.exit(1)
        log("No OAuth credentials or platform token provided - switching to OAuth authorization code flow.")
        env.oauth_client_id = DT_MCP_AUTH_CODE_FLOW_OAUTH_CLIENT_ID
    elif http_mode and env.uses_auth_code_flow:
        log("❌ HTTP mode cannot use the browser login: set OAUTH_CLIENT_SECRET together with OAUTH_CLIENT_ID, or DT_PLATFORM_TOKEN.")
        sys.exit(1)

    rt = Runtime(env, args.oauth_redirect_port, security)
    log(f"Dynatrace authentication: {_describe_dynatrace_auth(env)}")
    log(f"Client authentication: {_describe_client_auth(security)}")
    max_poll = env.dql_max_poll_seconds or (DEFAULT_HTTP_MAX_POLL_SECONDS if http_mode else DEFAULT_MAX_POLL_SECONDS)
    set_max_poll_seconds(max_poll)
    log(f"DQL queries are cancelled after {max_poll:g}s (DQL_MAX_POLL_SECONDS)")
    log(f"Longest accepted query timeframe: {env.max_query_timeframe} (MAX_QUERY_TIMEFRAME)")
    if http_mode:
        if security.upstream_secret:
            log(f"Gateway check: every request except /health must carry the {security.upstream_secret_header} header (MCP_UPSTREAM_SECRET)")
        else:
            log("⚠️ MCP_UPSTREAM_SECRET is not set: callers that reach this container directly bypass the gateway's rate limits.")
        log(f"Trusted proxies for X-Forwarded-* headers (MCP_FORWARDED_ALLOW_IPS): {security.forwarded_allow_ips}")
    if security.tool_roles_override:
        log(f"Tool role overrides (MCP_TOOL_ROLES): {json.dumps(security.tool_roles_override)}")

    asyncio.run(check_connection(rt))

    log(f"Starting Dynatrace MCP Server (Python) v{__version__}...")
    mcp = build_server(rt)

    if http_mode:
        import uvicorn

        from .http_app import allowed_hosts_for, build_http_app

        app = build_http_app(mcp, security, rt.policy, args.host, args.port)
        log(f"Allowed Host headers: {', '.join(allowed_hosts_for(args.host, args.port, security.allowed_hosts))}")
        if security.public_url:
            log(f"Public URL (protected-resource metadata): {security.public_url}")
        log(f"Dynatrace MCP Server running on HTTP at http://{args.host}:{args.port}/mcp")
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning", limit_concurrency=100, proxy_headers=True, forwarded_allow_ips=security.forwarded_allow_ips)
    else:
        log("Dynatrace MCP Server running on stdio")
        mcp.run("stdio")


if __name__ == "__main__":
    main()
