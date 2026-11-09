"""Fixed DQL queries: problems, vulnerabilities, exceptions, deployments, entities, service health."""

from __future__ import annotations

import sys

from ..client import DynatraceClient
from ..utils.dql_sanitize import (
    escape_dql_string_value,
    validate_additional_filter,
    validate_entity_id,
    validate_timeframe,
)
from ..utils.entity_types import DYNATRACE_ENTITY_TYPES_ALL, DYNATRACE_ENTITY_TYPES_BASICS, get_entity_type_from_id
from .execute_dql import DqlExecutionResult, execute_dql

FIVE_MB = 5_000_000


def _filter_clause(additional_filter: str | None) -> str:
    return f"| filter {additional_filter}" if additional_filter else ""


# ------------------------------------------------------------------ problems


async def list_problems(
    client: DynatraceClient, additional_filter: str | None = None, status: str | None = None, timeframe: str = "24h"
) -> DqlExecutionResult | None:
    validate_timeframe(timeframe)
    if additional_filter:
        validate_additional_filter(additional_filter)

    status_filter = {
        "ACTIVE": "| filter isNull(event.end)",
        "CLOSED": "| filter not(isNull(event.end))",
    }.get(status or "ALL", "")

    dql = f"""fetch dt.davis.problems, from: now()-{timeframe}, to: now()
| filter isNull(dt.davis.is_duplicate) OR not(dt.davis.is_duplicate)
{status_filter}
{_filter_clause(additional_filter)}
| fieldsAdd
   duration = (coalesce(event.end, now()) - event.start)/1000000000,
   affected_entities_count = arraySize(affected_entity_ids),
   event_count = arraySize(dt.davis.event_ids),
   affected_users_count = dt.davis.affected_users_count,
   problem_id = event.id
| fields display_id, event.name, event.description, event.status, event.category, event.start, event.end,
         root_cause_entity_id, root_cause_entity_name, duration, affected_entities_count,
         event_count, affected_users_count, problem_id, dt.davis.mute.status, dt.davis.mute.user,
         entity_tags, labels.alerting_profile, maintenance.is_under_maintenance,
         aws.account.id, azure.resource.group, azure.subscription, cloud.provider, cloud.region,
         dt.cost.costcenter, dt.cost.product, dt.host_group.id, dt.security_context, gcp.project.id,
         host.name,
         k8s.cluster.name, k8s.cluster.uid, k8s.container.name, k8s.namespace.name, k8s.node.name, k8s.pod.name, k8s.service.name, k8s.workload.kind, k8s.workload.name
| sort event.start desc
"""
    return await execute_dql(client, dql, max_result_records=5000, max_result_bytes=FIVE_MB)


# ------------------------------------------------------------------ vulnerabilities


async def list_vulnerabilities(
    client: DynatraceClient,
    additional_filter: str | None = None,
    risk_score: float | None = None,
    timeframe: str = "30d",
) -> list[str]:
    validate_timeframe(timeframe)
    if additional_filter:
        validate_additional_filter(additional_filter)
    min_score = float(risk_score) if risk_score else 8.0

    dql = f"""fetch security.events, from: now()-{timeframe}, to: now()
    | filter dt.system.bucket=="default_securityevents_builtin"
        AND event.provider=="Dynatrace"
        AND event.type=="VULNERABILITY_STATE_REPORT_EVENT"
        AND event.level=="ENTITY"
    // filter for the latest snapshot per entity
    | dedup {{vulnerability.display_id, affected_entity.id}}, sort:{{timestamp desc}}
    // filter for open non-muted vulnerabilities with minimum risk score
    | filter vulnerability.resolution.status=="OPEN"
        AND vulnerability.risk.score >= {min_score}
    {_filter_clause(additional_filter)}
    | sort vulnerability.risk.score desc
    | limit 100"""

    response = await execute_dql(client, dql, max_result_records=5000, max_result_bytes=FIVE_MB)
    if not response or not response.records:
        return []

    def g(v: dict, key: str, default: str = "N/A") -> object:
        return v.get(key) or default

    return [
        f"{g(v, 'vulnerability.title', 'Unknown')} (Vulnerability ID: {g(v, 'vulnerability.id')}, "
        f"Vulnerability Display ID: {g(v, 'vulnerability.display_id')}, Risk Score: {g(v, 'vulnerability.risk.score')}, "
        f"Risk Level: {g(v, 'vulnerability.risk.level')}, Affected Entity: {g(v, 'affected_entity.name')}, "
        f"External Vulnerability ID: {g(v, 'vulnerability.external_id')}, CVE: {g(v, 'vulnerability.references.cve')}, "
        f"Mute Status: {g(v, 'vulnerability.mute.status')}, Parent Mute Status: {g(v, 'vulnerability.parent.mute.status')}, "
        f"Full Details: {g(v, 'vulnerability.url')})"
        for v in response.records
    ]


# ------------------------------------------------------------------ exceptions


async def list_exceptions(
    client: DynatraceClient,
    additional_filter: str | None = None,
    timeframe: str = "24h",
    max_result_records: int = 5000,
) -> DqlExecutionResult | None:
    validate_timeframe(timeframe)
    if additional_filter:
        validate_additional_filter(additional_filter)

    dql = f"""fetch user.events, from: now()-{timeframe}, to: now()
| filter isNotNull(exception.stack_trace)
| filter isNotNull(error.id)
{_filter_clause(additional_filter)}
| fields error.id, error.type, exception.message, os.name, dt.rum.application.id, dt.rum.application.entity, start_time
| sort start_time desc
"""
    return await execute_dql(client, dql, max_result_records=max_result_records, max_result_bytes=FIVE_MB)


# ------------------------------------------------------------------ entity search


def generate_dql_search_entity_command(entity_names: list[str], extended_search: bool) -> str:
    if not entity_names:
        raise ValueError("No entity names supplied to search for")
    names = [escape_dql_string_value(n) for n in entity_names]
    search = '"*' + '*" OR "*'.join(names) + '*"'
    types = DYNATRACE_ENTITY_TYPES_ALL if extended_search else DYNATRACE_ENTITY_TYPES_BASICS

    parts = []
    for i, entity_type in enumerate(types):
        dql = f"fetch {entity_type} | search {search} | fieldsAdd entity.type | expand tags"
        parts.append(dql if i == 0 else f"  | append [ {dql} ]\n")
    return "".join(parts)


async def find_entity_via_smartscape(client: DynatraceClient, entity_names: list[str]) -> DqlExecutionResult | None:
    names = [escape_dql_string_value(n) for n in entity_names]
    dql = 'smartscapeNodes "*" | search "*' + '*" OR "*'.join(names) + '*" | fields id, name, type'
    print(f"Executing DQL: {dql}", file=sys.stderr)
    try:
        result = await execute_dql(client, dql)
        if result and result.records:
            return result
    except Exception as e:  # smartscapeNodes may not be available in every environment
        print(f"Error while querying smartscapeNodes: {e}", file=sys.stderr)
    print("No results from smartscapeNodes", file=sys.stderr)
    return None


async def find_entities_by_name(
    client: DynatraceClient, entity_names: list[str], extended_search: bool
) -> DqlExecutionResult | None:
    return await execute_dql(client, generate_dql_search_entity_command(entity_names, extended_search))


# ------------------------------------------------------------------ deployments


def build_deployments_query(
    timeframe: str, entity_id: str | None = None, additional_filter: str | None = None, limit: int = 50
) -> str:
    validate_timeframe(timeframe)
    if entity_id:
        validate_entity_id(entity_id)
    if additional_filter:
        validate_additional_filter(additional_filter)

    # The stored event.type of deployment events differs between ingest paths (Events API, SDLC
    # events, OneAgent-detected changes), so match any type that mentions "deployment".
    dql = f"""fetch events, from: now()-{timeframe}, to: now()
| filter contains(lower(event.type), "deployment")
"""
    if entity_id:
        eid = escape_dql_string_value(entity_id)
        dql += f'| filter in("{eid}", affected_entity_ids) or dt.source_entity == "{eid}"\n'
    dql += _filter_clause(additional_filter) + "\n" if additional_filter else ""
    dql += f"| sort timestamp desc\n| limit {int(limit)}\n"
    return dql


async def list_deployments(
    client: DynatraceClient,
    timeframe: str = "24h",
    entity_id: str | None = None,
    additional_filter: str | None = None,
    limit: int = 50,
) -> DqlExecutionResult | None:
    dql = build_deployments_query(timeframe, entity_id, additional_filter, limit)
    return await execute_dql(client, dql, max_result_records=limit, max_result_bytes=FIVE_MB)


# ------------------------------------------------------------------ entity details


async def get_entity_details(client: DynatraceClient, entity_id: str) -> dict[str, object]:
    """Look up one entity and its relationships.

    Uses Smartscape (node + edges) when available, otherwise the classic entity table.
    Returns {"source": "smartscape"|"classic"|None, "entity": dict|None, "relationships": list}.
    """
    validate_entity_id(entity_id)
    eid = escape_dql_string_value(entity_id)

    try:
        node = await execute_dql(
            client, f'smartscapeNodes "*" | filter id == toSmartscapeId("{eid}") | limit 1', max_result_bytes=FIVE_MB
        )
        if node and node.records:
            edges = await execute_dql(
                client,
                f'smartscapeEdges "*" | filter source_id == toSmartscapeId("{eid}") '
                f'or target_id == toSmartscapeId("{eid}") | limit 200',
                max_result_records=200,
                max_result_bytes=FIVE_MB,
            )
            return {"source": "smartscape", "entity": node.records[0], "relationships": edges.records if edges else []}
    except Exception as e:  # smartscape may not be available in every environment
        print(f"Smartscape lookup for {entity_id} failed, falling back to classic entities: {e}", file=sys.stderr)

    entity_type = get_entity_type_from_id(entity_id)
    if not entity_type:
        return {"source": None, "entity": None, "relationships": []}
    classic = await execute_dql(
        client, f'fetch {entity_type} | filter id == "{eid}" | fieldsAdd tags | limit 1', max_result_bytes=FIVE_MB
    )
    if classic and classic.records:
        return {"source": "classic", "entity": classic.records[0], "relationships": []}
    return {"source": None, "entity": None, "relationships": []}


# ------------------------------------------------------------------ service health


def build_service_health_query(service_id: str, timeframe: str, days_ago: int = 0) -> str:
    """Response time, request and failure counts of one service, for the last `timeframe`
    (or the same window `days_ago` days earlier)."""
    validate_entity_id(service_id, expected_prefix="SERVICE")
    validate_timeframe(timeframe)
    sid = escape_dql_string_value(service_id)
    shift = f"-{int(days_ago)}d" if days_ago else ""
    return (
        "timeseries { response_time = avg(dt.service.request.response_time), "
        "requests = sum(dt.service.request.count), failures = sum(dt.service.request.failure_count) }, "
        f"from: now(){shift}-{timeframe}, to: now(){shift}, "
        f'filter: dt.entity.service == "{sid}"'
    )


def summarize_service_health(record: dict | None) -> dict[str, float | None] | None:
    """Collapse the timeseries arrays into totals. Response time is in microseconds in Grail."""
    if not record:
        return None
    rt = record.get("response_time") or []
    req = record.get("requests") or []
    fail = record.get("failures") or []

    total_requests = sum(v for v in req if v is not None)
    total_failures = sum(v for v in fail if v is not None)
    # Average response time weighted by requests per interval (an average of averages would
    # over-weight quiet intervals); fall back to a plain mean if counts are missing.
    pairs = [(r, n) for r, n in zip(rt, req) if r is not None and n]
    if pairs:
        avg_rt = sum(r * n for r, n in pairs) / sum(n for _, n in pairs)
    else:
        values = [r for r in rt if r is not None]
        avg_rt = sum(values) / len(values) if values else None
    peak_rt = max((r for r in rt if r is not None), default=None)

    if not total_requests and avg_rt is None:
        return None
    return {
        "avg_response_time_ms": avg_rt / 1000 if avg_rt is not None else None,
        "peak_response_time_ms": peak_rt / 1000 if peak_rt is not None else None,
        "requests": total_requests,
        "failures": total_failures,
        "error_rate_pct": (total_failures / total_requests * 100) if total_requests else None,
    }


async def get_service_health(
    client: DynatraceClient, service_id: str, timeframe: str = "2h", days_ago: int = 0
) -> dict[str, float | None] | None:
    result = await execute_dql(client, build_service_health_query(service_id, timeframe, days_ago))
    return summarize_service_health(result.records[0] if result and result.records else None)
