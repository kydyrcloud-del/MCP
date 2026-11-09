"""End-to-end tool calls through a real MCP client, with the Dynatrace API mocked by respx."""

import json

import httpx
import pytest
import respx
from mcp import Client, types

from dynatrace_mcp.capabilities import execute_dql as dql_module
from dynatrace_mcp.config import get_dynatrace_env
from dynatrace_mcp.server import Runtime, build_server

ENV = "https://abc12345.apps.dynatrace.com"


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(dql_module, "POLL_INTERVAL_S", 0)


def make_server(**env_overrides):
    env = get_dynatrace_env({"DT_ENVIRONMENT": ENV, "DT_PLATFORM_TOKEN": "dt0s16.TEST", **env_overrides})
    return build_server(Runtime(env, None))


def text(result: types.CallToolResult) -> str:
    return "".join(c.text for c in result.content if isinstance(c, types.TextContent))


def grail_result(records, scanned=1_000_000):
    return {"records": records, "types": [], "metadata": {"grail": {"scannedBytes": scanned, "scannedRecords": 42}}}


@respx.mock
async def test_list_problems_builds_safe_query():
    route = respx.post(f"{ENV}/platform/storage/query/v1/query:execute").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": grail_result(
                    [{"display_id": "P-1", "problem_id": "abc", "event.name": "CPU saturation", "event.status": "ACTIVE"}]
                )
            },
        )
    )
    async with Client(make_server(), mode="legacy") as client:
        ok = await client.call_tool("list_problems", {"status": "ACTIVE", "timeframe": "2h"})
        bad = await client.call_tool("list_problems", {"timeframe": "2h | fetch logs"})

    assert "Problem P-1" in text(ok) and "CPU saturation" in text(ok)
    query = json.loads(route.calls[0].request.content)["query"]
    assert "from: now()-2h" in query and "filter isNull(event.end)" in query
    assert bad.is_error and "Invalid timeframe" in text(bad)
    assert route.call_count == 1  # the injected query was never sent


@respx.mock
async def test_timeframe_longer_than_maximum_is_rejected():
    route = respx.post(f"{ENV}/platform/storage/query/v1/query:execute").mock(
        return_value=httpx.Response(200, json={"result": grail_result([])})
    )
    async with Client(make_server(MAX_QUERY_TIMEFRAME="7d"), mode="legacy") as client:
        for tool, extra in (
            ("list_problems", {}),
            ("list_vulnerabilities", {}),
            ("list_exceptions", {}),
            ("list_deployments", {}),
            ("get_service_health", {"serviceId": "SERVICE-ABC"}),
        ):
            result = await client.call_tool(tool, {"timeframe": "8d", **extra})
            assert result.is_error and "allowed maximum of 7d" in text(result), tool
        ok = await client.call_tool("list_problems", {"timeframe": "7d"})
    assert not ok.is_error
    assert route.call_count == 1  # only the allowed query reached Dynatrace


@respx.mock
async def test_api_errors_are_reported_as_tool_errors():
    respx.post(f"{ENV}/platform/storage/query/v1/query:verify").mock(
        return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}})
    )
    async with Client(make_server(), mode="legacy") as client:
        result = await client.call_tool("verify_dql", {"dqlStatement": "fetch logs"})
    assert result.is_error
    assert "HTTP status: 403" in text(result) and "lacking the necessary permissions" in text(result)


@respx.mock
async def test_no_rate_limit_in_server():
    """Rate limiting is done by the gateway (APIM), not by the server."""
    respx.post(f"{ENV}/platform/storage/query/v1/query:verify").mock(return_value=httpx.Response(200, json={"valid": True}))
    async with Client(make_server(), mode="legacy") as client:
        results = [await client.call_tool("verify_dql", {"dqlStatement": "fetch logs"}) for _ in range(10)]
    assert not any(r.is_error for r in results)



def queries_sent(route) -> list[str]:
    return [json.loads(c.request.content)["query"] for c in route.calls]


@respx.mock
async def test_list_deployments():
    route = respx.post(f"{ENV}/platform/storage/query/v1/query:execute").mock(
        return_value=httpx.Response(
            200,
            json={
                "result": grail_result(
                    [
                        {
                            "timestamp": "2026-11-09T10:00:00Z",
                            "event.type": "CUSTOM_DEPLOYMENT",
                            "event.name": "checkout v1.4.2",
                            "dt.source_entity": "SERVICE-ABC",
                            "empty": None,
                        }
                    ]
                )
            },
        )
    )
    async with Client(make_server(), mode="legacy") as client:
        ok = await client.call_tool("list_deployments", {"timeframe": "6h", "entityId": "SERVICE-ABC"})
        bad = await client.call_tool("list_deployments", {"entityId": 'SERVICE-ABC") or true or ("'})

    assert not ok.is_error, text(ok)
    assert "checkout v1.4.2" in text(ok) and "dt.source_entity=SERVICE-ABC" in text(ok)
    assert "empty=" not in text(ok)  # empty fields are left out
    query = queries_sent(route)[0]
    assert "from: now()-6h" in query and 'contains(lower(event.type), "deployment")' in query
    assert 'in("SERVICE-ABC", affected_entity_ids)' in query
    assert bad.is_error and "Invalid entity ID" in text(bad)
    assert route.call_count == 1  # the malformed ID was never sent


@respx.mock
async def test_get_entity_details_via_smartscape():
    route = respx.post(f"{ENV}/platform/storage/query/v1/query:execute").mock(
        side_effect=[
            httpx.Response(200, json={"result": grail_result([{"id": "n1", "name": "checkout", "type": "SERVICE"}])}),
            httpx.Response(
                200,
                json={
                    "result": grail_result(
                        [{"type": "calls", "source_type": "SERVICE", "source_id": "n1", "target_type": "SERVICE", "target_id": "n2"}]
                    )
                },
            ),
        ]
    )
    async with Client(make_server(), mode="legacy") as client:
        result = await client.call_tool("get_entity_details", {"entityId": "SERVICE-ABC"})

    assert not result.is_error, text(result)
    assert "source: smartscape" in text(result) and "name=checkout" in text(result)
    assert "- calls: SERVICE n1 -> SERVICE n2" in text(result)
    node_q, edge_q = queries_sent(route)
    assert 'smartscapeNodes "*" | filter id == toSmartscapeId("SERVICE-ABC")' in node_q
    assert 'source_id == toSmartscapeId("SERVICE-ABC") or target_id == toSmartscapeId("SERVICE-ABC")' in edge_q


@respx.mock
async def test_get_entity_details_falls_back_to_classic_entities():
    route = respx.post(f"{ENV}/platform/storage/query/v1/query:execute").mock(
        side_effect=[
            httpx.Response(400, json={"error": {"message": "smartscapeNodes is not available"}}),
            httpx.Response(200, json={"result": grail_result([{"id": "HOST-AB12", "entity.name": "web-01"}])}),
        ]
    )
    async with Client(make_server(), mode="legacy") as client:
        result = await client.call_tool("get_entity_details", {"entityId": "HOST-AB12"})

    assert not result.is_error, text(result)
    assert "source: classic" in text(result) and "entity.name=web-01" in text(result)
    assert 'fetch dt.entity.host | filter id == "HOST-AB12"' in queries_sent(route)[1]


def health_series(rt_us, requests, failures):
    return {"result": grail_result([{"response_time": rt_us, "requests": requests, "failures": failures}])}


@respx.mock
async def test_get_service_health_compares_with_previous_day():
    route = respx.post(f"{ENV}/platform/storage/query/v1/query:execute").mock(
        side_effect=[
            # now: 200 ms and 400 ms, 100 + 100 requests, 4 failures -> weighted avg 300 ms, 2 % errors
            httpx.Response(200, json=health_series([200_000, 400_000], [100, 100], [1, 3])),
            # one day earlier: 150 ms, 200 requests, 2 failures -> 1 % errors
            httpx.Response(200, json=health_series([150_000, 150_000], [100, 100], [1, 1])),
        ]
    )
    async with Client(make_server(), mode="legacy") as client:
        result = await client.call_tool("get_service_health", {"serviceId": "SERVICE-ABC", "timeframe": "2h"})

    out = text(result)
    assert not result.is_error, out
    assert "| Avg response time | 300.0 ms | 150.0 ms | +100% |" in out
    assert "| Error rate | 2.00 % | 1.00 % | +100% |" in out
    now_q, before_q = queries_sent(route)
    assert "from: now()-2h, to: now()" in now_q and 'dt.entity.service == "SERVICE-ABC"' in now_q
    assert "from: now()-1d-2h, to: now()-1d" in before_q


async def test_get_service_health_requires_a_service_id():
    async with Client(make_server(), mode="legacy") as client:
        result = await client.call_tool("get_service_health", {"serviceId": "HOST-AB12"})
    assert result.is_error and "is not a SERVICE entity ID" in text(result)
