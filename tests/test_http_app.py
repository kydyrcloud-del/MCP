"""HTTP layer: gateway secret check and the related settings."""

import httpx
import pytest
import respx

from dynatrace_mcp.capabilities import execute_dql as dql_module
from dynatrace_mcp.config import get_dynatrace_env, get_security_settings
from dynatrace_mcp.http_app import build_http_app
from dynatrace_mcp.server import Runtime, build_server

ENV = "https://abc12345.apps.dynatrace.com"
SECRET = "s3cr3t-from-apim-0123456789"
TOKEN = "static-bearer-token-0123456789"


def make_app(**sec_env):
    env = get_dynatrace_env({"DT_ENVIRONMENT": ENV, "DT_PLATFORM_TOKEN": "dt0s16.TEST"})
    security = get_security_settings(
        {"MCP_AUTH_MODE": "bearer", "MCP_BEARER_TOKEN": TOKEN, **sec_env}, http_mode=True
    )
    rt = Runtime(env, None, security)
    return build_http_app(build_server(rt), security, rt.policy, "127.0.0.1", 3000)


def client_for(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:3000")


async def test_health_needs_no_gateway_secret():
    async with client_for(make_app(MCP_UPSTREAM_SECRET=SECRET)) as c:
        r = await c.get("/health")
    assert r.status_code == 200


@pytest.mark.parametrize("headers", [{}, {"x-from-apim": "wrong-secret-value-000000"}])
async def test_requests_without_gateway_secret_are_rejected(headers):
    async with client_for(make_app(MCP_UPSTREAM_SECRET=SECRET)) as c:
        # even a valid bearer token is not enough when the gateway header is missing
        r = await c.post("/mcp", json={}, headers={"Authorization": f"Bearer {TOKEN}", **headers})
    assert r.status_code == 403
    assert "www-authenticate" not in r.headers  # nothing that hints at how to get in


async def test_gateway_secret_passes_through_to_authentication():
    async with client_for(make_app(MCP_UPSTREAM_SECRET=SECRET)) as c:
        r = await c.post("/mcp", json={}, headers={"x-from-apim": SECRET})
    assert r.status_code == 401  # past the gateway check, stopped by the missing bearer token


async def test_custom_gateway_header_name():
    async with client_for(make_app(MCP_UPSTREAM_SECRET=SECRET, MCP_UPSTREAM_SECRET_HEADER="X-Apim-Key")) as c:
        assert (await c.post("/mcp", json={}, headers={"x-from-apim": SECRET})).status_code == 403
        assert (await c.post("/mcp", json={}, headers={"x-apim-key": SECRET})).status_code == 401


async def test_no_gateway_secret_configured_keeps_old_behaviour():
    async with client_for(make_app()) as c:
        r = await c.post("/mcp", json={})
    assert r.status_code == 401


def test_gateway_and_proxy_settings():
    s = get_security_settings({}, http_mode=False)
    assert s.upstream_secret is None
    assert s.upstream_secret_header == "x-from-apim"
    assert s.forwarded_allow_ips == "127.0.0.1"

    s = get_security_settings({"MCP_FORWARDED_ALLOW_IPS": "10.0.0.0/16"}, http_mode=False)
    assert s.forwarded_allow_ips == "10.0.0.0/16"

    with pytest.raises(ValueError, match="at least 16"):
        get_security_settings({"MCP_UPSTREAM_SECRET": "short"}, http_mode=False)
    for bad in ("Authorization", "x from apim"):
        with pytest.raises(ValueError, match="MCP_UPSTREAM_SECRET_HEADER"):
            get_security_settings({"MCP_UPSTREAM_SECRET_HEADER": bad}, http_mode=False)


def test_dql_max_poll_seconds_setting():
    base = {"DT_ENVIRONMENT": ENV}
    assert get_dynatrace_env(base).dql_max_poll_seconds is None
    assert get_dynatrace_env({**base, "DQL_MAX_POLL_SECONDS": "90"}).dql_max_poll_seconds == 90
    for bad in ("0", "-5", "abc", "nan"):
        with pytest.raises(ValueError, match="DQL_MAX_POLL_SECONDS"):
            get_dynatrace_env({**base, "DQL_MAX_POLL_SECONDS": bad})


@respx.mock
async def test_dql_is_cancelled_after_max_poll_seconds(monkeypatch):
    monkeypatch.setattr(dql_module, "POLL_INTERVAL_S", 0)
    monkeypatch.setattr(dql_module, "MAX_POLL_SECONDS", dql_module.MAX_POLL_SECONDS)  # restored after the test
    dql_module.set_max_poll_seconds(0)

    api = f"{ENV}{dql_module.QUERY_API}"
    respx.post(f"{api}/query:execute").respond(json={"requestToken": "tok", "state": "RUNNING"})
    respx.get(f"{api}/query:poll").respond(json={"state": "RUNNING"})
    cancel = respx.post(f"{api}/query:cancel").respond(status_code=200, json={})

    from dynatrace_mcp.client import DynatraceClient

    with pytest.raises(TimeoutError, match="within 0 seconds"):
        await dql_module.execute_dql(DynatraceClient(ENV, "t"), "fetch logs")
    assert cancel.called
