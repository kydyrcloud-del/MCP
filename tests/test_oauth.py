import asyncio
import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from dynatrace_mcp.auth import oauth
from dynatrace_mcp.auth.token_cache import FileTokenCache


def test_authorization_url_and_pkce():
    url, verifier, state = oauth.create_authorization_url(
        "https://sso.dynatrace.com", "dt0s12.client", "http://localhost:5344/auth/login", ["a:b", "c:d"]
    )
    q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    assert url.startswith("https://sso.dynatrace.com/oauth2/authorize?client_id=dt0s12.client&redirect_uri=")
    assert q["state"] == state and q["code_challenge_method"] == "S256" and q["scope"] == "a:b c:d"
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert q["code_challenge"] == expected
    assert "%20" in url  # spaces encoded as %20, not '+'


@respx.mock
async def test_full_authorization_code_flow(monkeypatch, unused_tcp_port):
    opened: list[str] = []
    monkeypatch.setattr(oauth, "_open_browser", opened.append)
    token_route = respx.post("https://sso.example.com/sso/oauth2/token").mock(
        return_value=httpx.Response(200, json={"access_token": "at", "refresh_token": "rt", "expires_in": 300})
    )
    respx.route(host="localhost").pass_through()

    async def simulate_browser():
        while not opened:
            await asyncio.sleep(0.01)
        state = parse_qs(urlparse(opened[0]).query)["state"][0]
        async with httpx.AsyncClient() as http:
            r = await http.get(f"http://localhost:{unused_tcp_port}/auth/login", params={"code": "c0de", "state": state})
        assert r.status_code == 200 and "Authorization Successful" in r.text

    flow = asyncio.create_task(
        oauth.perform_authorization_code_flow("https://sso.example.com", "cid", ["s:1"], unused_tcp_port)
    )
    await simulate_browser()
    token = await flow

    assert token["access_token"] == "at"
    form = parse_qs(token_route.calls[0].request.content.decode())
    assert form["grant_type"] == ["authorization_code"] and form["code"] == ["c0de"]
    assert form["redirect_uri"] == [f"http://localhost:{unused_tcp_port}/auth/login"]
    assert form["code_verifier"][0]


@respx.mock
async def test_authorization_code_flow_rejects_state_mismatch(monkeypatch, unused_tcp_port):
    opened: list[str] = []
    monkeypatch.setattr(oauth, "_open_browser", opened.append)
    respx.route(host="localhost").pass_through()

    flow = asyncio.create_task(oauth.perform_authorization_code_flow("https://sso.example.com", "cid", [], unused_tcp_port))
    while not opened:
        await asyncio.sleep(0.01)
    async with httpx.AsyncClient() as http:
        await http.get(f"http://localhost:{unused_tcp_port}/auth/login", params={"code": "c", "state": "forged"})
    with pytest.raises(RuntimeError, match="state parameter mismatch"):
        await flow


async def test_file_token_cache_roundtrip(tmp_path):
    cache = FileTokenCache("cid@https://sso", directory=tmp_path)
    await cache.initialize()
    assert cache.get_token() is None
    await cache.set_token(["s"], {"access_token": "at", "refresh_token": "rt", "expires_in": 300})
    assert cache.is_token_valid()
    assert oct(cache.path.stat().st_mode & 0o777) == "0o600"

    reloaded = FileTokenCache("cid@https://sso", directory=tmp_path)
    await reloaded.initialize()
    assert reloaded.get_token()["access_token"] == "at"

    await reloaded.clear_token()
    assert not cache.path.exists()
