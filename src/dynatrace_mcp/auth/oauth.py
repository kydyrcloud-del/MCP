"""OAuth helpers: SSO discovery, token endpoint, client credentials, and the
interactive authorization-code flow with PKCE."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import os
import random
import secrets
import sys
import threading
import webbrowser
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

import httpx

DEFAULT_SSO_URL = "https://sso.dynatrace.com"


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------- SSO discovery


async def get_sso_url(environment_url: str) -> str:
    """Find the SSO base URL by following the platform's OAuth redirect."""
    override = os.environ.get("DT_SSO_URL")
    if override:
        _log(f"Using SSO URL from DT_SSO_URL environment variable: {override}")
        return override

    try:
        url = environment_url.rstrip("/") + "/platform/oauth2/authorization/dynatrace-sso"
        async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
            response = await http.head(url)
        if 300 <= response.status_code < 400 and response.headers.get("location"):
            loc = urlparse(response.headers["location"])
            return f"{loc.scheme}://{loc.netloc}"
        _log(f"No redirect found when discovering SSO URL for {environment_url}, using default: {DEFAULT_SSO_URL}")
    except Exception as e:
        _log(f"Error discovering SSO URL for {environment_url}: {e}. Using default: {DEFAULT_SSO_URL}")
    return DEFAULT_SSO_URL


# ---------------------------------------------------------------- token endpoint


async def request_oauth_token(sso_base_url: str, params: dict[str, str]) -> dict[str, Any]:
    """POST to /sso/oauth2/token. Returns the JSON body even for error responses."""
    async with httpx.AsyncClient(timeout=30) as http:
        res = await http.post(
            sso_base_url.rstrip("/") + "/sso/oauth2/token",
            data=params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if not res.is_success:
        _log(f"Failed to fetch token: {res.status_code} {res.reason_phrase}")
    try:
        return res.json()
    except ValueError:
        return {"error": f"HTTP {res.status_code}", "error_description": res.text[:500]}


async def request_token_for_client_credentials(
    client_id: str, client_secret: str, sso_base_url: str, scopes: list[str]
) -> dict[str, Any]:
    return await request_oauth_token(
        sso_base_url,
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": " ".join(scopes),
        },
    )


async def refresh_access_token(
    sso_base_url: str, client_id: str, refresh_token: str, scopes: list[str]
) -> dict[str, Any]:
    response = await request_oauth_token(
        sso_base_url,
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": " ".join(scopes),
        },
    )
    if not response.get("access_token") or response.get("error"):
        raise RuntimeError(
            f"Failed to refresh access token: {response.get('error')} - {response.get('error_description')}"
        )
    return response


# ---------------------------------------------------------------- PKCE helpers


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def generate_pkce_challenge() -> tuple[str, str]:
    verifier = base64url_encode(secrets.token_bytes(46))
    challenge = base64url_encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def get_random_port(min_port: int = 5344, max_port: int = 5349, exclude: list[int] | None = None) -> int:
    exclude = exclude or []
    choices = [p for p in range(min_port, max_port + 1) if p not in exclude]
    if not choices:
        raise RuntimeError("No available ports to choose from")
    return random.choice(choices)


def get_codespaces_forwarded_url(port: int) -> str | None:
    name = os.environ.get("CODESPACE_NAME")
    domain = os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
    return f"https://{name}-{port}.{domain}" if name and domain else None


def create_authorization_url(
    sso_base_url: str, client_id: str, redirect_uri: str, scopes: list[str]
) -> tuple[str, str, str]:
    """Returns (authorization_url, code_verifier, state)."""
    state = secrets.token_hex(20)
    verifier, challenge = generate_pkce_challenge()
    parts = [
        f"client_id={quote(client_id, safe='')}",
        f"redirect_uri={quote(redirect_uri, safe='')}",
        f"state={quote(state, safe='')}",
        "response_type=code",
        "code_challenge_method=S256",
        f"code_challenge={quote(challenge, safe='')}",
        f"scope={quote(' '.join(scopes), safe='')}",
    ]
    return f"{sso_base_url.rstrip('/')}/oauth2/authorize?{'&'.join(parts)}", verifier, state


# ---------------------------------------------------------------- redirect server

_PAGE = "<!DOCTYPE html><html><head><title>{title}</title></head><body><h1>{title}</h1>{body}</body></html>"


async def _start_redirect_server(port: int) -> tuple[asyncio.Server, asyncio.Future[tuple[str, str]]]:
    loop = asyncio.get_running_loop()
    result: asyncio.Future[tuple[str, str]] = loop.create_future()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = (await reader.readline()).decode(errors="replace")
            # drain headers
            while (line := await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            parts = request_line.split(" ")
            target = urlparse(parts[1] if len(parts) > 1 else "/")
            query = {k: v[0] for k, v in parse_qs(target.query).items()}

            if target.path != "/auth/login":
                status, page = "404 Not Found", "Not Found"
            elif query.get("error"):
                status = "400 Bad Request"
                page = _PAGE.format(
                    title="OAuth Authorization Error",
                    body=f"<p><strong>Error:</strong> {html.escape(query['error'])}</p>"
                    f"<p><strong>Description:</strong> {html.escape(query.get('error_description', 'Unknown error'))}</p>"
                    "<p>You can close this tab and check the console for more information.</p>",
                )
                if not result.done():
                    result.set_exception(
                        RuntimeError(f"OAuth error: {query['error']} - {query.get('error_description')}")
                    )
            elif query.get("code") and query.get("state"):
                status = "200 OK"
                page = _PAGE.format(
                    title="Authorization Successful!",
                    body="<p>You have successfully authorized the Dynatrace MCP Server.</p>"
                    "<p>You can close this tab and return to your terminal.</p>"
                    "<script>setTimeout(() => window.close(), 3000);</script>",
                )
                if not result.done():
                    result.set_result((query["code"], query["state"]))
            else:
                status = "400 Bad Request"
                page = _PAGE.format(
                    title="Invalid OAuth Callback",
                    body="<p>The authorization code or state parameter is missing.</p>",
                )
                if not result.done():
                    result.set_exception(RuntimeError("Missing authorization code or state parameter"))

            payload = page.encode()
            writer.write(
                f"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                + payload
            )
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "localhost", port)
    return server, result


def _open_browser(url: str) -> None:
    def run() -> None:
        try:
            if not webbrowser.open(url):
                _log("⚠️ Could not open browser automatically. Please open the URL below manually.")
        except Exception as e:
            _log(f"⚠️ Could not open browser automatically: {e}. Please open the URL below manually.")

    threading.Thread(target=run, daemon=True).start()


async def perform_authorization_code_flow(
    sso_base_url: str, client_id: str, scopes: list[str], port: int, timeout_s: float = 300
) -> dict[str, Any]:
    _log("🚀 Starting OAuth Authorization Code Flow with local redirect/callback...")
    server, code_future = await _start_redirect_server(port)
    forwarded = get_codespaces_forwarded_url(port)
    redirect_uri = f"{forwarded}/auth/login" if forwarded else f"http://localhost:{port}/auth/login"
    _log(f"🌐 OAuth redirect server listening on {redirect_uri}")

    try:
        auth_url, verifier, state = create_authorization_url(sso_base_url, client_id, redirect_uri, scopes)
        _log("\n" + "=" * 60 + "\n🔐 OAuth Authorization Required\n" + "=" * 60 + "\n")
        _log("Trying to open the authorization URL in your default browser...")
        _open_browser(auth_url)
        _log(f"\n👉 {auth_url}\n")
        _log("After authorization, you will be redirected back and the server will continue automatically.")
        _log("=" * 60 + "\n")

        code, received_state = await asyncio.wait_for(code_future, timeout=timeout_s)
        if received_state != state:
            raise RuntimeError("OAuth state parameter mismatch - possible CSRF attack")

        _log("✅ Authorization code received! Exchanging for access token...")
        token = await request_oauth_token(
            sso_base_url,
            {
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        if not token.get("access_token") or token.get("error"):
            raise RuntimeError(
                f"Failed to exchange code for token: {token.get('error')} - {token.get('error_description')}"
            )
        _log("🎉 Successfully obtained access token via OAuth Authorization Code Flow!")
        return token
    finally:
        server.close()
        await server.wait_closed()
