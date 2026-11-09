"""Creates authenticated Dynatrace clients.

Order of precedence:
1. DT_PLATFORM_TOKEN                       -> used directly as bearer token
2. OAUTH_CLIENT_ID + OAUTH_CLIENT_SECRET   -> OAuth client credentials flow
3. OAUTH_CLIENT_ID only                    -> interactive OAuth authorization code flow (browser)
"""

from __future__ import annotations

import asyncio
import sys
import time

from ..client import DynatraceClient
from .oauth import (
    get_random_port,
    get_sso_url,
    perform_authorization_code_flow,
    refresh_access_token,
    request_token_for_client_credentials,
)
from .token_cache import get_or_create_token_cache

__all__ = ["create_dt_client"]


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


async def create_dt_client(
    environment_url: str,
    scopes: list[str],
    client_id: str | None = None,
    client_secret: str | None = None,
    platform_token: str | None = None,
    oauth_redirect_port: int | None = None,
) -> DynatraceClient:
    if platform_token:
        return DynatraceClient(environment_url, platform_token)
    if client_id and client_secret:
        return await _client_credentials_client(environment_url, scopes, client_id, client_secret)
    if client_id:
        return await _auth_code_flow_client(environment_url, scopes, client_id, oauth_redirect_port)
    raise RuntimeError(
        "Failed to create Dynatrace HTTP Client: Please provide either clientId and clientSecret for client "
        "credentials flow, clientId only for interactive OAuth flow, or just a platform token."
    )


# ------------------------------------------------------------- client credentials

# Client-credentials tokens are cached per (client, scope set) until shortly before
# they expire, instead of requesting a new token for every tool call.
_cc_tokens: dict[tuple[str, frozenset[str]], tuple[str, float]] = {}
_cc_lock = asyncio.Lock()


async def _client_credentials_client(
    environment_url: str, scopes: list[str], client_id: str, client_secret: str
) -> DynatraceClient:
    key = (client_id, frozenset(scopes))
    async with _cc_lock:
        cached = _cc_tokens.get(key)
        if cached and time.time() + 30 < cached[1]:
            return DynatraceClient(environment_url, cached[0])

        _log(
            f"🔒 Client-Creds-Flow: Trying to authenticate API Calls to {environment_url} via OAuthClientId "
            f"{client_id} with the following scopes: {', '.join(scopes)}"
        )
        sso = await get_sso_url(environment_url)
        token = await request_token_for_client_credentials(client_id, client_secret, sso, scopes)
        if (
            not token.get("access_token")
            or token.get("error")
            or token.get("error_description")
            or token.get("issueId")
        ):
            raise RuntimeError(
                f"Failed to retrieve OAuth token (IssueId: {token.get('issueId')}): {token.get('error')} - "
                f"{token.get('error_description')}. Note: Your OAuth client is most likely not configured "
                "correctly and/or is missing scopes."
            )
        _log(
            f"Successfully retrieved token from SSO! Token valid for {token.get('expires_in')}s "
            f"with scopes: {token.get('scope')}"
        )
        _cc_tokens[key] = (token["access_token"], time.time() + float(token.get("expires_in") or 300))
        return DynatraceClient(environment_url, token["access_token"])


# ------------------------------------------------------------- authorization code flow

# One lock per cache key: deduplicates concurrent refreshes (refresh tokens are
# single-use) and prevents two browser login flows from starting at once.
_auth_locks: dict[str, asyncio.Lock] = {}


async def _auth_code_flow_client(
    environment_url: str, scopes: list[str], client_id: str, oauth_redirect_port: int | None
) -> DynatraceClient:
    sso = await get_sso_url(environment_url)
    cache_key = f"{client_id}@{sso}"
    cache = await get_or_create_token_cache(cache_key)
    lock = _auth_locks.setdefault(cache_key, asyncio.Lock())

    async with lock:
        token = cache.get_token()
        if token and cache.is_token_valid():
            expires_at = token.get("expires_at")
            expires_in = round((expires_at - time.time() * 1000) / 1000) if expires_at else "never"
            _log(f"✅ Auth-Code-Flow: Using cached access token (expires in {expires_in}s)")
            return DynatraceClient(environment_url, token["access_token"])

        if token and token.get("refresh_token"):
            _log("🔍 Auth-Code-Flow: Found expired cached token, attempting refresh...")
            try:
                refreshed = await refresh_access_token(sso, client_id, token["refresh_token"], scopes)
                _log("✅ Successfully refreshed access token!")
                await cache.set_token(scopes, refreshed)
                return DynatraceClient(environment_url, refreshed["access_token"])
            except Exception as e:
                _log(f"❌ Token refresh failed with error: {e}")
                await cache.clear_token()

        _log("🚀 Auth-Code-Flow: No valid cached token found, initiating OAuth Authorization Code Flow...")
        _log(f"Using SSO base URL {sso}")

        max_attempts = 1 if oauth_redirect_port else 3
        used_ports: list[int] = []
        last_error: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            port = oauth_redirect_port or get_random_port(exclude=used_ports)
            used_ports.append(port)
            try:
                _log(f"🔄 Attempting to start OAuth callback server on port {port} (attempt {attempt}/{max_attempts})")
                response = await perform_authorization_code_flow(sso, client_id, scopes, port)
                await cache.set_token(scopes, response)
                _log(f"✅ Successfully retrieved token from SSO! Token cached for future use with scopes: {', '.join(scopes)}")
                return DynatraceClient(environment_url, response["access_token"])
            except OSError as e:  # port already in use
                last_error = e
                _log(f"❌ Port {port} is already in use. {'Retrying with a different port...' if attempt < max_attempts else ''}")
                await asyncio.sleep(0.5)
            except Exception as e:
                last_error = e
                break

        raise RuntimeError(
            f"Failed to start OAuth callback server after {max_attempts} attempts. Last error: {last_error}"
        )
