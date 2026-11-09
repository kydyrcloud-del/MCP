"""HTTP transport: stateless Streamable HTTP at /mcp, wrapped in an authentication layer.

Request handling order:

1. ``GET /health``                                   -> 200, no authentication (container probes)
2. gateway secret header (MCP_UPSTREAM_SECRET, if set) -> else 403. Proves the request
   came through APIM, so its rate limits and JWT checks cannot be skipped.
3. ``GET /.well-known/oauth-protected-resource[...]`` -> RFC 9728 metadata (Entra mode with MCP_PUBLIC_URL)
4. everything else: bearer token required
   * ``entra``:  Entra ID JWT validated (signature, expiry, audience, issuer, tenant, client app)
   * ``bearer``: constant-time comparison against MCP_BEARER_TOKEN
5. caller must hold at least one known role (MCP_REQUIRE_ROLE, default on)   -> else 403
6. the caller is stored in the ASGI scope and the request goes to the MCP app,
   where AuthorizationMiddleware filters and enforces tools per role.
"""

from __future__ import annotations

import hmac
import json
import sys
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlparse

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from .config import SecuritySettings
from .security import (
    SCOPE_CALLER_KEY,
    AuthenticationError,
    AuthenticationUnavailable,
    Caller,
    EntraTokenVerifier,
    ToolPolicy,
)
from .utils.http_auth import MAX_BODY_BYTES, validate_bearer_token

PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource"
START_TIME = time.monotonic()

Authenticator = Callable[[str | None], Awaitable[Caller]]


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def resource_metadata_url(public_url: str) -> str:
    """RFC 9728 location: https://host/path -> https://host/.well-known/oauth-protected-resource/path"""
    u = urlparse(public_url)
    path = u.path.rstrip("/")
    return f"{u.scheme}://{u.netloc}{PROTECTED_RESOURCE_PATH}{path}"


def allowed_hosts_for(host: str, port: int, extra: list[str]) -> list[str]:
    hosts = {"localhost", "127.0.0.1", "[::1]", "localhost:*", "127.0.0.1:*", "[::1]:*"}
    if host not in ("0.0.0.0", "::"):
        hosts |= {host, f"{host}:{port}"}
    hosts |= set(extra)
    return sorted(hosts)


def make_authenticator(settings: SecuritySettings, verifier: EntraTokenVerifier | None = None) -> Authenticator:
    if settings.auth_mode == "bearer":
        assert settings.bearer_token
        bearer_caller = Caller(id="static-bearer", name="static-bearer", auth="bearer", roles=frozenset(settings.bearer_roles))

        async def bearer(header: str | None) -> Caller:
            if not validate_bearer_token(header, settings.bearer_token or ""):
                raise AuthenticationError("Missing or invalid bearer token")
            return bearer_caller

        return bearer

    if settings.auth_mode == "entra":
        assert settings.entra_tenant_id
        v = verifier or EntraTokenVerifier(
            settings.entra_tenant_id,
            settings.entra_audiences,
            settings.entra_issuers,
            settings.entra_allowed_client_ids,
        )

        async def entra(header: str | None) -> Caller:
            if not header or not header.startswith("Bearer "):
                raise AuthenticationError("Missing bearer token")
            token = header[len("Bearer ") :].strip()
            if not token:
                raise AuthenticationError("Missing bearer token")
            return await v.verify(token)

        return entra

    raise ValueError(f"HTTP mode needs MCP_AUTH_MODE=entra or bearer (got {settings.auth_mode!r})")


def build_http_app(
    mcp: MCPServer,
    settings: SecuritySettings,
    policy: ToolPolicy,
    host: str,
    port: int,
    verifier: EntraTokenVerifier | None = None,
) -> Any:
    hosts = allowed_hosts_for(host, port, settings.allowed_hosts)
    protect = "*" not in hosts
    app = mcp.streamable_http_app(
        stateless_http=True,
        host=host,
        max_request_body_size=MAX_BODY_BYTES,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=protect,
            allowed_hosts=hosts,
            allowed_origins=settings.allowed_origins,
        ),
    )
    authenticate = make_authenticator(settings, verifier)
    known_roles = policy.known_roles
    metadata_url = resource_metadata_url(settings.public_url) if settings.public_url else None
    upstream_header = settings.upstream_secret_header.encode()
    upstream_secret = settings.upstream_secret.encode() if settings.upstream_secret else None

    def from_gateway(headers: dict[bytes, bytes]) -> bool:
        if upstream_secret is None:
            return True
        return hmac.compare_digest(headers.get(upstream_header, b""), upstream_secret)

    def www_authenticate(error: str | None = None, description: str | None = None) -> bytes:
        parts = ['Bearer realm="dynatrace-mcp"']
        if error:
            parts.append(f'error="{error}"')
        if description:
            parts.append('error_description="{}"'.format(description.replace('"', "'").replace("\\", "/")))
        if settings.auth_mode == "entra" and metadata_url:
            parts.append(f'resource_metadata="{metadata_url}"')
        return ", ".join(parts).encode()

    async def asgi(scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":  # lifespan
            await app(scope, receive, send)
            return

        async def respond(status: int, payload: dict, extra: list[tuple[bytes, bytes]] | None = None) -> None:
            body = json.dumps(payload).encode()
            headers = [(b"content-type", b"application/json"), (b"cache-control", b"no-store")] + (extra or [])
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": body})

        method, path = scope["method"], scope["path"]

        if method == "GET" and path == "/health":
            await respond(
                200,
                {"status": "ok", "uptime": round(time.monotonic() - START_TIME, 1), "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
            )
            return

        headers = dict(scope.get("headers") or [])
        if not from_gateway(headers):
            client = scope.get("client") or ("?", 0)
            _log(f"🔒 403 {method} {path}: request from {client[0]} did not come through the gateway (missing or wrong {settings.upstream_secret_header})")
            await respond(403, {"jsonrpc": "2.0", "id": None, "error": {"code": -32003, "message": "Forbidden"}})
            return

        if method == "GET" and path.startswith(PROTECTED_RESOURCE_PATH):
            if settings.auth_mode == "entra" and settings.public_url:
                meta: dict[str, Any] = {
                    "resource": settings.public_url,
                    "authorization_servers": [f"https://login.microsoftonline.com/{settings.entra_tenant_id}/v2.0"],
                    "bearer_methods_supported": ["header"],
                    "resource_name": "Dynatrace MCP Server",
                }
                if settings.entra_scopes:
                    meta["scopes_supported"] = settings.entra_scopes
                await respond(200, meta)
            else:
                await respond(404, {"error": "not_found"})
            return

        auth_header = headers.get(b"authorization", b"").decode(errors="replace") or None
        try:
            caller = await authenticate(auth_header)
        except AuthenticationError as e:
            had_token = bool(auth_header)
            _log(f"🔒 401 {method} {path}: {e}")
            await respond(
                401,
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "Unauthorized"}},
                [(b"www-authenticate", www_authenticate("invalid_token" if had_token else None, str(e) if had_token else None))],
            )
            return
        except AuthenticationUnavailable as e:
            await respond(503, {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(e)}}, [(b"retry-after", b"30")])
            return

        if settings.require_role and not (caller.roles & known_roles):
            _log(f"🔒 403 {method} {path}: caller {caller.name} ({caller.id}) has no Dynatrace MCP role")
            await respond(
                403,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32003, "message": f"Forbidden: caller holds none of the roles {', '.join(sorted(known_roles))}"},
                },
                [(b"www-authenticate", www_authenticate("insufficient_scope", "No Dynatrace MCP role assigned"))],
            )
            return

        scope[SCOPE_CALLER_KEY] = caller
        await app(scope, receive, send)

    return asgi
