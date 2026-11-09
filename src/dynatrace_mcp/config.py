"""Reads and validates environment variables.

Two groups of settings:

* ``DynatraceEnv``: how the server reaches and authenticates against Dynatrace.
* ``SecuritySettings``: how MCP clients authenticate against this server (HTTP mode)
  and which tools each caller may use.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse

from .utils.dql_sanitize import validate_timeframe

DEFAULT_MAX_QUERY_TIMEFRAME = "30d"

# =============================================================================
# Dynatrace connection
# =============================================================================


@dataclass
class DynatraceEnv:
    dt_environment: str
    oauth_client_id: str | None = None
    oauth_client_secret: str | None = None
    dt_platform_token: str | None = None
    # DQL_MAX_POLL_SECONDS; None = mode default (600s stdio, 60s HTTP), applied in main()
    dql_max_poll_seconds: float | None = None
    # MAX_QUERY_TIMEFRAME: longest timeframe a query tool accepts (bounds the data each query scans)
    max_query_timeframe: str = DEFAULT_MAX_QUERY_TIMEFRAME

    @property
    def uses_auth_code_flow(self) -> bool:
        """True when the interactive browser login would be used (no secret, no token)."""
        return not self.dt_platform_token and not self.oauth_client_secret


def _optional(name: str, value: str | None) -> str | None:
    """Treat empty strings as unset (some MCP clients set blank fields to "")."""
    if value == "":
        print(f"⚠️ {name} is set to an empty string – ignoring it and treating it as unset.", file=sys.stderr)
        return None
    return value


def get_dynatrace_env(env: Mapping[str, str] | None = None) -> DynatraceEnv:
    """Validate the environment. Raises ValueError with a user-friendly message on failure."""
    env = os.environ if env is None else env

    oauth_client_id = _optional("OAUTH_CLIENT_ID", env.get("OAUTH_CLIENT_ID"))
    oauth_client_secret = _optional("OAUTH_CLIENT_SECRET", env.get("OAUTH_CLIENT_SECRET"))
    dt_platform_token = _optional("DT_PLATFORM_TOKEN", env.get("DT_PLATFORM_TOKEN"))
    dt_environment = env.get("DT_ENVIRONMENT")

    if not dt_environment:
        raise ValueError("Please set DT_ENVIRONMENT environment variable to your Dynatrace Platform Environment")

    invalid_url_msg = (
        "Please set DT_ENVIRONMENT to a valid Dynatrace Environment URL "
        "(e.g., https://<environment-id>.apps.dynatrace.com)"
    )
    parsed = urlparse(dt_environment)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(invalid_url_msg)

    # Only platform URLs are allowed (not classic *.live.dynatrace.com URLs)
    if not re.search(r"\.apps\.(dynatrace|dynatracelabs)\.com/?$", dt_environment):
        raise ValueError(
            "Please set DT_ENVIRONMENT to a valid Dynatrace Platform Environment URL "
            "(e.g., https://<environment-id>.apps.dynatrace.com or "
            "https://<environment-id>.sprint.apps.dynatracelabs.com)"
        )

    dql_max_poll_seconds: float | None = None
    poll_raw = (env.get("DQL_MAX_POLL_SECONDS") or "").strip()
    if poll_raw:
        try:
            dql_max_poll_seconds = float(poll_raw)
        except ValueError:
            dql_max_poll_seconds = float("nan")
        if not (dql_max_poll_seconds > 0):  # also rejects NaN
            raise ValueError("DQL_MAX_POLL_SECONDS must be a positive number of seconds")

    max_query_timeframe = (env.get("MAX_QUERY_TIMEFRAME") or "").strip() or DEFAULT_MAX_QUERY_TIMEFRAME
    try:
        validate_timeframe(max_query_timeframe)
    except ValueError:
        raise ValueError('MAX_QUERY_TIMEFRAME must be a timeframe like "30d", "2w" or "12h"') from None

    return DynatraceEnv(
        dt_environment=dt_environment.rstrip("/"),
        oauth_client_id=oauth_client_id,
        oauth_client_secret=oauth_client_secret,
        dt_platform_token=dt_platform_token,
        dql_max_poll_seconds=dql_max_poll_seconds,
        max_query_timeframe=max_query_timeframe,
    )


# =============================================================================
# Client authentication + authorization
# =============================================================================

AuthMode = Literal["entra", "bearer", "none"]


@dataclass
class SecuritySettings:
    http_mode: bool = False
    auth_mode: AuthMode = "none"  # "none" only for stdio

    # static bearer token (MCP_AUTH_MODE=bearer)
    bearer_token: str | None = None
    bearer_roles: list[str] = field(default_factory=list)

    # roles granted to the local user in stdio mode
    stdio_roles: list[str] = field(default_factory=list)

    # Microsoft Entra ID (MCP_AUTH_MODE=entra)
    entra_tenant_id: str | None = None
    entra_audiences: list[str] = field(default_factory=list)
    entra_issuers: list[str] = field(default_factory=list)
    entra_allowed_client_ids: list[str] = field(default_factory=list)
    entra_scopes: list[str] = field(default_factory=list)  # advertised in protected-resource metadata
    require_role: bool = True

    # public URL of the MCP endpoint as clients see it (e.g. the APIM URL)
    public_url: str | None = None

    # HTTP transport hardening
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_origins: list[str] = field(default_factory=list)
    # Shared secret the gateway (APIM) adds to every request, so callers cannot skip the
    # gateway and its rate limits by calling the container directly (MCP_UPSTREAM_SECRET)
    upstream_secret: str | None = None
    upstream_secret_header: str = "x-from-apim"
    # Proxies whose X-Forwarded-* headers uvicorn trusts (MCP_FORWARDED_ALLOW_IPS)
    forwarded_allow_ips: str = "127.0.0.1"

    # behaviour
    tool_roles_override: dict[str, list[str]] = field(default_factory=dict)
    audit_log: bool = True
    audit_log_args: bool = True


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _bool(name: str, value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be true or false (got {value!r})")


def get_security_settings(env: Mapping[str, str] | None = None, *, http_mode: bool = False) -> SecuritySettings:
    """Validate client-auth and authorization settings. Raises ValueError on misconfiguration."""
    # Imported here to avoid a cycle (security.roles has no dependency on config).
    from .security.roles import ALL_ROLES, ALL_TOOLS

    env = os.environ if env is None else env
    s = SecuritySettings(http_mode=http_mode)

    s.stdio_roles = _csv(env.get("MCP_STDIO_ROLES")) or list(ALL_ROLES)
    s.bearer_roles = _csv(env.get("MCP_BEARER_ROLES")) or list(ALL_ROLES)
    s.allowed_hosts = _csv(env.get("MCP_ALLOWED_HOSTS"))
    s.allowed_origins = _csv(env.get("MCP_ALLOWED_ORIGINS"))
    s.public_url = (env.get("MCP_PUBLIC_URL") or "").rstrip("/") or None
    s.require_role = _bool("MCP_REQUIRE_ROLE", env.get("MCP_REQUIRE_ROLE"), True)
    s.audit_log = _bool("MCP_AUDIT_LOG", env.get("MCP_AUDIT_LOG"), True)
    s.audit_log_args = _bool("MCP_AUDIT_LOG_ARGS", env.get("MCP_AUDIT_LOG_ARGS"), True)

    s.forwarded_allow_ips = (env.get("MCP_FORWARDED_ALLOW_IPS") or "").strip() or "127.0.0.1"
    s.upstream_secret = env.get("MCP_UPSTREAM_SECRET") or None
    header = (env.get("MCP_UPSTREAM_SECRET_HEADER") or "").strip().lower()
    if header:
        if not re.fullmatch(r"[a-z0-9-]+", header) or header in ("authorization", "host", "content-type"):
            raise ValueError("MCP_UPSTREAM_SECRET_HEADER must be a custom header name, e.g. x-from-apim")
        s.upstream_secret_header = header
    if s.upstream_secret is not None and len(s.upstream_secret) < 16:
        raise ValueError("MCP_UPSTREAM_SECRET must be at least 16 characters long (openssl rand -base64 32)")

    if s.public_url and urlparse(s.public_url).scheme not in ("https", "http"):
        raise ValueError("MCP_PUBLIC_URL must be an absolute URL, e.g. https://my-apim.azure-api.net/dynatrace/mcp")

    raw_override = env.get("MCP_TOOL_ROLES")
    if raw_override:
        try:
            override = json.loads(raw_override)
        except json.JSONDecodeError as e:
            raise ValueError(f"MCP_TOOL_ROLES must be a JSON object: {e}") from e
        if not isinstance(override, dict) or not all(
            isinstance(k, str) and isinstance(v, list) and all(isinstance(r, str) for r in v) for k, v in override.items()
        ):
            raise ValueError('MCP_TOOL_ROLES must map tool names to lists of role names, e.g. {"list_problems": ["Dynatrace.Read"]}')
        unknown = sorted(set(override) - ALL_TOOLS)
        if unknown:
            raise ValueError(f"MCP_TOOL_ROLES contains unknown tool(s): {', '.join(unknown)}")
        s.tool_roles_override = override

    if not http_mode:
        s.auth_mode = "none"
        return s

    mode = (env.get("MCP_AUTH_MODE") or "").strip().lower()
    if not mode:
        mode = "entra" if env.get("ENTRA_TENANT_ID") else "bearer"
    if mode not in ("entra", "bearer"):
        raise ValueError("MCP_AUTH_MODE must be 'entra' or 'bearer' in HTTP mode")
    s.auth_mode = mode  # type: ignore[assignment]

    if mode == "bearer":
        s.bearer_token = env.get("MCP_BEARER_TOKEN") or None
        if not s.bearer_token:
            raise ValueError(
                "MCP_BEARER_TOKEN is required for MCP_AUTH_MODE=bearer. Generate one with: "
                "export MCP_BEARER_TOKEN=$(openssl rand -base64 32)"
            )
        if len(s.bearer_token) < 16:
            raise ValueError("MCP_BEARER_TOKEN must be at least 16 characters long")
        return s

    tenant = (env.get("ENTRA_TENANT_ID") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", tenant):
        raise ValueError("ENTRA_TENANT_ID must be your Entra tenant ID (a GUID) for MCP_AUTH_MODE=entra")
    s.entra_tenant_id = tenant
    s.entra_audiences = _csv(env.get("ENTRA_AUDIENCE"))
    if not s.entra_audiences:
        raise ValueError(
            "ENTRA_AUDIENCE is required for MCP_AUTH_MODE=entra: the Application ID URI and/or client ID of the "
            "MCP API app registration, e.g. 'api://dynatrace-mcp,11111111-2222-3333-4444-555555555555'"
        )
    s.entra_issuers = _csv(env.get("ENTRA_ISSUERS")) or [
        f"https://login.microsoftonline.com/{tenant}/v2.0",  # v2 access tokens
        f"https://sts.windows.net/{tenant}/",  # v1 access tokens
    ]
    s.entra_allowed_client_ids = _csv(env.get("ENTRA_ALLOWED_CLIENT_IDS"))
    s.entra_scopes = _csv(env.get("ENTRA_SCOPES"))
    return s
