"""Microsoft Entra ID access-token validation.

Checks the RS256 signature against the tenant's published signing keys (JWKS), then
expiry, audience, issuer and tenant, and optionally the calling client application.
Returns a ``Caller`` built from the token's claims.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any, Protocol

import jwt

from .caller import Caller


class AuthenticationError(Exception):
    """The bearer token is missing or invalid (HTTP 401)."""


class AuthenticationUnavailable(Exception):
    """The token could not be checked, e.g. the signing keys could not be fetched (HTTP 503)."""


class SigningKeySource(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


def jwks_url_for_tenant(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"


class EntraTokenVerifier:
    def __init__(
        self,
        tenant_id: str,
        audiences: list[str],
        issuers: list[str],
        allowed_client_ids: list[str] | None = None,
        key_source: SigningKeySource | None = None,
        leeway_s: int = 60,
    ) -> None:
        self.tenant_id = tenant_id
        self.audiences = list(audiences)
        self.issuers = list(issuers)
        self.allowed_client_ids = set(allowed_client_ids or [])
        self.leeway_s = leeway_s
        # PyJWKClient caches keys and re-fetches on an unknown key id (key rotation).
        self._keys: SigningKeySource = key_source or jwt.PyJWKClient(
            jwks_url_for_tenant(tenant_id), cache_keys=True, lifespan=3600, timeout=10
        )

    async def verify(self, token: str) -> Caller:
        try:
            signing_key = await asyncio.to_thread(self._keys.get_signing_key_from_jwt, token)
        except jwt.PyJWKClientConnectionError as e:
            print(f"❌ Could not fetch Entra signing keys: {e}", file=sys.stderr)
            raise AuthenticationUnavailable("Unable to validate tokens right now") from e
        except (jwt.PyJWKClientError, jwt.DecodeError) as e:
            raise AuthenticationError(f"Token signing key not recognized: {e}") from e

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                getattr(signing_key, "key", signing_key),
                algorithms=["RS256"],
                audience=self.audiences,
                issuer=self.issuers,
                leeway=self.leeway_s,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as e:
            raise AuthenticationError("Token has expired") from e
        except jwt.InvalidAudienceError as e:
            raise AuthenticationError("Token audience is not this MCP server") from e
        except jwt.InvalidIssuerError as e:
            raise AuthenticationError("Token issuer is not the configured Entra tenant") from e
        except jwt.PyJWTError as e:
            raise AuthenticationError(f"Invalid token: {e}") from e

        if claims.get("tid") and claims["tid"].lower() != self.tenant_id.lower():
            raise AuthenticationError("Token was issued for a different tenant")

        app_id = claims.get("azp") or claims.get("appid")
        if self.allowed_client_ids and app_id not in self.allowed_client_ids:
            raise AuthenticationError(f"Client application {app_id!r} is not allowed to call this MCP server")

        roles = claims.get("roles") or []
        if not isinstance(roles, list):
            roles = []
        is_app = claims.get("idtyp") == "app" or "scp" not in claims
        caller_id = claims.get("oid") or claims.get("sub")
        if not caller_id:
            raise AuthenticationError("Token has no oid/sub claim")

        name = claims.get("preferred_username") or claims.get("upn") or claims.get("unique_name") or app_id or caller_id
        return Caller(
            id=str(caller_id),
            name=str(name),
            auth="entra",
            roles=frozenset(str(r) for r in roles),
            app_id=str(app_id) if app_id else None,
            token_type="app" if is_app else "user",
            tenant_id=claims.get("tid"),
        )
