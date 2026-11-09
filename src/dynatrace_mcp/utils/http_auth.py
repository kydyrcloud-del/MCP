"""Bearer-token validation for HTTP mode (MCP_AUTH_MODE=bearer)."""

from __future__ import annotations

import hmac

MAX_BODY_BYTES = 1_048_576  # 1 MiB


def validate_bearer_token(auth_header: str | None, expected_token: str) -> bool:
    """Constant-time check that ``auth_header`` is exactly ``Bearer <expected_token>``."""
    prefix = "Bearer "
    if not auth_header or not auth_header.startswith(prefix):
        return False
    provided = auth_header[len(prefix) :].encode()
    return hmac.compare_digest(provided, expected_token.encode())
