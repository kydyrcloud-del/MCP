"""Minimal authenticated HTTP client for the Dynatrace Platform API.

There is no official Python SDK for these platform APIs, so this small client
covers what the tools need. Proxy settings (HTTPS_PROXY / HTTP_PROXY / NO_PROXY) are
honored automatically by httpx.
"""

from __future__ import annotations

import json
import platform
import sys
from collections.abc import Iterable
from typing import Any

import httpx

from . import __version__


def get_user_agent() -> str:
    return f"dynatrace-mcp-server-python/v{__version__} ({sys.platform}-{platform.machine()})"


class DynatraceApiError(Exception):
    """Raised for non-success HTTP responses from the Dynatrace API."""

    def __init__(self, status: int, message: str, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body

    def __str__(self) -> str:
        hint = ""
        if self.status == 403:
            hint = "Note: Your user or service-user is most likely lacking the necessary permissions/scopes for this API Call. "
        body = json.dumps(self.body) if not isinstance(self.body, str) else self.body
        return f"Client Request Error: {self.args[0]} with HTTP status: {self.status}. {hint}(body: {body})"


class DynatraceClient:
    """Bearer-token authenticated client bound to one Dynatrace environment."""

    def __init__(self, environment_url: str, bearer_token: str, timeout: float = 120.0) -> None:
        self.environment_url = environment_url.rstrip("/")
        self._bearer_token = bearer_token
        self._timeout = timeout

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        expected_status: Iterable[int] | None = None,
    ) -> Any:
        req_headers = {
            "Authorization": f"Bearer {self._bearer_token}",
            "User-Agent": get_user_agent(),
            "Accept": "application/json",
            **(headers or {}),
        }
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}

        async with httpx.AsyncClient(base_url=self.environment_url, timeout=self._timeout) as http:
            response = await http.request(
                method,
                path,
                json=json_body,
                params=clean_params or None,
                headers=req_headers,
                data=data,
                files=files,
            )

        ok = response.status_code in expected_status if expected_status else response.is_success
        body: Any
        try:
            body = response.json() if response.content else None
        except ValueError:
            body = response.text

        if not ok:
            message = response.reason_phrase or "Request failed"
            if isinstance(body, dict):
                err = body.get("error")
                if isinstance(err, dict) and err.get("message"):
                    message = err["message"]
                elif isinstance(err, str):
                    message = err
            raise DynatraceApiError(response.status_code, message, body)

        return body

    async def get(self, path: str, **kwargs: Any) -> Any:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> Any:
        return await self.request("POST", path, **kwargs)
