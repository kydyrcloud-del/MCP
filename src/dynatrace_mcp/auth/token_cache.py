"""Persistent OAuth token cache.

* default: OS keychain via ``keyring`` (service "dynatrace-mcp"), stored as JSON
* ``DT_MCP_TOKEN_STORAGE=file``: ~/.config/dynatrace-mcp/token-<account>.json (mode 0600)
* falls back to in-memory only if no keychain backend is available
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, TypedDict

KEYCHAIN_SERVICE = "dynatrace-mcp"
TOKEN_CACHE_DIR = Path.home() / ".config" / "dynatrace-mcp"
EXPIRY_BUFFER_MS = 30_000


class CachedToken(TypedDict, total=False):
    access_token: str
    refresh_token: str | None
    expires_at: float | None  # epoch milliseconds
    scopes: list[str]


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _is_valid_cached_token(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("access_token"), str) and bool(value["access_token"])


def token_from_response(scopes: list[str], response: dict[str, Any]) -> CachedToken:
    expires_in = response.get("expires_in")
    return CachedToken(
        access_token=response["access_token"],
        refresh_token=response.get("refresh_token"),
        expires_at=time.time() * 1000 + expires_in * 1000 if expires_in else None,
        scopes=list(scopes),
    )


class TokenCache:
    """In-memory token cache. Subclasses add persistence."""

    def __init__(self) -> None:
        self._token: CachedToken | None = None

    async def initialize(self) -> None:  # pragma: no cover - overridden
        return None

    def get_token(self) -> CachedToken | None:
        return self._token

    def is_token_valid(self) -> bool:
        if not self._token:
            return False
        expires_at = self._token.get("expires_at")
        if not expires_at:
            return True
        return time.time() * 1000 + EXPIRY_BUFFER_MS < expires_at

    async def set_token(self, scopes: list[str], response: dict[str, Any]) -> None:
        self._token = token_from_response(scopes, response)
        await self._persist()

    async def clear_token(self) -> None:
        self._token = None
        await self._delete()

    async def _persist(self) -> None:
        return None

    async def _delete(self) -> None:
        return None


class KeychainTokenCache(TokenCache):
    def __init__(self, account: str) -> None:
        super().__init__()
        self.account = account
        self._keyring: Any = None

    async def initialize(self) -> None:
        try:
            import keyring
            from keyring.backends.fail import Keyring as FailKeyring

            if isinstance(keyring.get_keyring(), FailKeyring):
                raise RuntimeError("no keyring backend")
            self._keyring = keyring
        except Exception:
            _log("⚠️ OS keychain not available – auth tokens will not be persisted across restarts.")
            return

        try:
            stored = await asyncio.to_thread(self._keyring.get_password, KEYCHAIN_SERVICE, self.account)
            if stored:
                parsed = json.loads(stored)
                if _is_valid_cached_token(parsed):
                    self._token = parsed
                    _log("🔑 Loaded existing auth token from OS keychain.")
                else:
                    _log("⚠️ Failed to load token from OS keychain: stored data is not a valid token")
        except Exception as e:
            _log(f"⚠️ Failed to load token from OS keychain: {e}")

    async def _persist(self) -> None:
        if not self._keyring or not self._token:
            return
        try:
            await asyncio.to_thread(
                self._keyring.set_password, KEYCHAIN_SERVICE, self.account, json.dumps(self._token)
            )
            _log("🔑 Auth token saved to OS keychain.")
        except Exception as e:
            _log(f"⚠️ Failed to save token to OS keychain: {e}")

    async def _delete(self) -> None:
        if not self._keyring:
            return
        try:
            await asyncio.to_thread(self._keyring.delete_password, KEYCHAIN_SERVICE, self.account)
        except Exception:
            pass


class FileTokenCache(TokenCache):
    def __init__(self, account: str, directory: Path = TOKEN_CACHE_DIR) -> None:
        super().__init__()
        self.path = directory / f"token-{re.sub(r'[^a-zA-Z0-9_-]', '_', account)}.json"

    async def initialize(self) -> None:
        try:
            parsed = json.loads(self.path.read_text("utf-8"))
            if _is_valid_cached_token(parsed):
                self._token = parsed
                _log("🔑 Loaded existing auth token from file cache.")
            else:
                _log("⚠️ Failed to load token from file cache: stored data is not a valid token")
        except FileNotFoundError:
            pass
        except Exception as e:
            _log(f"⚠️ Failed to load token from file cache: {e}")

    async def _persist(self) -> None:
        if not self._token:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._token, f)
            _log("🔑 Auth token saved to file cache.")
        except Exception as e:
            _log(f"⚠️ Failed to save token to file cache: {e}")

    async def _delete(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


_caches: dict[str, TokenCache] = {}
_cache_lock = asyncio.Lock()


async def get_or_create_token_cache(account: str) -> TokenCache:
    async with _cache_lock:
        if account not in _caches:
            cache: TokenCache = (
                FileTokenCache(account)
                if os.environ.get("DT_MCP_TOKEN_STORAGE") == "file"
                else KeychainTokenCache(account)
            )
            await cache.initialize()
            _caches[account] = cache
        return _caches[account]
