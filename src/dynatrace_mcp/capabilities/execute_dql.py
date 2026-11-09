"""DQL execution and verification against Grail."""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from ..client import DynatraceClient, get_user_agent

QUERY_API = "/platform/storage/query/v1"
POLL_INTERVAL_S = 2.0
# Give up (and cancel the query) after this long. 10 minutes suits a local stdio client;
# behind a gateway (APIM, Copilot) main() lowers it via DQL_MAX_POLL_SECONDS, because the
# caller times out much sooner and would never see the result anyway.
DEFAULT_MAX_POLL_SECONDS = 600.0
DEFAULT_HTTP_MAX_POLL_SECONDS = 60.0
MAX_POLL_SECONDS = DEFAULT_MAX_POLL_SECONDS


def set_max_poll_seconds(seconds: float) -> None:
    global MAX_POLL_SECONDS
    MAX_POLL_SECONDS = float(seconds)


@dataclass
class DqlExecutionResult:
    records: list[dict[str, Any]]
    metadata: dict[str, Any]
    types: list[dict[str, Any]] = field(default_factory=list)
    scanned_bytes: int = 0
    scanned_records: int | None = None
    execution_time_ms: int | None = None
    query_id: str | None = None
    sampled: bool | None = None


async def verify_dql_statement(client: DynatraceClient, dql: str) -> dict[str, Any]:
    return await client.post(f"{QUERY_API}/query:verify", json_body={"query": dql})


def _create_result(result: dict[str, Any], log_prefix: str) -> DqlExecutionResult:
    grail = (result.get("metadata") or {}).get("grail") or {}
    scanned = int(grail.get("scannedBytes") or 0)

    out = DqlExecutionResult(
        records=result.get("records") or [],
        metadata=result.get("metadata") or {},
        types=result.get("types") or [],
        scanned_bytes=scanned,
        scanned_records=grail.get("scannedRecords"),
        execution_time_ms=grail.get("executionTimeMilliseconds"),
        query_id=grail.get("queryId"),
        sampled=grail.get("sampled"),
    )
    print(
        f"{log_prefix} scannedBytes={out.scanned_bytes} scannedRecords={out.scanned_records} "
        f"executionTime={out.execution_time_ms} queryId={out.query_id}",
        file=sys.stderr,
    )
    return out


async def execute_dql(
    client: DynatraceClient,
    query: str,
    max_result_records: int | None = None,
    max_result_bytes: int | None = None,
) -> DqlExecutionResult | None:
    """Execute DQL; poll until the result is ready. Returns None if the query did not finish."""
    body: dict[str, Any] = {"query": query}
    if max_result_records is not None:
        body["maxResultRecords"] = max_result_records
    if max_result_bytes is not None:
        body["maxResultBytes"] = max_result_bytes

    headers = {"dt-client-context": get_user_agent()}
    response = await client.post(f"{QUERY_API}/query:execute", json_body=body, headers=headers)

    if response.get("result"):
        return _create_result(response["result"], "execute_dql - Metadata:")

    request_token = response.get("requestToken")
    if not request_token:
        print("execute_dql did not respond with a requestToken, stopping...", file=sys.stderr)
        return None

    deadline = time.monotonic() + MAX_POLL_SECONDS
    while True:
        await asyncio.sleep(POLL_INTERVAL_S)
        poll = await client.get(
            f"{QUERY_API}/query:poll", params={"request-token": request_token}, headers=headers
        )
        if poll.get("result"):
            return _create_result(poll["result"], "execute_dql Metadata (polled):")
        state = poll.get("state")
        if state not in ("RUNNING", "NOT_STARTED"):
            print(f"execute_dql with requestToken {request_token} ended with state {state}, stopping...", file=sys.stderr)
            return None
        if time.monotonic() > deadline:
            try:
                await client.post(f"{QUERY_API}/query:cancel", params={"request-token": request_token})
            except Exception:
                pass
            raise TimeoutError(
                f"DQL query did not finish within {MAX_POLL_SECONDS:.0f} seconds and was cancelled. "
                "Narrow the timeframe, add filters, or summarize the data to make it faster."
            )
