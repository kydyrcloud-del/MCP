"""Input validation for values embedded into DQL statements."""

from __future__ import annotations

import re

# Valid DQL duration units: s, m, h, d, w, M (months), y
_TIMEFRAME_PATTERN = re.compile(r"^[1-9]\d*[smhdwMy]$")
# Seconds per unit. Months and years are approximated (30 and 365 days); only used for the length cap.
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400, "M": 30 * 86400, "y": 365 * 86400}


def validate_timeframe(value: str) -> None:
    """Raise ValueError unless value looks like '24h', '7d', '30m', ..."""
    if not _TIMEFRAME_PATTERN.fullmatch(value):
        raise ValueError(
            f'Invalid timeframe "{value}". Expected a number followed by a unit (s/m/h/d/w/M/y), e.g. "24h" or "7d".'
        )


def timeframe_to_seconds(value: str) -> int:
    """Length of a timeframe like '24h' in seconds. Raises ValueError for invalid timeframes."""
    validate_timeframe(value)
    return int(value[:-1]) * _UNIT_SECONDS[value[-1]]


def check_timeframe_limit(value: str, max_timeframe: str) -> None:
    """Raise ValueError if the timeframe is invalid or longer than max_timeframe."""
    if timeframe_to_seconds(value) > timeframe_to_seconds(max_timeframe):
        raise ValueError(
            f'Timeframe "{value}" is longer than the allowed maximum of {max_timeframe} '
            "(MAX_QUERY_TIMEFRAME). Use a shorter timeframe."
        )


# Dynatrace entity IDs: an upper-case type prefix and a hex ID, e.g. SERVICE-1A2B3C4D5E6F7A8B
_ENTITY_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*-[0-9A-F]{1,32}$")


def validate_entity_id(value: str, expected_prefix: str | None = None) -> None:
    """Raise ValueError unless value is a Dynatrace entity ID (optionally of one type, e.g. SERVICE)."""
    if not _ENTITY_ID_PATTERN.fullmatch(value):
        raise ValueError(
            f'Invalid entity ID "{value}". Expected something like "SERVICE-1A2B3C4D5E6F7A8B". '
            "Use find_entity_by_name to look up the ID."
        )
    if expected_prefix and not value.startswith(expected_prefix + "-"):
        raise ValueError(f'"{value}" is not a {expected_prefix} entity ID (expected "{expected_prefix}-...").')


def validate_additional_filter(value: str) -> None:
    """Reject pipes and newlines so a filter cannot inject additional pipeline stages."""
    if re.search(r"[|\n\r]", value):
        raise ValueError("additionalFilter must not contain pipe (|) or newline characters.")


def escape_dql_string_value(value: str) -> str:
    """Escape a value for safe embedding inside a DQL double-quoted string literal."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
