import pytest

from dynatrace_mcp.config import get_dynatrace_env
from dynatrace_mcp.utils.dql_sanitize import (
    check_timeframe_limit,
    escape_dql_string_value,
    timeframe_to_seconds,
    validate_additional_filter,
    validate_entity_id,
    validate_timeframe,
)
from dynatrace_mcp.utils.entity_types import get_entity_type_from_id
from dynatrace_mcp.utils.http_auth import validate_bearer_token
from dynatrace_mcp.capabilities.queries import generate_dql_search_entity_command, summarize_service_health

ENV = "https://abc12345.apps.dynatrace.com"


# ---------------------------------------------------------------- config


def test_env_requires_dt_environment():
    with pytest.raises(ValueError, match="DT_ENVIRONMENT"):
        get_dynatrace_env({})


@pytest.mark.parametrize(
    "url",
    ["http://abc.apps.dynatrace.com", "https://abc.live.dynatrace.com", "not-a-url"],
)
def test_env_rejects_non_platform_urls(url):
    with pytest.raises(ValueError):
        get_dynatrace_env({"DT_ENVIRONMENT": url})


def test_env_defaults_and_empty_strings():
    env = get_dynatrace_env({"DT_ENVIRONMENT": ENV + "/", "OAUTH_CLIENT_ID": "", "DT_PLATFORM_TOKEN": ""})
    assert env.dt_environment == ENV
    assert env.oauth_client_id is None and env.dt_platform_token is None
    assert env.max_query_timeframe == "30d"


def test_env_max_query_timeframe():
    assert get_dynatrace_env({"DT_ENVIRONMENT": ENV, "MAX_QUERY_TIMEFRAME": "7d"}).max_query_timeframe == "7d"
    for bad in ("30", "7 days", "-1d", "0d"):
        with pytest.raises(ValueError, match="MAX_QUERY_TIMEFRAME"):
            get_dynatrace_env({"DT_ENVIRONMENT": ENV, "MAX_QUERY_TIMEFRAME": bad})


# ---------------------------------------------------------------- DQL sanitizing


@pytest.mark.parametrize("tf", ["24h", "7d", "30m", "1y", "3M"])
def test_valid_timeframes(tf):
    validate_timeframe(tf)


@pytest.mark.parametrize("tf", ["0h", "24", "h", "24h | fetch logs", "1.5h", "24hours"])
def test_invalid_timeframes(tf):
    with pytest.raises(ValueError):
        validate_timeframe(tf)


def test_timeframe_to_seconds():
    assert timeframe_to_seconds("90s") == 90
    assert timeframe_to_seconds("24h") == 86400
    assert timeframe_to_seconds("2w") == 14 * 86400
    assert timeframe_to_seconds("1M") == 30 * 86400
    assert timeframe_to_seconds("1y") == 365 * 86400


def test_timeframe_limit():
    for ok in ("30d", "720h", "4w", "1M", "15m"):
        check_timeframe_limit(ok, "30d")
    for too_long in ("31d", "5w", "2M", "1y", "721h"):
        with pytest.raises(ValueError, match="allowed maximum of 30d"):
            check_timeframe_limit(too_long, "30d")
    with pytest.raises(ValueError, match="Invalid timeframe"):
        check_timeframe_limit("24h | fetch logs", "30d")


def test_validate_entity_id():
    validate_entity_id("SERVICE-1A2B3C4D5E6F7A8B")
    validate_entity_id("PROCESS_GROUP-F84E4759809ADA84")
    validate_entity_id("SERVICE-ABC", expected_prefix="SERVICE")
    for bad in ("service-abc", "SERVICE-", "SERVICE-XYZ", 'SERVICE-1") or true', "SERVICE-1 | fetch logs", ""):
        with pytest.raises(ValueError, match="Invalid entity ID"):
            validate_entity_id(bad)
    with pytest.raises(ValueError, match="not a SERVICE entity ID"):
        validate_entity_id("HOST-ABC", expected_prefix="SERVICE")


def test_summarize_service_health():
    s = summarize_service_health({"response_time": [100_000, None, 300_000], "requests": [10, 5, 30], "failures": [0, None, 3]})
    assert s["avg_response_time_ms"] == 250  # weighted by requests: (100*10 + 300*30) / 40
    assert s["peak_response_time_ms"] == 300
    assert s["requests"] == 45 and s["failures"] == 3
    assert round(s["error_rate_pct"], 2) == 6.67
    assert summarize_service_health({"response_time": [None], "requests": [0], "failures": [0]}) is None
    assert summarize_service_health(None) is None


def test_additional_filter_rejects_pipes_and_newlines():
    validate_additional_filter('dt.entity.host == "HOST-1"')
    for bad in ["a | fetch logs", "a\nb", "a\rb"]:
        with pytest.raises(ValueError):
            validate_additional_filter(bad)


def test_escape_dql_string_value():
    assert escape_dql_string_value('a"b\\c\nd') == 'a\\"b\\\\c\\nd'


def test_entity_search_dql_escapes_names():
    dql = generate_dql_search_entity_command(['my"svc'], extended_search=False)
    assert dql.startswith('fetch dt.entity.application | search "*my\\"svc*"')
    assert "| append [ fetch dt.entity.service" in dql


# ---------------------------------------------------------------- entity types


def test_entity_type_from_id():
    assert get_entity_type_from_id("PROCESS_GROUP-F84E4759809ADA84") == "dt.entity.process_group"
    assert get_entity_type_from_id("KUBERNETES_SERVICE-AB") == "dt.entity.kubernetes_service"
    assert get_entity_type_from_id("INVALID") is None
    assert get_entity_type_from_id("UNKNOWN-123") is None


# ---------------------------------------------------------------- http auth


def test_bearer_token_validation():
    assert validate_bearer_token("Bearer secret", "secret")
    assert not validate_bearer_token("Bearer wrong", "secret")
    assert not validate_bearer_token("secret", "secret")
    assert not validate_bearer_token(None, "secret")

