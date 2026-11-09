# Dynatrace MCP Server (Python)

A Model Context Protocol (MCP) server that lets AI assistants and agents query and act on a Dynatrace environment. It runs locally next to an AI client (stdio), or as a shared HTTP service behind Azure API Management with Microsoft Entra ID sign-in and per-tool authorization.

It offers 9 read-only tools for querying problems, vulnerabilities, exceptions, deployments, entities and service health, and verifying DQL.

**Contents**

1. [What is MCP?](#1-what-is-mcp)
2. [What this project contains](#2-what-this-project-contains)
3. [Tools](#3-tools)
4. [How it works](#4-how-it-works)
5. [Code walkthrough](#5-code-walkthrough)
6. [Configuration reference](#6-configuration-reference)
7. [Running in stdio mode (local)](#7-running-in-stdio-mode-local)
8. [Running in HTTP mode](#8-running-in-http-mode)
9. [Production setup: Copilot → APIM → Container Apps → Dynatrace](#9-production-setup-copilot--apim--container-apps--dynatrace)
10. [Operations: logs, exit codes, troubleshooting](#10-operations-logs-exit-codes-troubleshooting)
11. [Development](#11-development)

---

## 1. What is MCP?

The [Model Context Protocol](https://modelcontextprotocol.io) is an open standard for connecting AI applications to external systems. It defines three roles:

| Role | What it is | Example |
|---|---|---|
| **Host / client** | The AI application the user talks to. It decides when to call a tool. | Claude Code, Claude Desktop, VS Code, Cursor, Microsoft Copilot Studio |
| **Server** | A program that exposes **tools** (functions the model can call) with a name, a description and a JSON schema for the arguments. | This project |
| **Backend** | The system the server talks to on the model's behalf. | Dynatrace Grail |

Messages are JSON-RPC 2.0. The calls that matter here are:

- `initialize`: the client and server agree on protocol version and capabilities.
- `tools/list`: the server returns the tools it offers. The model reads the descriptions to decide what to call.
- `tools/call`: the client calls one tool with arguments, and the server returns the result as text.

MCP has two standard transports, and this server supports both:

- **stdio**: the client starts the server as a child process and talks over stdin/stdout. It's single-user and local, and needs no network or login to the server itself.
- **Streamable HTTP**: the server listens on `POST /mcp`. Many users can share one deployment, so the server must authenticate callers.

Example: a user asks *"Are there any open problems in production?"*. The model calls `list_problems` with `{"status": "ACTIVE"}`. The server runs a DQL query against Dynatrace Grail and returns a formatted list, and the model summarizes it.

---

## 2. What this project contains

```
dynatrace-mcp-main-python/
├── pyproject.toml           package metadata, dependencies, `dynatrace-mcp-python` entry point
├── uv.lock                  pinned dependency versions
├── Dockerfile               container image (HTTP mode on port 8000 by default)
├── .env.template            every environment variable, with examples
├── src/dynatrace_mcp/
│   ├── __main__.py          `python -m dynatrace_mcp`
│   ├── server.py            all 9 tools, the Runtime, CLI arguments, startup checks, stdio/HTTP launch
│   ├── config.py            reads and validates every environment variable
│   ├── http_app.py          HTTP transport: health, gateway check, token check, role gate
│   ├── client.py            small authenticated HTTP client for the Dynatrace Platform API
│   ├── auth/                how the server authenticates to Dynatrace
│   │   ├── __init__.py      picks platform token / client credentials / browser login, caches tokens
│   │   ├── oauth.py         SSO discovery, token endpoint, PKCE authorization-code flow
│   │   └── token_cache.py   stores browser-login tokens in the OS keychain or a file
│   ├── security/            how callers authenticate to this server, and what they may do
│   │   ├── entra.py         Microsoft Entra ID JWT validation
│   │   ├── caller.py        the `Caller` identity attached to each request
│   │   ├── roles.py         roles and the tool → role policy
│   │   ├── middleware.py    filters tools/list and blocks forbidden tools/call
│   │   └── audit.py         one JSON audit line per tool call
│   ├── capabilities/        the Dynatrace API logic behind the tools
│   │   ├── execute_dql.py   run, poll, cancel and verify DQL queries
│   │   └── queries.py       fixed DQL queries (problems, vulnerabilities, exceptions, deployments, entities, service health)
│   └── utils/
│       ├── dql_sanitize.py  validates and escapes values put into DQL (timeframes, filters, entity IDs); timeframe cap
│       ├── entity_types.py  maps entity ID prefixes (HOST-, SERVICE-, ...) to entity types
│       └── http_auth.py     constant-time static bearer check, request body limit
└── tests/                   48 tests, with the Dynatrace API mocked by respx
```

### Libraries used

| Library | Used for |
|---|---|
| [`mcp`] | MCP server, tool registration, stdio and Streamable HTTP transports, middleware |
| `httpx` | All HTTP calls to Dynatrace and SSO (honors `HTTPS_PROXY` / `NO_PROXY`) |
| `pydantic` | Tool argument schemas and validation |
| `pyjwt[crypto]` | Entra ID token signature and claim validation, JWKS key fetching |
| `starlette` + `uvicorn` | ASGI app and web server for HTTP mode |
| `keyring` | Stores browser-login tokens in the macOS Keychain, Windows Credential Manager or Secret Service |
| `pytest`, `pytest-asyncio`, `respx` (dev) | Tests, with a mocked Dynatrace API |

Tooling: Python 3.12+, [uv](https://docs.astral.sh/uv/) for dependency management and running.

---

## 3. Tools

Each tool needs one of the listed roles (see [roles](#roles-and-tool-authorization)) and the listed Dynatrace OAuth scopes. Every tool also needs `app-engine:apps:run`.

### Read tools: bounded queries and metadata

| Tool | What it does | Roles | Dynatrace scopes |
|---|---|---|---|
| `get_environment_info` | Shows environment (tenant) details and confirms the connection works | Read, Query, Admin | – |
| `list_problems` | Problems (issues Dynatrace detected automatically) by `timeframe`, `status` (ACTIVE/CLOSED/ALL), optional DQL filter | Read, Query, Admin | `storage:events:read`, `storage:buckets:read` |
| `list_vulnerabilities` | Active, non-muted vulnerabilities above a `riskScore` | Read, Query, Admin | `storage:events:read`, `storage:buckets:read`, `storage:security.events:read` |
| `list_exceptions` | Application exceptions (user events) | Read, Query, Admin | `storage:user.events:read`, `storage:buckets:read` |
| `find_entity_by_name` | Looks up entity IDs and types by name (service, host, process group, ...) | Read, Query, Admin | `storage:entities:read`, `storage:smartscape:read` |
| `verify_dql` | Checks DQL syntax without running the query | Read, Query, Admin | – |
| `list_deployments` | Deployment events (releases, version changes), optionally for one entity | Read, Query, Admin | `storage:events:read`, `storage:buckets:read` |
| `get_entity_details` | Properties and relationships (calls, runs on, ...) of one entity | Read, Query, Admin | `storage:entities:read`, `storage:smartscape:read` |
| `get_service_health` | Response time, requests, failures and error rate of one service, compared with the day before | Read, Query, Admin | `storage:metrics:read` |

### Tool reference

This section describes each tool in detail: what it's for, its parameters, what it does in Dynatrace, and what it returns.

A few things are the same for every tool:

- **Output is text for the model.** Each tool returns a formatted text answer. Most answers end with **Next Steps**: suggested follow-up tool calls and ready-made DQL queries, so the model knows how to dig deeper.
- **Errors come back as tool errors.** A Dynatrace API error or bad input becomes an MCP tool error with the message, and the server keeps running (`guarded` in `server.py`).
- **Fixed-query tools use DQL underneath.** Every tool except `get_environment_info` and `verify_dql` builds a fixed DQL query (`capabilities/queries.py`) and run it through the Grail query API (`capabilities/execute_dql.py`).
- **Timeframes** are a number plus a unit: `s`, `m`, `h`, `d`, `w`, `M` (months) or `y`, for example `30m`, `24h`, `7d`. Anything else is rejected. Timeframes longer than `MAX_QUERY_TIMEFRAME` (default `30d`) are rejected too.
- **Entity IDs** (`entityId`, `serviceId`) must look like `SERVICE-1A2B3C4D5E6F7A8B`: an upper-case type and a hex ID. Anything else is rejected before a query is built.
- **`additionalFilter`** is one DQL filter condition added as `| filter <your filter>`. It may not contain `|` or newlines, so it can't add extra query stages.

A typical investigation chains the tools: `find_entity_by_name` → `get_entity_details` → `list_problems` with the entity filter → `get_service_health` (is it slower than yesterday?) → `list_deployments` (what changed?).

#### `get_environment_info`

Checks that the server can reach Dynatrace and shows which environment it is connected to. Use it first when something isn't working.

- **Parameters:** none.
- **How it works:** calls `GET /platform/management/v1/environment`.
- **Returns:** the environment details as JSON (environment ID, state, and so on) and the environment URL.

#### `list_problems`

Lists problems: issues that Dynatrace detected automatically, such as a slow service, a high error rate or a host that's down. The newest come first.

| Parameter | Default | Meaning |
|---|---|---|
| `timeframe` | `24h` | How far back to look |
| `status` | `ALL` | `ACTIVE` (still open), `CLOSED` (resolved) or `ALL` |
| `additionalFilter` | – | For example `dt.entity.service == "SERVICE-1234"` or `entity_tags == array("dt.owner:team-a")` |
| `maxProblemsToDisplay` | `10` | How many problems to show (1 to 5000) |


- **How it works:** runs `fetch dt.davis.problems`, drops duplicate problems, keeps open problems (no `event.end`) or closed ones depending on `status`, and calculates the duration and the number of affected entities, events and users. Results are sorted by start time, newest first.
- **Returns:** one line per problem: display ID (for example `P-12345`), problem ID, status, category, name, affected users, affected entities and duration. Next Steps include a DQL query for full details (root cause, Kubernetes and cloud fields) and a link to the problem in the Dynatrace UI.
- **Example:** *"Are there open problems on the checkout service?"* → `{"status": "ACTIVE", "additionalFilter": "dt.entity.service == \"SERVICE-ABC\""}`

#### `list_vulnerabilities`

Lists open security vulnerabilities (for example CVEs in third-party libraries) that Dynatrace found in monitored software. Muted and resolved ones are left out.

| Parameter | Default | Meaning |
|---|---|---|
| `timeframe` | `30d` | How far back to look |
| `riskScore` | `8.0` | Minimum Dynatrace risk score (0–10). `8.0` and up is roughly high and critical. |
| `additionalFilter` | – | For example `vulnerability.risk.level == "CRITICAL"`, `vulnerability.stack == "CODE_LIBRARY"` or `affected_entity.name contains "payment"` |
| `maxVulnerabilitiesToDisplay` | `25` | How many to show |

- **How it works:** runs `fetch security.events` on the built-in security events bucket for vulnerability state reports. It keeps only the latest report per vulnerability and affected entity, then keeps open vulnerabilities at or above the risk score, sorted by score (at most 100).
- **Returns:** per vulnerability: title, IDs, risk score and level, affected entity, CVE, mute status and a link. Next Steps include a DQL query for remediation advice, affected processes, hosts and Kubernetes workloads.

#### `list_exceptions`

Lists application errors (exceptions with stack traces) seen by Dynatrace real user monitoring in web and mobile apps. The newest come first.

| Parameter | Default | Meaning |
|---|---|---|
| `timeframe` | `24h` | How far back to look |
| `additionalFilter` | – | For example `error.id == "<id>"`, `dt.rum.application.id == "<id>"` or `os.name == "Android"` |
| `maxExceptionsToDisplay` | `10` | How many to show |

- **How it works:** runs `fetch user.events` and keeps events that have both an `error.id` and a stack trace.
- **Returns:** per exception: time, error type, error ID, operating system, application and the exception message. Next Steps include a DQL query that returns every occurrence with its full stack trace, and a link to the Dynatrace Error Inspector.

#### `find_entity_by_name`

Finds the Dynatrace entity ID and type for a name, such as a service, host, process group, application or Kubernetes node. Most other tools and DQL queries need the ID, so this is usually the first call when the user names a system.

| Parameter | Default | Meaning |
|---|---|---|
| `entityNames` | required | One or more names. Matching is partial (`*name*`). |
| `maxEntitiesToDisplay` | `10` | How many matches to show |
| `extendedSearch` | `false` | `true` searches every entity type, not just the common ones |

- **How it works:** first searches Smartscape (`smartscapeNodes "*" | search ...`). If that finds nothing or isn't available in the environment, it searches the classic entity tables (`fetch dt.entity.service`, `dt.entity.host`, ...) for 24 common types, or for all types with `extendedSearch`.
- **Returns:** per match: name, type, entity ID, tags, and a ready-to-use DQL filter such as `| filter dt.entity.service == "SERVICE-1234"`. Paste that filter into `list_problems` or `list_vulnerabilities`.

#### `verify_dql`

Checks whether a DQL query is valid without running it. It costs nothing.

- **Parameters:** `dqlStatement`, the query to check.
- **How it works:** calls the Grail `query:verify` endpoint.
- **Returns:** valid or invalid, plus any warnings or errors from Dynatrace explaining what to fix.

#### `list_deployments`

Lists deployment events, newest first, so the model can answer "what changed?", for example just before a problem started.

| Parameter | Default | Meaning |
|---|---|---|
| `timeframe` | `24h` | How far back to look |
| `entityId` | – | Only deployments that affect this entity, e.g. `SERVICE-1A2B3C4D5E6F7A8B` |
| `additionalFilter` | – | Extra DQL filter on the events |
| `maxDeploymentsToDisplay` | `10` | How many to show (1 to 50) |

- **How it works:** runs `fetch events` and keeps events whose `event.type` contains "deployment". The stored type differs between sources (Events API, SDLC events, changes OneAgent detects), so it matches the word rather than one exact value. With `entityId`, it keeps events where the entity is in `affected_entity_ids` or is the `dt.source_entity`.
- **Returns:** per deployment: time, event type, name, and every other non-empty field (version, project, source entity, ...). Field names depend on how your deployments are sent to Dynatrace.
- **Check in your environment:** if nothing shows up, run `fetch events | summarize count(), by:{event.type}` in a Dynatrace notebook to see how your deployment events are stored.

#### `get_entity_details`

Shows one entity's properties and its relationships: which services it calls or is called by, which host or process it runs on, and so on.

| Parameter | Default | Meaning |
|---|---|---|
| `entityId` | required | ID from `find_entity_by_name`, e.g. `SERVICE-1A2B3C4D5E6F7A8B` |
| `maxRelationshipsToDisplay` | `50` | How many relationships to show (1 to 200) |

- **How it works:** looks up the node with `smartscapeNodes "*" | filter id == toSmartscapeId("<id>")` and its relationships with `smartscapeEdges` (up to 200). If Smartscape isn't available, it falls back to the classic entity table (`fetch dt.entity.<type>`), which has properties and tags but no relationships.
- **Returns:** all non-empty properties of the entity, and one line per relationship: type, source and target.

#### `get_service_health`

Gives concrete numbers for one service: how fast it is, how much traffic it has and how often it fails, and how that compares with the same time yesterday.

| Parameter | Default | Meaning |
|---|---|---|
| `serviceId` | required | A `SERVICE-...` ID from `find_entity_by_name` |
| `timeframe` | `2h` | Window to analyse, e.g. `30m`, `2h`, `24h` |
| `compareToPreviousDay` | `true` | Also query the same window one day earlier |

- **How it works:** runs a `timeseries` query on `dt.service.request.response_time`, `dt.service.request.count` and `dt.service.request.failure_count`, filtered on the service. With the comparison on, it runs the same query shifted back one day (`from: now()-1d-2h, to: now()-1d`).
- **Returns:** a table with average response time (weighted by requests per interval), the slowest interval's average, requests, failures and error rate. With the comparison, it also shows the earlier values and the change in percent. Response times are converted from microseconds to milliseconds.
- **Cost:** two metric queries per call with the comparison on, one without.

---

## 4. How it works

### Request flow

```
 MCP client ──JSON-RPC──▶ transport ──▶ AuthorizationMiddleware ──▶ tool function ──▶ capabilities/* ──▶ DynatraceClient ──HTTPS──▶ Dynatrace
 (stdio or HTTP)          (stdio / http_app)   role check + audit       (server.py)      (DQL queries)         (bearer token)
```

1. **Transport.** In stdio mode the caller is the local user and has the roles in `MCP_STDIO_ROLES` (all roles by default). In HTTP mode, `http_app.py` checks the request in this order:
   1. `GET /health` returns 200 with no checks, for container probes.
   2. If `MCP_UPSTREAM_SECRET` is set, the request must carry the gateway secret header, or it gets 403.
   3. `GET /.well-known/oauth-protected-resource/...` returns OAuth discovery metadata (Entra mode).
   4. A bearer token is required: an Entra ID JWT, or the static `MCP_BEARER_TOKEN`. Otherwise 401.
   5. The caller must hold at least one known role (`MCP_REQUIRE_ROLE`). Otherwise 403.
   6. The caller identity is attached to the request and passed to the MCP app.
2. **Authorization middleware** runs for every MCP request:
   - `tools/list` returns only the tools the caller may use.
   - `tools/call` for a tool the caller may not use returns `Forbidden: ...` without running it.
   - Every call (allowed, failed or forbidden) is written to the audit log.
3. **The tool function** in `server.py` asks the `Runtime` for a Dynatrace client with the scopes it needs, calls a capability function, and formats the result as text for the model.
4. **Dynatrace authentication** uses one service identity: a platform token, an OAuth client, or the local user's browser login. Dynatrace therefore sees the server, not the end user. The audit log is the record of who did what.

### Two separate authentication layers

| Layer | Question it answers | Configured with |
|---|---|---|
| Caller → this server (HTTP only) | Who is calling, and which tools may they use? | `MCP_AUTH_MODE`, `ENTRA_*` or `MCP_BEARER_TOKEN`, `MCP_TOOL_ROLES` |
| This server → Dynatrace | How does the server prove itself to Dynatrace? | `DT_PLATFORM_TOKEN`, or `OAUTH_CLIENT_ID` + `OAUTH_CLIENT_SECRET` |

### Safety limits built in

- **Timeframe cap.** `list_problems`, `list_vulnerabilities`, `list_exceptions`, `list_deployments` and `get_service_health` reject timeframes longer than `MAX_QUERY_TIMEFRAME` (default `30d`) before anything is sent to Dynatrace. Grail bills by data scanned, and the timeframe is what drives it, so this bounds the cost of each query. Months and years count as 30 and 365 days.
- **DQL timeout.** Queries that are still running after `DQL_MAX_POLL_SECONDS` are cancelled in Dynatrace.
- **DQL injection protection.** Timeframes are validated (`24h`, `7d`, ...), entity IDs must match `TYPE-HEXID`, and additional filters may not contain `|` or newlines. Entity names are escaped before they're put into a query.
- **Request limits (HTTP).** Request bodies are capped at 1 MiB, the server handles at most 100 concurrent connections, and the `Host` header is checked to block DNS rebinding.
- **Rate limiting** is deliberately left to the gateway (APIM).

---

## 5. Code walkthrough

### `server.py`: tools, runtime and startup

- **Scope constants.** `SCOPES_BASE` and `ALL_REQUIRED_SCOPES` list the OAuth scopes. Each tool requests only the scopes it needs. The browser login requests all scopes at once, so one login covers every tool.
- **`Runtime`** holds the shared state:
  - `env` (Dynatrace settings), `security` (caller settings), `policy` (`ToolPolicy`) and `audit` (`AuditLogger`).
  - `default_caller`: the stdio user in stdio mode, or `ANONYMOUS` (no roles) in HTTP mode. If a request somehow arrives in HTTP mode without an authenticated caller, it is denied.
  - `client(scopes)` returns an authenticated `DynatraceClient`.
- **`guarded`** is a decorator on every tool. It turns Dynatrace API errors and unexpected exceptions into MCP tool errors (`isError: true`) the model can read, instead of protocol failures.
- **`build_server(rt)`** creates the `MCPServer` with the `AuthorizationMiddleware` and registers the 9 tools with `@mcp.tool(...)`. Each tool has a description (what the model reads), annotations (`read_only_hint`, ...) and typed parameters, from which pydantic builds the JSON schema.
- **`main()`**:
  1. Parses arguments (`--http`, `--host`, `--port`, `--oauth-redirect-port`).
  2. Loads and validates config. Exits with code 1 on errors.
  3. In HTTP mode, refuses to start with the browser login (it needs a person at the machine).
  4. Applies the DQL timeout and logs the security setup.
  5. Runs `check_connection`: is the environment reachable (exit 3), and do the credentials work (exit 2)?
  6. Starts stdio, or uvicorn with the `http_app`.

### `config.py`: environment validation

- `get_dynatrace_env()` returns a `DynatraceEnv`. It validates that `DT_ENVIRONMENT` is an `https://<id>.apps.dynatrace.com` platform URL, and checks the timeout and `MAX_QUERY_TIMEFRAME` values. Empty strings count as "unset", because some MCP clients send blank fields.
- `get_security_settings(http_mode=...)` returns a `SecuritySettings`. In HTTP mode it chooses `entra` or `bearer` and validates the Entra tenant GUID, audience, header names, secret lengths and the `MCP_TOOL_ROLES` JSON. Unknown tool names are rejected.
- All errors are raised as `ValueError` with a message saying what to set.

### `http_app.py`: HTTP transport and the authentication gate

- `build_http_app()` wraps the SDK's stateless Streamable HTTP app in an ASGI function that implements the checks from [request flow](#request-flow).
- `make_authenticator()` returns an async function that turns the `Authorization` header into a `Caller`, or raises `AuthenticationError` (401) or `AuthenticationUnavailable` (503, when Entra signing keys can't be fetched).
- `401` responses include a `WWW-Authenticate` header with `resource_metadata=...`, so OAuth-capable MCP clients can discover where to sign in (RFC 9728).
- `allowed_hosts_for()` builds the `Host` allow-list from localhost, the bind address and `MCP_ALLOWED_HOSTS`.

### `security/`: who the caller is and what they may do

- **`entra.py` (`EntraTokenVerifier`)**
  - Fetches the tenant's signing keys (JWKS), caches them for one hour, and re-fetches on an unknown key ID (key rotation).
  - Checks the RS256 signature, `exp`, `aud` (`ENTRA_AUDIENCE`), `iss` (v1 and v2 issuers), `tid`, and optionally the calling app (`azp`/`appid` against `ENTRA_ALLOWED_CLIENT_IDS`).
  - Builds a `Caller` from `oid`, `preferred_username`/`upn` and `roles`, and records whether it's a user token or an app-only token.
- **`caller.py`** defines the frozen `Caller` dataclass and a context variable so any tool can call `get_current_caller()`. For example, the audit log records `caller.id`.
- **`roles.py`** defines the four roles, groups the tools into READ/ADMIN, and provides `ToolPolicy` (with optional `MCP_TOOL_ROLES` overrides). Tools not in the policy are denied.
- **`middleware.py`** applies the policy to `tools/list` and `tools/call`, and times and audits each call.
- **`audit.py`** writes `AUDIT {...json...}` lines to stderr. The `body` and `message` arguments are replaced by their length, and long strings are truncated.

### `auth/`: how the server authenticates to Dynatrace

- `create_dt_client()` chooses, in order:
  1. `DT_PLATFORM_TOKEN`: sent as is.
  2. `OAUTH_CLIENT_ID` + `OAUTH_CLIENT_SECRET`: client-credentials grant. Tokens are cached per client and scope set until 30 seconds before they expire.
  3. `OAUTH_CLIENT_ID` alone: browser login (authorization code + PKCE). With nothing configured, the built-in public client `dt0s12.local-dt-mcp-server` is used.
- `oauth.py`:
  - Discovers the SSO URL by following the environment's login redirect (override with `DT_SSO_URL`).
  - Runs a short-lived `localhost:5344–5349` callback server for the browser login and checks the `state` parameter against CSRF.
  - Supports GitHub Codespaces port forwarding.
- `token_cache.py` stores browser-login tokens (with refresh token) in the OS keychain, or in `~/.config/dynatrace-mcp/token-*.json` (mode 0600) when `DT_MCP_TOKEN_STORAGE=file`. A per-account lock stops parallel tool calls from refreshing at the same time, because refresh tokens can only be used once.

### `capabilities/`: Dynatrace API logic

- **`execute_dql.py`**
  - Sends `POST /platform/storage/query/v1/query:execute`.
  - If the result isn't ready, polls `query:poll` every 2 seconds until it finishes, fails, or hits `MAX_POLL_SECONDS`, then calls `query:cancel`.
  - Logs `scannedBytes`, scanned records and execution time of each query to stderr.
- **`queries.py`** builds fixed, parameterized DQL for problems, vulnerabilities, exceptions and entity search, using the validators in `utils/dql_sanitize.py`.

### `client.py`

`DynatraceClient` is a thin `httpx` wrapper bound to one environment and one bearer token. It sets `User-Agent: dynatrace-mcp-server-python/vX (...)` and raises `DynatraceApiError(status, message, body)` on unexpected status codes. There is no official Python SDK for these platform APIs, so this client covers what the tools need.

---

## 6. Configuration reference

All configuration is through environment variables. Copy [.env.template](.env.template) as a starting point. Empty values count as unset.

### Dynatrace connection

| Variable | Required | Default | What to set |
|---|---|---|---|
| `DT_ENVIRONMENT` | **yes** | – | Your platform URL: `https://<environment-id>.apps.dynatrace.com` (or `...apps.dynatracelabs.com`). Classic `*.live.dynatrace.com` URLs are rejected. |
| `DT_PLATFORM_TOKEN` | one auth option | – | A Dynatrace platform token (`dt0s16.…`) with the scopes from [Tools](#3-tools). Simplest option, and suitable for HTTP mode. |
| `OAUTH_CLIENT_ID` | one auth option | – | Dynatrace OAuth client ID (`dt0s02.…`). On its own: browser login with that client. With the secret: client credentials. |
| `OAUTH_CLIENT_SECRET` | with `OAUTH_CLIENT_ID` | – | Secret for the OAuth client. **Recommended for HTTP mode.** In Azure, store it in Key Vault. |
| `DT_SSO_URL` | no | auto-detected | Override the SSO base URL (e.g. `https://sso.dynatrace.com`). Only needed if discovery fails, for example behind a proxy. |
| `DT_MCP_TOKEN_STORAGE` | no | keychain | `file` stores browser-login tokens in `~/.config/dynatrace-mcp/` instead of the OS keychain. Stdio only. |
| `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` | no | – | Outbound proxy for Dynatrace calls. Both are honored. |

If no Dynatrace credentials are set, stdio mode uses the browser login. HTTP mode refuses to start.

### Limits

| Variable | Default | What to set |
|---|---|---|
| `MAX_QUERY_TIMEFRAME` | `30d` | Longest timeframe the query tools accept, e.g. `7d`, `2w`, `720h`. Longer requests are rejected with an error. |
| `DQL_MAX_POLL_SECONDS` | `600` stdio, `60` HTTP | How long to wait for a DQL query before cancelling it. In HTTP mode, keep it below your gateway's and client's timeouts. |

### Server and transport (HTTP mode)

| Variable | Default | What to set |
|---|---|---|
| `MCP_HOST` / `--host` | `127.0.0.1` | Bind address. Use `0.0.0.0` in containers (the Dockerfile already does). |
| `MCP_PORT` / `--port` | `3000` | Listen port. The container uses `8000`. |
| `MCP_ALLOWED_HOSTS` | localhost + bind address | Extra accepted `Host` header values, comma-separated, e.g. your Container App FQDN. `*` turns the check off. |
| `MCP_ALLOWED_ORIGINS` | – | Accepted browser `Origin` values, if browsers call the server directly. |
| `MCP_PUBLIC_URL` | – | The URL clients use, e.g. `https://my-apim.azure-api.net/dynatrace/mcp`. Enables `/.well-known/oauth-protected-resource` and the `resource_metadata` hint in 401 responses. |
| `MCP_UPSTREAM_SECRET` | – | Shared secret that the gateway adds to every request (≥ 16 chars; `openssl rand -base64 32`). When set, requests without it get 403 (except `/health`), so nobody can skip APIM. |
| `MCP_UPSTREAM_SECRET_HEADER` | `x-from-apim` | Name of the header that carries the secret. |
| `MCP_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies whose `X-Forwarded-For` / `X-Forwarded-Proto` headers are trusted. Comma-separated IPs or CIDRs, or `*`. Only affects logged client IPs and the request scheme. |

### Caller authentication (HTTP mode)

| Variable | Default | What to set |
|---|---|---|
| `MCP_AUTH_MODE` | `entra` if `ENTRA_TENANT_ID` is set, otherwise `bearer` | `entra` (Microsoft Entra ID tokens) or `bearer` (one shared static token). Set it explicitly in production. |
| `MCP_BEARER_TOKEN` | – | **bearer mode:** the shared token (≥ 16 chars). Every request needs `Authorization: Bearer <token>`. |
| `MCP_BEARER_ROLES` | all roles | **bearer mode:** roles given to whoever holds the token, e.g. `Dynatrace.Read,Dynatrace.Query`. |
| `ENTRA_TENANT_ID` | – | **entra mode:** your tenant ID (GUID). |
| `ENTRA_AUDIENCE` | – | **entra mode:** accepted `aud` values, comma-separated. Use both the Application ID URI and the client ID of the API app registration, e.g. `api://dynatrace-mcp,11111111-2222-3333-4444-555555555555`. |
| `ENTRA_ISSUERS` | v1 + v2 issuers of the tenant | Override accepted `iss` values. Rarely needed. |
| `ENTRA_ALLOWED_CLIENT_IDS` | any client | Client IDs (`azp`/`appid`) of apps allowed to call the server, e.g. the app registration Copilot uses. Recommended. |
| `ENTRA_SCOPES` | – | Scopes advertised in the discovery metadata, e.g. `api://dynatrace-mcp/access_as_user`. |

### Authorization and audit

| Variable | Default | What to set |
|---|---|---|
| `MCP_REQUIRE_ROLE` | `true` | Reject callers (403) who hold none of the Dynatrace MCP roles. Keep it on. |
| `MCP_TOOL_ROLES` | built-in policy | JSON that overrides which roles may call a tool, e.g. `{"list_problems": ["Dynatrace.Read","Dynatrace.Query"]}`. Unknown tool names are rejected at startup. |
| `MCP_STDIO_ROLES` | all roles | Roles of the local user in stdio mode, e.g. `Dynatrace.Read` for a read-only setup. |
| `MCP_AUDIT_LOG` | `true` | Write an `AUDIT` JSON line per tool call to stderr. |
| `MCP_AUDIT_LOG_ARGS` | `true` | Include tool arguments in the audit line. `body` and `message` are always redacted. |

### Roles and tool authorization

| Role | Grants |
|---|---|
| `Dynatrace.Read` | Read tools |
| `Dynatrace.Query` | Read tools (query tools are currently removed) |
| `Dynatrace.Write` | Nothing at the moment (write tools are currently removed) |
| `Dynatrace.Admin` | All tools |

In Entra mode, roles come from the token's `roles` claim, so define them as **app roles** on the API app registration and assign them to users or groups.

---

## 7. Running in stdio mode (local)

Stdio is for one person on their own machine. The AI client starts the server as a subprocess.

### Install

```bash
cd dynatrace-mcp-main-python
uv sync
```

### Try it

```bash
DT_ENVIRONMENT=https://<id>.apps.dynatrace.com uv run dynatrace-mcp-python
```

With no credentials set, a browser window opens for the Dynatrace login. The token is saved in your OS keychain, so you only log in once. All logs go to stderr, because stdout carries the MCP protocol.

To use a token or OAuth client instead, add `DT_PLATFORM_TOKEN=...`, or `OAUTH_CLIENT_ID=...` + `OAUTH_CLIENT_SECRET=...`.

### Claude Code

```bash
claude mcp add dynatrace \
  -e DT_ENVIRONMENT=https://<id>.apps.dynatrace.com \
  -- uv run --directory /path/to/dynatrace-mcp-main-python dynatrace-mcp-python
```

### Claude Desktop / VS Code / Cursor (JSON config)

```json
{
  "mcpServers": {
    "dynatrace": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/dynatrace-mcp-main-python", "dynatrace-mcp-python"],
      "env": {
        "DT_ENVIRONMENT": "https://<id>.apps.dynatrace.com",
        "MCP_STDIO_ROLES": "Dynatrace.Read,Dynatrace.Query"
      }
    }
  }
}
```

`MCP_STDIO_ROLES` is optional. Leave it out to allow all tools.

### Docker (stdio)

```bash
docker build -t dynatrace-mcp-python .
docker run -i --rm --entrypoint dynatrace-mcp-python \
  -e DT_ENVIRONMENT=https://<id>.apps.dynatrace.com -e DT_PLATFORM_TOKEN=dt0s16.XXXX \
  dynatrace-mcp-python
```

The browser login doesn't work inside a container, so use a token or client credentials.

---

## 8. Running in HTTP mode

HTTP mode serves many users from one deployment at `POST /mcp` (stateless Streamable HTTP). It needs non-interactive Dynatrace credentials and caller authentication.

### Quick test with a static bearer token

```bash
export DT_ENVIRONMENT=https://<id>.apps.dynatrace.com
export DT_PLATFORM_TOKEN=dt0s16.XXXX
export MCP_AUTH_MODE=bearer
export MCP_BEARER_TOKEN=$(openssl rand -base64 32)

uv run dynatrace-mcp-python --http --port 3000      # endpoint: http://127.0.0.1:3000/mcp
```

```bash
curl http://127.0.0.1:3000/health

curl -X POST http://127.0.0.1:3000/mcp \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Add it to Claude Code:

```bash
claude mcp add --transport http dynatrace http://127.0.0.1:3000/mcp \
  --header "Authorization: Bearer $MCP_BEARER_TOKEN"
```

A static token gives everyone who holds it the same roles (`MCP_BEARER_ROLES`) and the same audit identity. Use Entra mode for shared deployments.

### Entra ID mode

```bash
export MCP_AUTH_MODE=entra
export ENTRA_TENANT_ID=<tenant-guid>
export ENTRA_AUDIENCE=api://dynatrace-mcp,<api-app-client-id>
export ENTRA_ALLOWED_CLIENT_IDS=<client-app-id>
uv run dynatrace-mcp-python --http
```

Callers send `Authorization: Bearer <Entra access token for api://dynatrace-mcp>`. See section 9 for the full Azure setup.

### Docker (HTTP)

The image starts in HTTP mode on port 8000 by default:

```bash
docker run --rm -p 8000:8000 --env-file .env dynatrace-mcp-python
```

### Endpoints

| Method and path | Authentication | Purpose |
|---|---|---|
| `GET /health` | none | `{"status":"ok","uptime":...}` for liveness and readiness probes |
| `GET /.well-known/oauth-protected-resource/<path>` | gateway secret | OAuth discovery metadata (Entra mode with `MCP_PUBLIC_URL`) |
| `POST /mcp` | gateway secret + bearer token + role | MCP JSON-RPC |

### Response codes

| Code | Meaning |
|---|---|
| 401 | Missing, invalid or expired token. The `WWW-Authenticate` header says why. |
| 403 | Missing or wrong gateway secret, or the caller holds no Dynatrace MCP role |
| 421 | `Host` header not allowed (add it to `MCP_ALLOWED_HOSTS`) |
| 503 | Entra signing keys couldn't be fetched (retry) |

---

## 9. Production setup: Copilot → APIM → Container Apps → Dynatrace

```
 Copilot agent ── Entra JWT ──▶ Azure API Management ── JWT + x-from-apim ──▶ Azure Container Apps ── OAuth (client credentials) ──▶ Dynatrace
  (signs the user in)            validate-jwt, rate limit per user             this server: re-validates JWT,
                                                                                tool-level roles, audit, timeframe cap
```

| Component | Responsibility |
|---|---|
| **Copilot agent** | Signs the user in with Entra ID and sends the access token with each MCP request |
| **APIM** | Validates the JWT, rate-limits per user, adds the gateway secret, forwards to ACA |
| **ACA (this server)** | Validates the JWT again (defense in depth, and to read roles), checks the gateway secret, enforces per-tool roles, audits, caps query timeframes |
| **Dynatrace** | Receives calls authenticated with the server's OAuth client |

### Step 1: Dynatrace OAuth clients

In Dynatrace (Account Management → Identity & access management → OAuth clients), create:

- **Read client** with exactly these scopes, and nothing else:
  - `app-engine:apps:run`
  - `storage:buckets:read`
  - `storage:events:read` (problems)
  - `storage:security.events:read` (vulnerabilities)
  - `storage:user.events:read` (exceptions)
  - `storage:entities:read` and `storage:smartscape:read` (entity search and details)
  - `storage:metrics:read` (service health)

The service user behind the client also needs matching Dynatrace policies. Grant read access only to the Grail tables and buckets these tools query (`dt.davis.problems`, `security.events`, `user.events`, events, entities, and the service request metrics), not to logs, spans or business events. Then even a misbehaving query can't read data the tools don't need.

### Step 2: Entra ID app registrations

1. **API app** (represents this server), e.g. `dynatrace-mcp-api`:
   - **Expose an API**: Application ID URI `api://dynatrace-mcp`, and a scope `access_as_user`.
   - **App roles** (allowed member types: Users/Groups, and Applications if you also want app-only callers): `Dynatrace.Read`, `Dynatrace.Query`, `Dynatrace.Write`, `Dynatrace.Admin`.
   - **Manifest**: set `"accessTokenAcceptedVersion": 2`.
   - **Enterprise application → Users and groups**: assign the roles to groups. Users without an assignment get 403.
2. **Client app** (used by Copilot to sign users in):
   - Add a client secret.
   - API permissions: delegated `api://dynatrace-mcp/access_as_user`, then grant admin consent.
   - Add the redirect URI that Copilot Studio shows when you configure OAuth.

### Step 3: Azure Container Apps

Store secrets in Key Vault and give the Container App a managed identity with *Key Vault Secrets User*.

```bash
az containerapp create -n dynatrace-mcp -g <rg> --environment <aca-env> \
  --image <registry>/dynatrace-mcp-python:<tag> \
  --target-port 8000 --ingress internal \
  --min-replicas 1 --max-replicas 1 \
  --user-assigned <identity-resource-id> \
  --secrets \
    "dt-client-secret=keyvaultref:https://<kv>.vault.azure.net/secrets/dt-client-secret,identityref:<identity-resource-id>" \
    "mcp-upstream-secret=keyvaultref:https://<kv>.vault.azure.net/secrets/mcp-upstream-secret,identityref:<identity-resource-id>" \
  --env-vars \
    DT_ENVIRONMENT=https://<id>.apps.dynatrace.com \
    OAUTH_CLIENT_ID=dt0s02.XXXX \
    OAUTH_CLIENT_SECRET=secretref:dt-client-secret \
    MCP_AUTH_MODE=entra \
    ENTRA_TENANT_ID=<tenant-guid> \
    ENTRA_AUDIENCE=api://dynatrace-mcp,<api-app-client-id> \
    ENTRA_ALLOWED_CLIENT_IDS=<client-app-id> \
    MCP_PUBLIC_URL=https://<apim>.azure-api.net/dynatrace/mcp \
    MCP_ALLOWED_HOSTS=<container-app-fqdn> \
    MCP_UPSTREAM_SECRET=secretref:mcp-upstream-secret \
    DQL_MAX_POLL_SECONDS=60
```

- **Ingress:** use `internal` with APIM in the same VNet where possible. The gateway secret is a second layer, not a replacement.
- **Health probes:** set liveness and readiness probes to `GET /health` on port 8000.
- **Logs:** stderr goes to Log Analytics. That includes the `AUDIT` lines.

### Step 4: API Management

Create an API with backend `https://<container-app-fqdn>` and an operation `POST /mcp`.

**Inbound policy** (sketch: adapt names, values and limits):

```xml
<inbound>
  <base />
  <validate-jwt header-name="Authorization" failed-validation-httpcode="401" require-scheme="Bearer">
    <openid-config url="https://login.microsoftonline.com/<tenant-guid>/v2.0/.well-known/openid-configuration" />
    <audiences>
      <audience>api://dynatrace-mcp</audience>
      <audience><api-app-client-id></audience>
    </audiences>
    <issuers>
      <issuer>https://login.microsoftonline.com/<tenant-guid>/v2.0</issuer>
    </issuers>
  </validate-jwt>
  <!-- per user, not per IP: all Copilot traffic comes from Microsoft IP ranges -->
  <rate-limit-by-key calls="60" renewal-period="60"
    counter-key="@(context.Request.Headers.GetValueOrDefault("Authorization","").AsJwt()?.Claims.GetValueOrDefault("oid","anonymous"))" />
  <!-- proves to the server that the request came through APIM -->
  <set-header name="x-from-apim" exists-action="override">
    <value>{{mcp-upstream-secret}}</value>
  </set-header>
  <!-- forward the Authorization header unchanged: the server needs the token for roles -->
</inbound>
<backend>
  <forward-request timeout="120" buffer-response="false" />
</backend>
```

- `{{mcp-upstream-secret}}` is an APIM *named value* backed by the same Key Vault secret as the Container App.
- Keep `forward-request` `timeout` above `DQL_MAX_POLL_SECONDS`.
- `buffer-response="false"` stops APIM from holding back streamed responses.
- APIM only sees `POST /mcp`. For stricter limits on specific tools, read `params.name` from the JSON-RPC body in the policy. Together with the server's timeframe cap (`MAX_QUERY_TIMEFRAME`), the per-user rate limit bounds how much data each user can scan: at most 60 calls a minute, each covering at most 30 days.
- OAuth discovery is optional. To expose it, add a separate operation for `GET /.well-known/oauth-protected-resource/dynatrace/mcp` (at the host root, outside the API base path) **without** `validate-jwt`.

### Step 5: Copilot agent

In Copilot Studio, add an MCP server tool:

- **Server URL:** `https://<apim>.azure-api.net/dynatrace/mcp`
- **Authentication:** OAuth 2.0 with the Entra client app:
  - Client ID and secret from step 2.
  - Authorization URL `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize`.
  - Token and refresh URL `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`.
  - Scope `api://dynatrace-mcp/access_as_user offline_access`.
- Copy the redirect URL Copilot shows into the client app registration.

Each user signs in once. Their token carries their `oid` and `roles`, so each user sees only the tools their roles allow, and every call is audited under their name.

### Replicas and state

The server keeps no per-user state. Each replica caches only its own Dynatrace access token and the Entra signing keys, and fetches them again after a restart. You can run more than one replica. Per-user rate limits live in APIM, so they apply across all replicas. One replica handles up to 100 concurrent connections.

---

## 10. Operations: logs, exit codes, troubleshooting

### Audit log

Each tool call writes one line to stderr:

```
AUDIT {"ts":"2026-11-07T10:15:02Z","event":"tool_call","tool":"list_problems","outcome":"ok","caller_id":"<oid>","caller_name":"jane@contoso.com","auth":"entra","token_type":"user","app_id":"<client-app-id>","roles":["Dynatrace.Read"],"duration_ms":2310.4,"args":{"timeframe":"24h","status":"ACTIVE"}}
```

`outcome` is `ok`, `error` or `forbidden`. In Log Analytics, filter on lines starting with `AUDIT `.

### Exit codes at startup

| Code | Cause |
|---|---|
| 1 | Configuration error (the log says which variable) |
| 2 | Dynatrace rejected the credentials |
| 3 | Dynatrace environment not reachable (network, proxy, wrong URL) |

### Common problems

| Symptom | Fix |
|---|---|
| `421 Misdirected Request` / invalid Host | Add the `Host` value APIM sends (usually the Container App FQDN) to `MCP_ALLOWED_HOSTS` |
| `403 Forbidden` on every request | Check that APIM sends `x-from-apim` with the same value as `MCP_UPSTREAM_SECRET` |
| `401 Token audience is not this MCP server` | Put the token's `aud` value in `ENTRA_AUDIENCE` (both the URI and the client ID are safest) |
| `401 Client application ... is not allowed` | Add the token's `azp` value to `ENTRA_ALLOWED_CLIENT_IDS` |
| `403 caller holds none of the roles` | Assign an app role to the user or group in the Enterprise application, then sign in again |
| A tool is missing from the list | The caller's roles don't allow it; see [Tools](#3-tools) |
| `DQL query did not finish within N seconds` | Narrow the timeframe or add filters, or raise `DQL_MAX_POLL_SECONDS` (and the gateway timeout) |
| `Failed to retrieve OAuth token ... missing scopes` | Add the scopes from [Tools](#3-tools) to the Dynatrace OAuth client |

---

## 11. Development

```bash
uv sync                 # install, including dev dependencies
uv run pytest           # 48 tests: utilities, OAuth flow, HTTP gateway checks, end-to-end tool calls against a mocked API
uv run python -m dynatrace_mcp --help
```

| Test file | Covers |
|---|---|
| `tests/test_server.py` | End-to-end MCP tool calls through a real MCP client, with the Dynatrace API mocked by respx |
| `tests/test_http_app.py` | Gateway secret, header and timeout settings, DQL cancel on timeout |
| `tests/test_oauth.py` | PKCE, the full authorization-code flow, state mismatch, the file token cache |
| `tests/test_utils.py` | Config validation, DQL sanitizing, entity ID check, timeframe cap, service health maths, entity types, bearer check |

**Adding a tool:**

1. Register it in `build_server()` in `server.py` with `@mcp.tool(...)` and `@guarded`.
2. Request only the scopes it needs with `rt.client([...])`.
3. Add the tool name to one of the groups in `security/roles.py`. Tools that aren't in the policy are denied.
