# IRONSCALES MCP Server

An [MCP](https://modelcontextprotocol.io) server for the [IRONSCALES](https://ironscales.com) Management API
(AppAPI v1), the email security platform that turns reported phishing into incidents and
removes malicious emails from every affected mailbox. It lets an AI agent read incidents and
their details, look up what IRONSCALES knows about a sender, read mitigation statistics and the
allow list and, on explicit request, classify incidents (phishing, spam, false positive) and add
or remove allow-list entries.

- Transport: MCP Streamable HTTP at `POST /mcp`, health probe at `GET /health`
- Stateless and multi-tenant: credentials arrive on every request as HTTP headers and are
  never stored; every tool is listed from the first `tools/list`
- Python 3.12, [uv](https://docs.astral.sh/uv/), FastMCP, httpx
- License: Apache-2.0, Copyright 2026 MSPbots.ai

## Authentication headers

| Header | Required | Type | Default | Allowed values | Description | Example |
|---|---|---|---|---|---|---|
| `X-Ironscales-API-Key` | Yes | string | none | - | The company's AppAPI token | `your-api-key` |
| `X-Ironscales-Company-ID` | Yes | integer | none | positive number | IRONSCALES company id the key belongs to | `123456` |
| `X-Ironscales-Scopes` | No | string | `company.all`, then `partner.all` | comma-separated scopes | Token scopes to request when the key does not hold `company.all` | `company.view,company.classify` |

Where to get them: in the IRONSCALES dashboard the key is under **Settings > General > Company
Token**. Scopes available to keys: `company.all`, `company.view`, `company.classify`,
`company.edit` and, for partner keys, `partner.all`, `partner.company.view`,
`partner.company.classify`, `partner.company.edit`, `partner.mitigation.view`.

How they are used: the key is exchanged at `POST https://appapi.ironscales.com/appapi/get-token/`
(`{"key": ..., "scopes": [...]}`) for a JWT, which is sent as `Authorization: JWT <token>`.
Without `X-Ironscales-Scopes` the server asks for `company.all` and, if the key is not allowed
that scope, `partner.all`. Tokens are cached in memory, keyed by a SHA-256 of the key and the
scopes, until shortly before they expire, and refreshed once when the API rejects one.

A request to `/mcp` without both required headers gets HTTP 401 naming the missing one; a
non-numeric company id or a malformed scope list gets HTTP 400.

## Tools

All tools return a JSON string. **write** marks tools that change data; **confirm** marks the
tool that changes mailboxes and also needs `confirm: true`.

| Area | Tools |
|---|---|
| Overview | `ironscales_navigate` (**domain**), `ironscales_back`, `ironscales_status` |
| Incidents | `ironscales_incidents_list` (status, classification, sender_email, recipient_email, subject, created_after, created_before, limit, offset), `ironscales_incidents_get` (**incident_id**) |
| Sender lookup | `ironscales_email_classify` (**sender**, subject, reply_to; past incidents and allow-list entries) |
| Remediation | **confirm**: `ironscales_remediation_act` (**incident_id**, **action**, classifying_user_email) |
| Stats | `ironscales_stats_company` (period: 24h, 7d, 30d, 90d, 180d, 1y, ytd, all) |
| Allow list | **write**: `ironscales_allowlist_manage` (**operation** list / add / remove, entry_type, value, reason, scope, expiration_date) |

Errors come back as a JSON envelope instead of an exception:

```json
{"error": {"code": "unauthorized", "message": "IRONSCALES returned HTTP 403 for get-token: No company found for API key [<redacted>]", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`, `invalid_argument`,
`rate_limited`, `upstream_error`. Reads are retried with backoff on 429, 5xx and network
errors; writes only on 429. IRONSCALES allows 120 API calls per minute per company.

## Run locally

```bash
uv sync
uv run python -m ironscales_mcp          # listens on 0.0.0.0:8080
```

or with Docker:

```bash
docker build --platform linux/amd64 -t ironscales-mcp:dev .
docker run --rm -p 8080:8080 ironscales-mcp:dev
```

Configuration (environment variables, all optional): `MCP_HTTP_HOST` (default `0.0.0.0`),
`MCP_HTTP_PORT` (default `8080`), `LOG_LEVEL` (default `INFO`). Credentials are never read
from the environment.

## Testing example

```bash
# list tools
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Ironscales-API-Key: your-api-key" \
  -H "X-Ironscales-Company-ID: 123456" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# open incidents
curl -s http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Ironscales-API-Key: your-api-key" \
  -H "X-Ironscales-Company-ID: 123456" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ironscales_incidents_list","arguments":{"status":"open","limit":10}}}'
```

Unit tests (no network access needed):

```bash
uv run pytest
```

## Delivery notes

- **Tool count (9).** Kept as is because the tool names are an existing contract.
- **Rebuilt on the documented API.** The official specification is published at
  `https://appapi.ironscales.com/appapi/docs/` (IRONSCALES Management API v1). Older versions
  called `/api/v1/...` routes with `X-IronScales-API-Key` headers, which do not exist (the API
  answers 404); every tool now uses the AppAPI routes with the JWT exchange.
- **Status words.** `open` / `in_progress` list unclassified incidents, `closed` classified ones
  and `pending` challenged ones (release requests and end-user reports). `offset` is rounded down
  to a whole page because the API pages by page number.
- **Remediation is classification.** IRONSCALES acts on an incident by classifying it:
  `quarantine` / `delete` classify it as phishing (the emails are removed from all affected
  mailboxes), `mark_spam` as spam, `mark_false_positive` as a false positive. The API requires the
  analyst's email (`classifying_user_email`) and the current classification, which the tool reads
  first. `block_sender` and `report_to_microsoft` have no API and return an `invalid_argument`
  error. The tool needs `confirm: true`.
- **Sender lookup instead of a scan.** IRONSCALES has no API that scans an arbitrary email, so
  `ironscales_email_classify` returns past incidents from the sender, their classifications and
  matching allow-list entries, with `verdict: null`; body, headers, URLs and attachments are not
  sent anywhere.
- **Stats periods** map to the API's presets; 30 days (the default) uses the date-range email and
  remediation statistics because no preset covers it.
- **Allow-list removal** deletes only entries whose value matches exactly.
- **Parameters the API cannot honour were removed**: `severity` on the incident list, `reason`
  and `notify_users` on remediation.
- **Not included**: the incident "card" UI resource of older versions (an MCP Apps HTML view);
  the tools return the same data as JSON.

## License

Apache License 2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).
