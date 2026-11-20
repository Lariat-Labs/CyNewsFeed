# REST API

All endpoints are under `/api` and return JSON. In Azure they require an Entra session (Easy Auth). Locally they're
open when `AUTH_MODE=none`.

## Stories

| Method & path | Description |
|---|---|
| `GET /api/items` | List: `days`, `category`, `severity` (minimum), `feed`, `tag`, `q`, `rule`, `hits`, `starred`, `unread`, `limit`, `offset` |
| `GET /api/items/{id}` | Story with full text |
| `PATCH /api/items/{id}` | `{read, starred}` |
| `POST /api/items/{id}/summarize` | AI summary now; returns item and token usage |
| `POST /api/items/summarize` | `{ids: [...]}` (max 25) |
| `POST /api/items/{id}/detections` | `{formats: ["kql","spl","sigma","yara"]}` |

## Sources, rules, alerts

| Method & path | Description |
|---|---|
| `GET/POST /api/feeds`, `PUT/DELETE /api/feeds/{id}` | Source CRUD |
| `POST /api/feeds/test` | Validate a feed URL with a preview |
| `POST /api/feeds/seed` | Add missing built-in sources |
| `GET/POST /api/rules`, `PUT/DELETE /api/rules/{id}` | Rule CRUD (webhooks masked) |
| `POST /api/rules/test` | Back-test an unsaved rule: `{…rule, days}` |
| `GET /api/alerts?days=` | Alert history |

## Intel

| Method & path | Description |
|---|---|
| `GET /api/iocs` | Aggregated IOCs: `days`, `type` (`ip`, `domain`, `url`, `hash`, …), `min_severity`, `q` |
| `GET /api/iocs/export` | `format=stix\|csv\|txt`, same filters, plus `items=id1,id2`, `defang=true` |
| `POST /api/iocs/misp` | `{days, minSeverity, type, itemIds}` |
| `GET /api/events?days=` | Multi-source events |
| `GET /api/trends?days=` | Rising entities |
| `GET /api/frameworks?days=` | ATT&CK / ATLAS / OWASP coverage |
| `GET/PUT /api/ai/inventory` | AI package inventory |
| `GET /api/ai/exposure` | Live OSV check (`refresh=true` to bypass the 15-minute cache) |

## Digests, reports, runs

| Method & path | Description |
|---|---|
| `GET /api/digests`, `GET /api/digests/{date}`, `POST /api/digests/run` | Daily digests |
| `GET /api/reports`, `GET /api/reports/{id}`, `POST /api/reports/weekly` | Weekly briefs |
| `GET /api/reports/{id}/markdown` | Markdown export |
| `GET /api/runs`, `POST /api/runs` | Run history / start an aggregation |
| `GET /api/stats?days=` | Dashboard statistics |

## Agent & chats

| Method & path | Description |
|---|---|
| `GET /api/agent` | Provider, model, tools |
| `GET/PUT /api/agent/prompts` | One-click prompt templates |
| `GET/POST /api/chats`, `GET/PATCH/DELETE /api/chats/{id}` | Chats (scoped to the signed-in user) |
| `POST /api/chats/{id}/messages` | `{text}` or `{brief: {type, value, itemId, reason}}`; responds with **Server-Sent Events**: `start`, `text`, `step_start`, `step_end`, `done`, `error` |

## Settings & usage

| Method & path | Description |
|---|---|
| `GET/PUT /api/settings/ai` | `{autoSummarize, scheduledDigestAI}` |
| `GET /api/usage?days=` | Estimated AI spend by kind and day, recent calls |
| `GET /api/integrations` | TAXII/MCP/MISP status and URLs |
| `GET /api/config`, `GET /api/me` | App config, current user |

## Machine endpoints (own auth)

| Path | Auth |
|---|---|
| `/healthz` | none |
| `/taxii2/…` | `TAXII_TOKEN`; see [TAXII](../integrations/taxii.md) |
| `/mcp` | `MCP_TOKEN`; see [MCP](../integrations/mcp.md) |
