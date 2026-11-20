# Configuration

All configuration is via environment variables (`.env` for Docker Compose, Container App settings and Key Vault
secrets in Azure). The template is `.env.example` in the repo root.

!!! note "Runtime settings"
    **Auto-summarise**, the **AI scheduled digest**, the **one-click agent prompts** and the **AI supply-chain inventory** are
    changed in the UI (Settings and AI security pages) and stored in Azure Storage. The variables below only provide
    their initial defaults.

## Server

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP port |
| `PUBLIC_BASE_URL` | `http://localhost:8080` | External URL, used in Slack links, TAXII discovery and MCP setup snippets |
| `AUTH_MODE` | `none` | `easyauth` requires Container Apps Easy Auth headers on `/api` |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / `text` | `debug`/`warn`/`error`; `json` for cloud logging |
| `TZ` | `UTC` | Timezone for the scheduler, digests and dashboards |

## Storage

| Variable | Default | Description |
|---|---|---|
| `STORAGE_MODE` | `azure` | `azure` (Tables + Blob) or `memory` (ephemeral) |
| `AZURE_STORAGE_CONNECTION_STRING` | | Connection string (Azurite or key-based accounts) |
| `AZURE_STORAGE_ACCOUNT` | | Account name, authenticated with managed identity or `az login` (`DefaultAzureCredential`) |
| `STORAGE_TABLE_PREFIX` / `STORAGE_BLOB_CONTAINER` | `cynews` | Table name prefix and blob container |

## AI providers

| Variable | Default | Description |
|---|---|---|
| `AI_PROVIDER` | `none` | `claude`, `azureopenai`, `ollama` or `none` |
| `ANTHROPIC_API_KEY` | | Claude API key (an `ant auth login` profile also works) |
| `CLAUDE_MODEL` | `claude-haiku-5-5` | Per-story summaries, tags and rule scoring |
| `CLAUDE_DIGEST_MODEL` | `claude-opus-5-5` | Daily digest and weekly brief |
| `CLAUDE_CHAT_MODEL` | `claude-opus-5-5` | Research agent and detection engineering |
| `CLAUDE_EFFORT` / `CLAUDE_DIGEST_EFFORT` / `CLAUDE_CHAT_EFFORT` | `low` / `medium` / `medium` | Thinking effort per task |
| `CLAUDE_FALLBACKS` | `true` | Server-side refusal fallbacks (ignored for Haiku models) |
| `AZURE_OPENAI_ENDPOINT` / `_API_KEY` / `_API_VERSION` | | Azure OpenAI connection |
| `AZURE_OPENAI_DEPLOYMENT` / `_DIGEST_DEPLOYMENT` / `_CHAT_DEPLOYMENT` | | Deployments per task |
| `OLLAMA_URL` / `OLLAMA_MODEL` | `http://localhost:11434` / `llama3.1:8b` | Local LLM |
| `AI_CONCURRENCY` | `4` | Parallel AI calls |
| `AI_MAX_CHARS` | `24000` | Article text sent per summary |
| `AUTO_SUMMARIZE` | `false` | Initial value of "auto-summarise every new story" |
| `SCHEDULED_DIGEST_AI` | `false` | Initial value of "AI-written scheduled digest" |
| `AGENT_MAX_STEPS` | `12` | Maximum tool rounds per agent answer |

## Threat intel lookups (agent)

| Variable | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | Enables `ioc_reputation` for IPs, domains, URLs and hashes |
| `ABUSEIPDB_API_KEY` | Adds AbuseIPDB to `ioc_reputation` for IPs |
| `NVD_API_KEY` | Optional; raises NVD rate limits for `lookup_cve` |
| `OSV_URL` | OSV.dev query endpoint for the AI supply-chain watch |

## Ingestion and schedule

| Variable | Default | Description |
|---|---|---|
| `SCHEDULER_ENABLED` | `false` | In-process cron (local). In Azure, Container Apps Jobs do the scheduling |
| `RUN_ON_START` | `false` | Run an aggregation at startup |
| `FETCH_CRON` / `DIGEST_CRON` | `0 * * * *` / `0 8 * * *` | Cron expressions (quote them in `.env`) |
| `RETENTION_DAYS` | `90` | Purge items and alerts older than this |
| `BACKFILL_DAYS` | `3` | Ignore older items when a feed is new |
| `FETCH_CONCURRENCY` / `FETCH_TIMEOUT_SECONDS` | `8` / `20` | Feed fetching |
| `FETCH_FULL_TEXT` | `true` | Extract article text when RSS only has a teaser |
| `MAX_ITEMS_PER_FEED_PER_RUN` | `25` | Cap per feed per run |
| `DEFAULT_RULE_THRESHOLD` | `70` | Default AI relevance threshold for new rules |
| `SEED_DEFAULT_FEEDS` | `true` | Seed built-in sources (new built-ins are added once on upgrade) |
| `USER_AGENT` | `CyNewsFeed/1.0 …` | HTTP User-Agent for fetches |

## Notifications and integrations

| Variable | Default | Description |
|---|---|---|
| `SLACK_WEBHOOK_URL` | | Default Slack channel for alerts and digests |
| `SLACK_ENABLED` | `true` | Master switch for Slack |
| `TAXII_TOKEN` | | Enables `/taxii2/`. Open without a token only when `AUTH_MODE=none` |
| `MCP_TOKEN` | | Enables `/mcp`. Open without a token only when `AUTH_MODE=none` |
| `MISP_URL` / `MISP_KEY` / `MISP_VERIFY_TLS` | / / `true` | MISP push |
