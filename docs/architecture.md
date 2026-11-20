# Architecture

```
                 ┌──────────────────── Azure Container Apps Environment ────────────────────┐
 Browser ──HTTPS─┼─► Easy Auth (Entra ID) ─► ca-cynews  (Go: REST API + embedded React UI)   │
 SIEM/TIP ─TAXII─┼──────────────────────────► /taxii2/*  (token)                             │
 Agents ──MCP────┼──────────────────────────► /mcp       (token)                             │
                 │   caj-aggregate (hourly)  ─►  cynews run                                  │
                 │   caj-digest    (daily)   ─►  cynews digest                               │
                 └───────────────┬─────────────────────────┬────────────────────────────────┘
                                 │ managed identity (RBAC)  │
          Storage account: Tables (feeds, items, itemindex, rules, alerts, runs, digests, chats,
                           settings, usage, reports) + Blob (article text, chat transcripts, locks)
          Key Vault (secrets) · ACR (images) · Log Analytics (logs)

 Outbound: RSS/Atom/JSON feeds · CISA KEV · OSV.dev · NVD · VirusTotal · AbuseIPDB
           LLM (Claude | Azure OpenAI | Ollama) · Slack webhooks · MISP
```

## Components

| Package | Responsibility |
|---|---|
| `cmd/cynews` | Entry point: `serve`, `run`, `digest`, `seed`, `query`, `ask`, `mcp` |
| `internal/feeds` | Fetching (conditional GET), RSS/Atom/JSON parsing, CISA KEV, OSV watch, full-text extraction, defaults |
| `internal/pipeline` | Aggregation, enrichment (heuristic or AI), rule matching, alerts, retention, digest, detections, weekly brief, migrations |
| `internal/ai` | Provider abstraction, prompts and ordered JSON schemas, Claude / Azure OpenAI / Ollama / heuristic, chat sessions, pricing |
| `internal/agent` | Read-only toolbox (shared by agent, CLI, MCP), external intel, tool-use loop, prompt templates |
| `internal/rules` | Keyword/regex compilation, hybrid/semantic/keyword evaluation |
| `internal/ioc` | Defang-aware IOC extraction and sanitisation |
| `internal/frameworks` | ATT&CK / ATLAS / OWASP LLM validation and explicit-ID extraction |
| `internal/analysis` | Event clustering, trends, framework coverage |
| `internal/sharing` | IOC aggregation, STIX 2.1, CSV/TXT, TAXII 2.1 server, MISP push |
| `internal/detect` | Structural validation of KQL/SPL/Sigma/YARA |
| `internal/mcp` | MCP JSON-RPC server (HTTP + stdio) |
| `internal/store` | Store interface; Azure Tables/Blob (blob-lease locks) and in-memory implementations |
| `internal/notify` | Slack Block Kit |
| `internal/api` | REST API, SSE chat streaming, SPA serving |
| `frontend/` | React + Vite + TypeScript + Tailwind + TanStack Query, built into `internal/web/dist` and embedded |

## Aggregation run

1. Acquire the `aggregate` lock (blob lease, renewed) and run one-time migrations.
2. Sync new built-in sources, then load feeds and rules.
3. Fetch feeds concurrently (conditional GET, OSV watch for `osv-watch`); dedupe by canonical URL hash, across feeds too.
4. Enrich each new item: full text, then the heuristic enricher (or AI if auto-summarise is on), regex CVEs/IOCs/framework IDs.
5. Evaluate rules, store the item (text in blob), and send Slack alerts.
6. Retry failed AI enrichments (if AI is on), purge beyond retention, and record the run and its spend.

## Data model

Items are partitioned by **publish day** (`YYYYMMDD`) with inverted-timestamp row keys (newest first), so "last N days"
is a range query and retention is partition-scoped. Each entity stores its JSON document in a `Data` property plus a few
columns for browsing in Storage Explorer. Chats are partitioned by a hash of the Entra principal ID. Messages are blobs
that keep the provider-native transcript, so resumed conversations replay exactly.

See [Design notes](design.md) for the full design history and decisions.
