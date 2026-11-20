# CyNewsFeed — Build Plan & Spec

A cybersecurity news + podcast aggregator with AI summaries, entity tagging, rule-based
(keyword **and** semantic) alerting to Slack, and a daily AI digest. Go backend, React SPA,
Azure Storage for state, deployable to Azure Container Apps or run locally with Docker.

---

## 1. Decisions (from the spec Q&A)

| # | Topic | Decision |
|---|-------|----------|
| 1 | LLM provider | **Pluggable**: Claude (Anthropic API), Azure OpenAI, Ollama — selected by `AI_PROVIDER`; `none` for no-AI mode |
| 2 | Rule matching | **Keyword/regex prefilter + LLM relevance score (0–100)** against each rule's plain-English description |
| 3 | Slack | **Outbound**: real-time rule-hit alerts + daily digest via incoming webhooks (Block Kit), per-rule webhook override |
| 4 | Hosting | **Azure Container Apps**: one app (SPA + API) + two scheduled Container Apps Jobs (aggregate, digest) |
| 5 | Storage | **Azure Table Storage** (feeds, items, rules, alerts, runs, digests) + **Blob** (raw article text, run locks). Azurite locally |
| 6 | Frontend | **React + Vite + TypeScript + Tailwind**, TanStack Query |
| 7 | Auth | **Entra ID via Container Apps Easy Auth** in cloud; none locally |
| 8 | Podcasts | **Show notes only** — summarize RSS description/notes, inline audio player |
| 9 | IaC | **Terraform** (azurerm + azuread + azapi), Makefile + deploy script wrapper |
| 10 | Schedule | **Hourly fetch** (alerts immediately) + **daily digest at 08:00** — both cron-configurable |
| 11 | Sources | News & research blogs, Advisories & vulns (incl. CISA KEV JSON), Podcasts |
| 12 | Retention | **90 days** purge + AI-extracted **entity tags** (CVEs, actors, malware, vendors, products, severity) |

---

## 2. Architecture

```
                 ┌───────────────────────── Azure Container Apps Environment ─────────────────────────┐
                 │                                                                                      │
 Browser ──HTTPS─┼─► [Easy Auth / Entra ID] ─► ca-cynews (Go: REST API + embedded SPA, scale 0..1)      │
                 │                                   │                                                  │
                 │   caj-aggregate (cron 0 * * * *) ─┤  `cynews run`     ┌──────────────┐               │
                 │   caj-digest    (cron 0 8 * * *) ─┤  `cynews digest`  │ Managed      │               │
                 │                                   │                   │ Identity     │               │
                 └───────────────────────────────────┼───────────────────┴──────┬───────┘───────────────┘
                                                     │                          │ RBAC (Table/Blob Data Contributor,
                                                     ▼                          │       KV Secrets User, AcrPull)
                     ┌───────────────── Storage Account ─────────────────┐      │
                     │ Tables: feeds items itemindex rules alerts runs    │◄─────┘
                     │         digests                                    │
                     │ Blob:   raw/{itemID}.txt   locks/{name}            │
                     └────────────────────────────────────────────────────┘
        Key Vault (anthropic key, AOAI key, slack webhook)    ACR (images)    Log Analytics (logs)

 External:  RSS/Atom/JSON feeds ──► fetcher      LLM (Claude | Azure OpenAI | Ollama)      Slack webhooks
```

**Locally**: `docker compose up` → `cynews serve` (API + SPA + in-process cron scheduler) + Azurite
(+ optional Ollama profile). Or `make dev` for hot-reload (Vite proxy → Go API).

### Single binary, subcommands
| Command | Purpose |
|---------|---------|
| `cynews serve` | HTTP API + SPA; optional in-process scheduler (`SCHEDULER_ENABLED=true` locally) |
| `cynews run` | One aggregation pass (fetch → dedupe → enrich → AI → match → alert → store → purge) |
| `cynews digest` | Build + store + post the daily digest |
| `cynews seed` | Seed default feeds (also auto on first run when feeds table empty) |

---

## 3. Pipeline (one aggregation run)

1. **Lock** — acquire a blob lease `locks/aggregate` (memory mutex locally) so the cron job and a
   manual "Refresh now" never overlap.
2. **Load feeds** (enabled) and **rules** (enabled).
3. **Fetch concurrently** (bounded worker pool, default 8) with conditional GET
   (`ETag`/`If-Modified-Since`), per-feed timeout, UA header, max body size. Parsers:
   - RSS/Atom/JSON Feed via `gofeed` (articles + podcasts; iTunes extensions → audio URL, duration, image)
   - `cisa-kev` — CISA Known Exploited Vulnerabilities JSON catalog → one item per new CVE
4. **Normalize + dedupe** — canonical URL (lowercase host, strip `utm_*`/fragments/trailing slash) →
   `id = sha256(canonical)[:16]`. Skip if in `itemindex`. Skip items older than `BACKFILL_DAYS` (default 3)
   so a new feed doesn't flood the LLM with its archive. Cap `MAX_ITEMS_PER_FEED_PER_RUN`.
5. **Enrich** — if article and description < 600 chars and `FETCH_FULL_TEXT=true`, fetch the page and
   extract main text with readability (fallback silently to description). Raw text → blob `raw/{id}.txt`.
6. **Keyword prefilter** — each rule's keywords (case-insensitive, word-boundary) and regexes → `keywordHits`.
7. **AI enrichment (one LLM call per item)** — structured JSON output containing:
   - `tldr` (1–2 sentences), `bullets` (3–5 key points), `why_it_matters`
   - `severity` (`info|low|medium|high|critical`)
   - `tags`: `cves[]`, `threat_actors[]`, `malware[]`, `vendors[]`, `products[]`, `topics[]`
   - `rule_scores`: `[{rule_id, score 0-100, reason}]` for every active semantic/hybrid rule
   Rules + instructions live in the (cached) system prompt so the per-item cost is just the article.
   CVEs are also regex-extracted deterministically and merged (LLM can't drop them).
8. **Rule evaluation** per rule mode:
   - `keyword`: alert if keyword/regex hit
   - `semantic`: alert if LLM score ≥ `threshold` (default 70)
   - `hybrid` (default): alert if keyword hit **or** score ≥ threshold; keyword hit adds +15 to the score shown
   - Optional `min_severity` filter per rule
9. **Persist** item (+ index) and alerts; **notify** Slack (per-rule webhook override → global webhook),
   rate-limited, one message per (rule,item), idempotent via alert key.
10. **Feed health** — update each feed's `lastFetched`, `lastStatus`, `lastError`, `etag`, counts.
11. **Retention** — delete item/alert partitions older than `RETENTION_DAYS` (90) + their blobs.
12. **Run record** → `runs` table (duration, per-feed stats, new items, alerts, errors, AI tokens).

**Failure isolation**: a failing feed or LLM call never aborts the run. AI failures store the item with
`aiStatus=error` and retry enrichment on the next run (up to 3 attempts).

### Daily digest
Collect items from the last 24 h → rank (rule hits, severity, KEV, source weight) → top ~40 go to the
digest model → structured output: `headline`, `overview` paragraph, `sections[{title, items[{id, line}]}]`.
Stored in `digests` table, shown in the UI, posted to Slack.

---

## 4. Data model (Azure Tables)

| Table | PartitionKey | RowKey | Notes |
|-------|--------------|--------|-------|
| `feeds` | `feed` | feedID (slug) | name, url, kind (`rss`/`cisa-kev`), category (`news`/`research`/`advisory`/`podcast`), enabled, weight, etag, lastModified, lastFetched, lastStatus, lastError, itemCount |
| `items` | `YYYYMMDD` (published, UTC) | `invTs_id` (newest first) | id, feedID, feedName, category, title, link, published, author, snippet, tldr, bullets(JSON), whyItMatters, severity, tags(JSON), ruleHits(JSON), audioURL, imageURL, duration, aiStatus, aiModel, aiAttempts, read, starred |
| `itemindex` | `id` | itemID | → items PK/RK; dedupe + direct lookup |
| `rules` | `rule` | ruleID | name, description, keywords(JSON), regexes(JSON), mode, threshold, minSeverity, slackWebhook, enabled, created |
| `alerts` | `YYYYMMDD` | `invTs_ruleID_itemID` | ruleID, ruleName, itemID, title, link, score, reason, matchedKeywords, notified, notifyError |
| `runs` | `run` | `invTs` | kind, started, finished, stats(JSON), error |
| `digests` | `digest` | `YYYYMMDD` | headline, overview, sections(JSON), itemCount, model |

Why date-partitioned items: a "last N days" view is N partition queries, retention purge is
partition-scoped, and RowKey inversion gives newest-first without sorting.
Large text (full article) lives in Blob to stay well under the 64 KB/property and 1 MB/entity limits.

---

## 5. REST API (`/api`)

| Method & path | Purpose |
|---------------|---------|
| `GET /items?days=7&category=&severity=&feed=&tag=&q=&rule=&starred=&limit=` | List/filter/search |
| `GET /items/{id}` | Item detail (+ raw text) |
| `PATCH /items/{id}` | `{read, starred}` |
| `GET/POST /feeds`, `PUT/DELETE /feeds/{id}` | Source management |
| `POST /feeds/test` | Validate a feed URL → parse preview |
| `GET/POST /rules`, `PUT/DELETE /rules/{id}` | Rule CRUD (webhooks masked on read) |
| `POST /rules/{id}/test?days=7` | Back-test: keyword hits + LLM batch scoring over recent items |
| `GET /alerts?days=7` | Alert history |
| `GET /digests`, `GET /digests/{date}` | Digest archive |
| `POST /runs` / `POST /digests/run` | Trigger aggregate / digest now (async, lock-guarded) |
| `GET /runs` | Run history |
| `GET /stats` | Counts by severity/category/day, top tags (dashboard) |
| `GET /me` | Current user (Easy Auth principal header) |
| `GET /healthz` | Liveness |

---

## 6. AI provider abstraction

```go
type Provider interface {
    Name() string
    Enrich(ctx, EnrichInput) (*Enrichment, Usage, error)       // per-item summary/tags/rule scores
    ScoreBatch(ctx, Rule, []ItemBrief) ([]RuleScore, error)     // rule back-testing
    Digest(ctx, DigestInput) (*DigestOutput, error)
}
```
- **Claude** — official `anthropic-sdk-go/v2`; structured outputs (JSON schema), adaptive thinking
  with `effort` config (default `low` for items, `medium` for digests), cached system prompt,
  server-side refusal fallbacks (`fallbacks: "default"`), typed error handling. Models are configurable:
  `CLAUDE_MODEL` (items) and `CLAUDE_DIGEST_MODEL`, both default `claude-opus-5-5`.
- **Azure OpenAI** — chat completions with `response_format: json_schema`, `api-key` auth.
- **Ollama** — `/api/chat` with `format: <json schema>`.
- **none** — heuristic: first sentences as TL;DR, regex CVEs, keyword-only rules.

All providers share the same prompt builder + JSON schema and are wrapped in a concurrency limiter
(`AI_CONCURRENCY`, default 4) with retry/backoff on 429/5xx.

---

## 7. Frontend (SPA)

- **Feed** — dense, scannable card list: source, time-ago, severity chip, TL;DR, tag chips, rule-hit
  badges. Filters (category, severity, source, tag, days, starred, rule hits), full-text search,
  keyboard nav (`j/k` move, `o` open, `s` star). Detail panel: bullets, why-it-matters, entities,
  original link, podcast audio player.
- **Dashboard** — counts by severity/day, top CVEs/actors/vendors, recent alerts.
- **Rules** — create/edit (name, plain-English description, keywords, regex, mode, threshold, min
  severity, Slack webhook override), back-test against the last N days with scores + reasons.
- **Sources** — list with health (last fetch, status, errors, item count), enable/disable, add with
  live validation/preview.
- **Digests** — daily archive. **Runs** — history + "Refresh now".
- Dark-first theme, responsive, light/dark toggle.

Built by Vite into `frontend/dist`, copied into the Go binary via `embed` (single artifact).

---

## 8. Infrastructure (Terraform, `infra/terraform`)

- Resource group, Log Analytics workspace
- Storage account (StorageV2, LRS, TLS1.2, no public blob access, shared-key disabled optional)
  + tables + `raw`/`locks` containers
- User-assigned managed identity + role assignments (Table Data Contributor, Blob Data Contributor,
  Key Vault Secrets User, AcrPull)
- Azure Container Registry (Basic)
- Key Vault (RBAC mode) + secrets (anthropic key, AOAI key, Slack webhook) — only those provided
- Container Apps environment, app (`ca-cynews`, ingress external, 0..1 replicas), jobs
  `caj-aggregate` + `caj-digest` (schedule trigger, cron vars, `replica_timeout`)
- Entra ID auth (optional `enable_auth`): app registration + secret (azuread) + `authConfigs` (azapi)
- Outputs: app URL, storage account, ACR login server

`scripts/deploy.sh`: `terraform apply -target` (ACR) → `az acr build` → `terraform apply` with the image tag.

---

## 9. Configuration (env)

`AI_PROVIDER` (claude|azureopenai|ollama|none) · `ANTHROPIC_API_KEY` · `CLAUDE_MODEL` · `CLAUDE_DIGEST_MODEL`
· `CLAUDE_EFFORT` · `AZURE_OPENAI_ENDPOINT|API_KEY|DEPLOYMENT|API_VERSION` · `OLLAMA_URL|MODEL`
· `STORAGE_MODE` (azure|memory) · `AZURE_STORAGE_CONNECTION_STRING` *or* `AZURE_STORAGE_ACCOUNT` (+ managed identity)
· `SLACK_WEBHOOK_URL` · `PUBLIC_BASE_URL` · `SCHEDULER_ENABLED` · `FETCH_CRON` · `DIGEST_CRON` · `TZ`
· `RETENTION_DAYS` · `BACKFILL_DAYS` · `FETCH_FULL_TEXT` · `FETCH_CONCURRENCY` · `AI_CONCURRENCY` · `PORT`

---

## 10. Repo layout

```
backend/   cmd/cynews · internal/{config,model,store,feeds,ai,rules,notify,pipeline,api,web}
frontend/  Vite React TS app
infra/terraform/
scripts/   deploy.sh
docker-compose.yml · Dockerfile · Makefile · .env.example · README.md · docs/
```

## 11. Testing & quality
- Unit: URL canonicalization, keyword/regex matcher, rule evaluation, KEV parser, CVE extraction,
  prompt/schema building, Slack payloads.
- Integration: pipeline end-to-end with memory store + fake AI provider + `httptest` feed server;
  Azure store against Azurite (`make test-azurite`).
- `go vet`, `tsc --noEmit`, `terraform validate`.

## 12. Build milestones
1. Scaffold, config, model, memory store, feeds fetcher, pipeline w/ no-AI → items visible
2. Azure Table/Blob store + Azurite compose
3. AI providers (Claude, AOAI, Ollama) + enrichment + entity tags
4. Rules engine + Slack alerts + back-testing
5. Digest
6. SPA (feed, rules, sources, digests, runs, dashboard)
7. Terraform + deploy script + Dockerfile
8. Tests, docs

## 13. Research agent (v2)

**Decisions:** in-app agent loop (works with every provider) · highlights for tagged entities, new IOCs, and
AI-flagged key details · data scope: stored dataset + NVD/KEV + VirusTotal/AbuseIPDB · read-only · per-user chat
history · VirusTotal + AbuseIPDB · default one-click prompt = analyst brief (editable) · streaming with visible
tool steps.

- **Enrichment additions**: `tags.iocs[]` (AI-extracted, merged with the defang-aware regex extractor in `internal/ioc`)
  and `key_details[]` (verbatim phrases from the AI's own summary, validated server-side so the UI can highlight them).
- **Agent loop** (`internal/agent`): provider-neutral `Session` (`AddUser` / `Step` / `AddToolResults` / `Drain`).
  Each step streams text, then runs the tool calls concurrently and returns all results in one turn. It stops after
  `AGENT_MAX_STEPS`. Claude uses streaming Messages with adaptive thinking, auto prompt caching, eager tool-input
  streaming and server-side refusal fallbacks. Azure OpenAI and Ollama use non-streaming tool calling.
- **Persistence**: chat metadata in the `chats` table (PartitionKey = hash of the Entra principal), messages as blobs
  `chats/{id}/{seq}.json`. Each message stores the provider-native transcript entries it added (`native`), so resuming
  replays the conversation byte-for-byte (append-only; Claude thinking blocks stay valid). If the provider changed,
  it falls back to plain-text history.
- **API**: `GET/POST /api/chats`, `GET/PATCH/DELETE /api/chats/{id}`, `POST /api/chats/{id}/messages` (SSE:
  `start`, `text`, `step_start`, `step_end`, `done`, `error`; 15 s heartbeats; the agent runs detached from the
  request so answers are saved after a disconnect), `GET /api/agent`, `GET/PUT /api/agent/prompts`.
- **CLI**: `cynews query <tool> '<json>'`, `cynews query --list`, `cynews ask "<question>"`.

## 14. v3: detections & sharing, AI-security pack, events/trends/briefs/MCP

- **Detections** (`POST /api/items/{id}/detections`): the chat model writes KQL, SPL, Sigma and YARA using an
  ordered JSON schema (title before query), `internal/detect` validates structure (Sigma YAML fields, balanced
  KQL/SPL, YARA rule/condition), and results are stored on the item.
- **IOC sharing**: `internal/sharing` aggregates indicators across stories (first/last seen, max severity,
  malware/actors/CVEs). STIX 2.1 bundles use deterministic UUIDv5 ids (stable across exports and TAXII polls),
  indicator + report objects. TAXII 2.1 read-only server with discovery, API root, collections, objects (added_after,
  match[type|id], limit/next) and manifest. MISP push creates one event (TLP:AMBER, org-only distribution).
- **IOC precision**: only explicitly defanged hostnames, URLs and emails count, plus public IPs, raw-IP URLs, hashes and
  bare domains on unusual TLDs. File extensions, reverse-DNS ids and benign SaaS are rejected, and a one-time migration
  cleans stored data.
- **AI-security pack**: 11 AI-security sources plus the `osv-watch` feed kind, which queries OSV.dev for the package
  inventory (setting `inventory`). New default sources are added to existing installs once (`defaults_seeded`).
  Enrichment adds `attack`, `atlas` and `owasp_llm`. Explicit IDs (T1190, AML.T0051, LLM01) are also regex-extracted for free.
- **Analysis**: union-find clustering (strong links: shared CVE where ≤3 CVEs, or shared malware; weak links:
  cross-feed title Jaccard with a size guard; multi-topic items attach to a single best cluster). Trends compare
  recent and baseline daily rates, and broad labels are down-weighted. Framework coverage gives tactic → technique counts.
- **Weekly brief** (`POST /api/reports/weekly`, Markdown export) using the digest model. **MCP**: JSON-RPC 2.0
  (initialize, tools/list, tools/call with structuredContent, ping), protocol 2025-06-18, read-only annotations.

## 15. Future
NVD / GHSA API sources with CVSS filters · Message Batches API for 50% cheaper bulk enrichment ·
embedding-based clustering of duplicate stories across sources · Slack slash commands ·
transcript-based podcast summaries for rule-matched episodes · Teams / email notifiers ·
per-user read state (multi-user).
