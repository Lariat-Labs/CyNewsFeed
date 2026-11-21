# CyNewsFeed

A cybersecurity news and podcast aggregator with AI briefings, entity tagging, and
**keyword + semantic alert rules** that post to Slack. A single Go binary (API + embedded
React SPA + scheduler) stores its state in Azure Table/Blob Storage, runs locally with
Docker, and deploys to Azure Container Apps with Terraform.

- **35 curated sources** out of the box: news, vendor research, CISA advisories, the **CISA KEV**
  catalog, ZDI, and security podcasts (all verified working; editable in the UI).
- **AI briefing per story**: TL;DR, key points, why-it-matters, severity, and extracted CVEs,
  threat actors, malware, vendors, products, topics. Pluggable: **Claude**, **Azure OpenAI**,
  **Ollama**, or no AI.
- **Alert rules**: describe what you care about in plain English, add optional keywords and regex.
  Every new story is scored 0–100 against each rule in the *same* LLM call that summarises it,
  so "somewhat related" stories trigger even without your exact words. Back-test a rule against
  past days before saving it.
- **Slack**: real-time Block Kit alerts (per-rule channel override) and a daily AI-written digest.
- **Scheduling**: hourly aggregation and a daily digest (cron-configurable). Conditional GET,
  cross-feed dedupe, full-text extraction for short RSS snippets, automatic AI retries, 90-day
  retention.
- **Research agent**: click any highlighted CVE, threat actor, malware family, vendor, IOC or
  AI-flagged key detail to get a one-click analyst brief, or ask your own question. A chat page
  keeps per-user history you can pick up later. The agent works in a read-only tool loop over your
  dataset (search, entity timelines, top entities, alerts, digests), plus NVD/CISA KEV and optional
  VirusTotal/AbuseIPDB lookups. It streams its answer, shows each lookup it ran, and cites the stories
  it used.
- **Detections and IOC sharing**: one click writes KQL (Sentinel/Defender), Splunk SPL, Sigma and YARA for a story,
  with a structure check on each. An IOC page aggregates every indicator; export it as **STIX 2.1**, CSV or text, push it to
  **MISP**, or let Sentinel, OpenCTI, MISP or Splunk pull it from the built-in **TAXII 2.1** feed.
- **AI-security pack**: OWASP GenAI, MITRE ATLAS, the AI Incident Database, arXiv LLM-security papers, Embrace The Red and
  others; stories are mapped to **MITRE ATT&CK**, **MITRE ATLAS** and the **OWASP LLM Top 10** (heatmaps on the Dashboard
  and the AI Security page). An **AI supply-chain watch** checks your model and framework packages (PyPI, npm, Go, …)
  against OSV.dev for vulnerabilities and malicious packages.
- **Events, trends, briefs and MCP**: cross-source coverage is clustered into events, rising entities are detected
  against a baseline, a weekly **executive brief** exports to Markdown or PDF, and a read-only **MCP server** (HTTP and
  `cynews mcp` stdio) gives Claude Code, Cursor or your own agents the same research tools.
- **SPA**: dense feed with filters, search and keyboard navigation (`j`/`k`/`o`/`s`/`/`); a dashboard
  (severity trend, top CVEs/actors/malware/vendors); rule editor with back-testing; source health;
  digest archive; run history. Dark and light themes.

Full documentation lives in [`docs/`](docs/) and is published with MkDocs (see [Documentation](#documentation)). The design notes are in [docs/design.md](docs/design.md).

---

## Quick start

### 1. Docker Compose (app + Azurite storage emulator)

```bash
cp .env.example .env          # set ANTHROPIC_API_KEY (or AI_PROVIDER=none) and SLACK_WEBHOOK_URL
docker compose up --build
open http://localhost:8080
```
The first aggregation runs on startup, then hourly. Use **Refresh now** in the sidebar at any time.
For a fully local LLM: set `AI_PROVIDER=ollama`, then run `docker compose --profile ollama up` and
`docker compose exec ollama ollama pull llama3.1:8b`.

### 2. Native dev loop (hot reload)

```bash
make install
make dev-api      # Go API on :8080 against Azurite (starts it in Docker)
make dev-web      # Vite on :5173, proxies /api
```

### 3. Zero dependencies (ephemeral)

```bash
make build
STORAGE_MODE=memory AI_PROVIDER=none SCHEDULER_ENABLED=true RUN_ON_START=true ./bin/cynews serve
```

## Deploy to Azure

```bash
az login
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars   # fill in
make deploy        # = scripts/deploy.sh: creates ACR → az acr build → terraform apply
```

This creates, in `rg-cynews`:

| Resource | Purpose |
|---|---|
| Container App `ca-cynews` | API + SPA, scales 0→1, Entra ID sign-in (Easy Auth) |
| Container Apps Jobs `caj-cynews-aggregate` / `-digest` | hourly aggregation / daily digest (cron in **UTC**) |
| Storage account | Tables (feeds, items, rules, alerts, runs, digests) + Blob (article text, run locks); shared keys disabled |
| User-assigned managed identity | Table/Blob Data Contributor, AcrPull, Key Vault Secrets User |
| Key Vault | Anthropic / Azure OpenAI keys and the Slack webhook |
| ACR, Log Analytics | image registry, logs |

Trigger a run manually with `az containerapp job start -g rg-cynews -n caj-cynews-aggregate`.
Set `enable_auth = false` if you can't create Entra app registrations; then put the app behind
another access control, because without auth it is public.

## Configuration

Everything is configured with environment variables; see [.env.example](.env.example). The key ones:

| Variable | Default | Notes |
|---|---|---|
| `AI_PROVIDER` | `none` | `claude`, `azureopenai`, `ollama`, `none` |
| `CLAUDE_MODEL` / `CLAUDE_DIGEST_MODEL` | `claude-opus-5-5` | per-item vs. digest model |
| `CLAUDE_EFFORT` / `CLAUDE_DIGEST_EFFORT` | `low` / `medium` | thinking effort |
| `STORAGE_MODE` | `azure` | `azure` (connection string *or* account + managed identity) or `memory` |
| `SLACK_WEBHOOK_URL` | | default channel for alerts and digests |
| `FETCH_CRON` / `DIGEST_CRON` / `TZ` | hourly / 08:00 | in-process scheduler (`SCHEDULER_ENABLED=true`) |
| `BACKFILL_DAYS` | `3` | ignore older items when a feed is first added |
| `RETENTION_DAYS` | `90` | purge older items and alerts |
| `FETCH_FULL_TEXT` | `true` | extract article text when the RSS only has a teaser |

**Claude credentials**: `ANTHROPIC_API_KEY`, or an `ant auth login` profile (the SDK picks it up).

### AI cost

The app makes one LLM call per new story; volume is roughly 300–800 stories a day with the default
sources. Per-item input is around 3–6k tokens, and output around 400. With the default **Claude Opus 5.5**
($4 / $20 per MTok), that's about $10–20/day. Setting `CLAUDE_MODEL=claude-haiku-5-5` ($0.10 /
$0.50) brings per-item cost under $1/day, and you can keep Opus for the daily digest
(`CLAUDE_DIGEST_MODEL`). Token usage per run is shown on the Activity page. To cut volume, disable
noisy sources or lower `MAX_ITEMS_PER_FEED_PER_RUN`.

## Research agent

- **Highlights**: in each story's briefing, CVEs, actors and malware are underlined, IOCs (IPs, domains, URLs,
  hashes, emails, extracted by regex with defang support plus the AI) are boxed in monospace, and **key details**
  the AI flagged for follow-up (deadlines, exploitation status, impact) get a highlighter box. Click any of them for
  **Analyst brief** / **Investigate indicator** / **Follow up on this**, or type your own question.
- **Chats** live at `/chat`, scoped to the signed-in Entra user. A reply keeps running and is saved even if you close
  the tab. Resumed chats replay the exact provider transcript, so Claude's thinking blocks stay valid.
- **Tools** (read-only): `search_stories`, `get_story`, `entity_timeline`, `top_entities`, `list_alerts`,
  `get_digest`, `list_sources`, `lookup_cve` (NVD + KEV), and `ioc_reputation` (only when
  `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` are set).
- **CLI**: the same tools from a terminal, handy for scripting and for seeing exactly what the agent sees:

  ```bash
  cynews query --list
  cynews query entity_timeline '{"value":"CVE-2026-114938"}'
  cynews ask "Which threat actors were most active this week?"
  ```
- **Standard prompts** for each entity type are editable under **Settings**.
- Configure with `CLAUDE_CHAT_MODEL` (default `claude-opus-5-5`), `CLAUDE_CHAT_EFFORT` (`medium`) and
  `AGENT_MAX_STEPS` (12). A typical brief makes 5–10 lookups and costs a few cents to roughly $0.30 on Opus 5.5.

## Sharing and integrations

| Integration | Where | Auth |
|---|---|---|
| STIX 2.1 / CSV / TXT export | IOCs page, or `GET /api/iocs/export?format=stix\|csv\|txt&days=30&min_severity=high` | app sign-in |
| TAXII 2.1 (read-only) | `/taxii2/`, collections "all" and "high & critical" | `TAXII_TOKEN` as Basic password or Bearer |
| MCP server | `POST /mcp` (Streamable HTTP), or `cynews mcp` (stdio) | `MCP_TOKEN` Bearer |
| MISP push | IOCs page → Push to MISP | `MISP_URL` + `MISP_KEY` |

In Azure, the TAXII and MCP tokens are generated by Terraform and stored in Key Vault:

```bash
terraform -chdir=infra/terraform output -raw taxii_token
terraform -chdir=infra/terraform output -raw mcp_token
claude mcp add --transport http cynewsfeed "$(terraform -chdir=infra/terraform output -raw mcp_url)" \
  --header "Authorization: Bearer $(terraform -chdir=infra/terraform output -raw mcp_token)"
```

Microsoft Sentinel: *Threat Intelligence – TAXII* data connector → API root `…/taxii2/api/`, a collection ID from
Settings → Integrations, username anything, password = TAXII token.

## Writing good rules

| Mode | Fires when | Use for |
|---|---|---|
| **hybrid** (default) | keyword/regex hit **or** AI relevance ≥ threshold | most rules |
| **semantic** | AI relevance ≥ threshold | fuzzy topics ("healthcare ransomware") |
| **keyword** | keyword/regex hit | exact identifiers; works without AI |

- Describe the *intent*, e.g. "Exploitation or critical vulnerabilities affecting Fortinet
  FortiGate or FortiOS", not just "Fortinet".
- The threshold is 70 by default. Go lower for broader recall, or set 85+ for only squarely on-topic stories.
- Use **Minimum severity** to mute low-urgency matches, and **Back-test** to see what would have fired.
- Keywords are case-insensitive and whole-word; regexes are RE2 (linear-time, safe).

## Development

```bash
make test           # go vet + unit/pipeline tests + tsc
make test-azurite   # also runs the Azure Table/Blob store integration test against Azurite
make run-once       # single aggregation pass
```

```
backend/
  cmd/cynews/            entrypoint: serve | run | digest | seed
  internal/ai/           provider interface, prompts + JSON schemas, Claude / Azure OpenAI / Ollama / heuristic
  internal/feeds/        fetcher (RSS/Atom/JSON, CISA KEV), canonical URLs, full-text, defaults.yaml
  internal/pipeline/     aggregation, enrichment, rule matching, alerts, retention, digest, back-testing
  internal/rules/        keyword/regex compilation + hybrid evaluation
  internal/store/        Store interface, Azure Tables/Blob (+ blob-lease locks), in-memory
  internal/notify/       Slack Block Kit
  internal/api/          REST API + SPA serving
  internal/web/dist/     built SPA (embedded)
frontend/                React + Vite + TypeScript + Tailwind + TanStack Query
infra/terraform/         Azure infrastructure
```

## Releases

CyNewsFeed is released as **one versioned bundle** (SemVer). Each [release](https://github.com/Lariat-Labs/CyNewsFeed/releases)
ships prebuilt `cynews` binaries for Linux, macOS and Windows (amd64/arm64, UI embedded), a multi-arch image
`ghcr.io/lariat-labs/cynewsfeed:<version>`, and auto-generated notes. Maintainers cut releases from **Actions → Release → Run
workflow** (patch / minor / major), or by pushing a `vX.Y.Z` tag. `cynews version` and the app sidebar show the running version.

## Security

See [SECURITY.md](SECURITY.md) to report vulnerabilities privately. The repo uses secret scanning with push protection,
CodeQL code scanning (Go, TypeScript, Actions), Dependabot alerts, security updates and version updates, and
dependency review on pull requests.

## Documentation

The full docs (getting started, deployment, configuration, user guide, integrations, API, CLI, costs and architecture)
are in [`docs/`](docs/) and build with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/):

```bash
pip install -r docs/requirements.txt
mkdocs serve            # http://127.0.0.1:8000
```

The `Docs` workflow (`.github/workflows/docs.yml`) publishes to **GitHub Pages** on every push to `main` that changes the
docs. Enable it once in the repo under *Settings → Pages → Build and deployment → Source: GitHub Actions*.
