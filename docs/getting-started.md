# Getting started

## Prerequisites

- Docker (for Docker Compose and the Azurite storage emulator)
- Optional for native development: Go 1.25+, Node.js 22+
- Optional: an [Anthropic API key](https://console.anthropic.com/), or Azure OpenAI or Ollama, for AI features

## Option 1: Docker Compose (recommended)

```bash
git clone https://github.com/Lariat-Labs/CyNewsFeed.git && cd CyNewsFeed
cp .env.example .env        # add ANTHROPIC_API_KEY and SLACK_WEBHOOK_URL (both optional)
docker compose up --build
```

Open <http://localhost:8080>. The first aggregation runs on startup and then hourly. Use **Refresh now** in the sidebar
any time.

The stack runs the app plus **Azurite**, the Azure Storage emulator, so local data persists in a Docker volume.

!!! note "No AI key?"
    Leave `AI_PROVIDER=none`. You still get the feed, regex CVE/IOC extraction, keyword alert rules, events, trends,
    the IOC pages, TAXII and MCP.

### Fully local LLM

```bash
# in .env: AI_PROVIDER=ollama
docker compose --profile ollama up --build
docker compose exec ollama ollama pull llama3.1:8b
```

## Option 2: native dev loop (hot reload)

```bash
make install     # npm ci + go mod download
make dev-api     # Go API on :8080 against Azurite (started in Docker)
make dev-web     # Vite dev server on :5173, proxies /api
```

## Option 3: zero dependencies (ephemeral)

```bash
make build
STORAGE_MODE=memory AI_PROVIDER=none SCHEDULER_ENABLED=true RUN_ON_START=true ./bin/cynews serve
```

Data is lost on restart.

## First steps in the UI

1. **Feed**: click a story. If it isn't summarised yet, click **Summarise with AI**.
2. **Alert rules**: create a rule, e.g. "Exploitation of Fortinet or Ivanti VPN appliances", and back-test it.
3. **Settings → AI usage**: decide whether to auto-summarise new stories on each run (off by default).
4. **Ask the agent**: try "What were the most critical vulnerabilities this week, and which are exploited?"
