# CLI

The `cynews` binary is the server, the scheduled jobs and a research CLI. It reads the same environment variables as
the app.

| Command | Description |
|---|---|
| `cynews serve` | HTTP API + UI (+ in-process scheduler when `SCHEDULER_ENABLED=true`) |
| `cynews run` | One aggregation pass (used by the Container Apps Job) |
| `cynews digest` | Build and post the daily digest |
| `cynews seed [--overwrite]` | Seed built-in sources |
| `cynews query --list` | List agent tools and their arguments |
| `cynews query <tool> '<json>'` | Run one tool and print its JSON result (what the agent sees) |
| `cynews ask "<question>"` | Run the research agent in the terminal |
| `cynews mcp` | MCP server over stdio |

## Examples

```bash
cynews query entity_timeline '{"value":"CVE-2026-114938"}'
cynews query list_iocs '{"type":"domain","min_severity":"high","days":7}'
cynews query trending '{"recent_days":7}'
cynews ask "Which threat actors were most active this week?"
```

Locally against Azurite:

```bash
export STORAGE_MODE=azure \
  AZURE_STORAGE_CONNECTION_STRING='DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;TableEndpoint=http://127.0.0.1:10002/devstoreaccount1;'
./bin/cynews query top_entities '{"type":"malware"}'
```

(That key is Azurite's well-known public development key, not a secret.)
