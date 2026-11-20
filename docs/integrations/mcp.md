# MCP server

CyNewsFeed exposes its read-only research tools as a [Model Context Protocol](https://modelcontextprotocol.io) server,
so Claude Code, Claude Desktop, Cursor or your own agents can query the dataset.

- **Transports**: Streamable HTTP at `POST /mcp` (JSON responses), and **stdio** via `cynews mcp`.
- **Protocol**: `2025-06-18` (also accepts `2025-03-26` and `2024-11-05`).
- **Tools**: the same as the [research agent](../user-guide/agent.md#tools), all annotated `readOnlyHint`. Results include
  `structuredContent`.

## Remote (HTTP)

Set `MCP_TOKEN`; Terraform generates one (`terraform output -raw mcp_token`). In Azure, `/mcp` is excluded from Entra
sign-in and protected by the bearer token.

```bash
claude mcp add --transport http cynewsfeed https://<app>/mcp \
  --header "Authorization: Bearer $MCP_TOKEN"
```

## Local (stdio)

Run the binary with the same storage settings as the app (e.g. the Azurite connection string, or
`AZURE_STORAGE_ACCOUNT` plus `az login`):

```bash
claude mcp add cynewsfeed --env STORAGE_MODE=azure --env AZURE_STORAGE_ACCOUNT=<account> -- /path/to/cynews mcp
```

Logs go to stderr; stdout carries only protocol messages.

## Example prompts

- "Using cynewsfeed, what multi-source events happened this week and which involve exploited CVEs?"
- "List IOCs from critical stories in the last 7 days and the malware they're tied to."
- "Which OWASP LLM Top 10 categories came up most this month? Cite stories."
