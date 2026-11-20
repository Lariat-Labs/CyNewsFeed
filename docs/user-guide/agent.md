# Research agent

**Ask the agent** is a chat over your dataset. It is **read-only**: it searches, reads and looks things up, but never
changes rules, sources or data.

## Starting a conversation

- **From a highlight**: click a highlighted entity in a story, then **Analyst brief** (or type a question).
- **From a story**: the **Ask** button in the story header.
- **From an event**: **Brief me on this event** on the Events page.
- **Directly**: the chat page, with suggested starter questions.

Answers stream in. A collapsible **lookups** list shows each tool call, and numbered **citations** link to the stories
used. Chats are saved **per signed-in user** and can be resumed. If you close the tab mid-answer, the agent finishes and
saves the answer.

## Tools

| Tool | What it does |
|---|---|
| `search_stories` | Free-text or exact-entity search with filters |
| `get_story` | Full briefing and optional article text |
| `entity_timeline` | First/last seen, mentions per source, chronology, co-occurring entities |
| `top_entities` | Most-mentioned CVEs, actors, malware, vendors, products, topics or IOCs |
| `list_events` / `trending` | Multi-source events and rising entities |
| `list_iocs` | Aggregated indicators |
| `framework_coverage` | ATT&CK / ATLAS / OWASP LLM coverage |
| `list_alerts`, `get_digest`, `list_sources` | Alerts, digests, source health |
| `lookup_cve` | NVD (CVSS, CWE, affected CPEs) + CISA KEV status |
| `ioc_reputation` | VirusTotal / AbuseIPDB (only when API keys are set) |

The same tools are available from the terminal (`cynews query`, `cynews ask`) and to external agents via the
[MCP server](../integrations/mcp.md).

## Standard prompts

The one-click prompts per entity type (CVE, actor, malware, IOC, vendor, key detail, default) are editable under
**Settings**. Placeholders: `{{value}}`, `{{type}}`, `{{story}}`, `{{reason}}`.

## Models and cost

The agent uses `CLAUDE_CHAT_MODEL` (default Claude Opus 5.5, medium effort). A typical brief makes 5–10 lookups and costs a
few cents to around $0.30. Each answer shows its cost.
