# Feed & AI summaries

The **Feed** is the main page: a dense, filterable stream of stories from all enabled sources.

## Reading

- Filter by **time window**, **category** (news, research, advisories, AI security, podcasts), **minimum severity**,
  **source**, **rule hits**, **starred**, **unread**, or a **tag** (click any chip).
- Search matches titles, summaries and tags (all words must match).
- Click a story to open its briefing in a side panel. Click it again, press `Esc` or use ✕ to close it.
- Keyboard: `j`/`k` next/previous, `o` open original, `s` star, `/` search, `Esc` close. Hover the keyboard icon for a reminder.

## Free enrichment (always on)

Every new story gets, without any AI call:

- a lead excerpt and a keyword-based severity guess
- regex-extracted **CVEs**, **IOCs** (defanged indicators, public IPs and hashes) and explicit **ATT&CK / ATLAS / OWASP
  LLM** IDs
- **keyword/regex alert rules**
- clustering into **events** and **trends**

## AI summaries (on demand)

Click **Summarise with AI** on a story, or **Summarise N** on a filtered view (up to 25), to get:

- **TL;DR**, **key points** and **why it matters**
- **severity** (info → critical)
- **entities**: CVEs, threat actors, malware, vendors, products, topics and IOCs
- **framework mappings**: MITRE ATT&CK and ATLAS techniques, OWASP LLM Top 10 categories
- **key details**: phrases worth following up (deadlines, exploitation status, impact), highlighted in yellow
- semantic **alert rule** scores, which may trigger alerts

To summarise everything automatically on each scheduled run, enable **Settings → AI usage → Auto-summarise**. See
[AI costs](../reference/costs.md) first.

## Highlights and "Ask about this"

In a briefing, CVEs, actors, malware, vendors, products, IOCs, framework tags and key details are **clickable**. The
popover offers a one-click **analyst brief** (or **investigate indicator** / **follow up on this**), a free-form question,
**Filter feed** and **Copy** (IOCs are copied defanged). See [Research agent](agent.md).

## Sources

**Sources** lists every feed with its health (last fetch, errors, item counts). You can enable or disable sources, add
RSS/Atom/JSON feeds (with a live test and preview), or restore built-in defaults. Built-in kinds:

| Kind | Example |
|---|---|
| `rss` | Any RSS, Atom or JSON Feed, including podcasts with audio enclosures |
| `cisa-kev` | The CISA Known Exploited Vulnerabilities JSON catalog |
| `osv-watch` | OSV.dev advisories for your AI package inventory ([AI security](ai-security.md)) |
