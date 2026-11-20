# CyNewsFeed

**CyNewsFeed** is a self-hosted cybersecurity intelligence feed for SecOps and AI-security teams. It aggregates
news, vendor research, government advisories, the CISA KEV catalog, AI-security sources and podcasts, then lets you:

- **Read faster.** Get on-demand AI briefings per story: TL;DR, key points, severity, extracted CVEs, actors, malware,
  IOCs, and MITRE ATT&CK, MITRE ATLAS and OWASP LLM Top 10 mappings.
- **Get alerted.** Alert rules combine keywords/regex with AI relevance scoring and post to Slack.
- **Investigate.** A research agent answers questions about any highlighted CVE, actor or indicator, grounded in your
  dataset plus NVD, CISA KEV, VirusTotal and AbuseIPDB, with citations.
- **Act.** Generate KQL, SPL, Sigma and YARA detections, export IOCs as STIX 2.1, serve them over **TAXII 2.1**, or push
  them to MISP.
- **Report.** Cross-source coverage is clustered into events, rising topics are detected, and a daily digest plus a
  weekly executive brief are generated.
- **Connect agents.** A read-only **MCP server** gives Claude Code, Cursor or your own agents the same research tools.

It runs as **one Go binary** (API + embedded React UI + scheduler) with state in **Azure Table and Blob Storage**.
It deploys to **Azure Container Apps** with Terraform, or runs locally with Docker Compose.

!!! tip "AI is opt-in"
    By default nothing calls an LLM on a schedule. Stories get free regex-based enrichment, and AI runs only when you
    click **Summarise**, generate detections or briefs, or chat with the agent. See [AI costs](reference/costs.md).

## Where to start

<div class="grid cards" markdown>

- **[Getting started](getting-started.md)**: run it locally in five minutes.
- **[Deployment](deployment.md)**: deploy to Azure with Terraform.
- **[User guide](user-guide/feed.md)**: the features, page by page.
- **[Integrations](integrations/taxii.md)**: SIEM/TIP, MCP, Slack and MISP.

</div>

## Screens at a glance

| Page | What it's for |
|---|---|
| **Feed** | Filterable stream of stories; click one for the AI briefing, highlights, detections and IOC export |
| **Events & trends** | Multi-source events and rising entities |
| **Dashboard** | Severity trend, ATT&CK heatmap, top CVEs/actors/malware, recent alerts |
| **Digests & briefs** | Daily digest and weekly executive brief |
| **Ask the agent** | Chat with the research agent; history per user |
| **IOCs** | Aggregated indicators with STIX/CSV/TXT export and MISP push |
| **AI security** | OWASP LLM Top 10 grid, ATLAS heatmap, AI supply-chain watch |
| **Alert rules / Sources / Activity / Settings** | Configuration, health, spend and integrations |
