# Events, trends & briefs

## Events

**Events & trends** groups coverage of the same incident across sources into one event, ranked by number of sources,
severity and recency. Stories join an event when, within 4 days, they:

- share a **CVE** (stories listing more than 3 CVEs don't link others), or a **malware family**, or
- have strongly overlapping headlines from **different sources** (with a size guard against chaining).

Multi-topic items such as podcast episodes and weekly roundups attach to their single best-matching event and never
bridge unrelated events. Expand an event for its timeline, or click **Brief me on this event** to have the agent
reconcile what the sources say.

## Trends

**Rising** compares mentions in the recent window with the preceding baseline (3× as long). Entities not seen in the
baseline are marked **NEW**. Broad labels (topics, big vendors) are down-weighted, so specific CVEs, actors and malware
rank first. Right after installation the baseline is empty, so most items show as NEW until a few weeks of data exist.

## Daily digest

**Digests & briefs → Daily digest**: a briefing of the last 24 hours, posted to Slack on schedule.

- Scheduled digests are a ranked headline list unless **Settings → AI usage → AI-written scheduled digest** is on.
- **Generate now** always uses AI (one call with the digest model).

## Weekly executive brief

**Digests & briefs → Weekly brief → Generate** writes a leadership-ready brief for the last 7 days: title, executive
summary, 3–5 key risks with recommendations, 5–8 top events (linked to source stories), metrics commentary and
next-week priorities.

- Export as **Markdown**, or **PDF** via the print button.
- One call with the digest model, about $0.10 on Opus. Regenerating in the same ISO week overwrites that week's brief.
