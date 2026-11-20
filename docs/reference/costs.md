# AI costs

CyNewsFeed is **AI-optional and AI-off-by-default on schedules**. Nothing calls a model unless you click something or
enable automation.

| Action | Model (default) | Typical cost |
|---|---|---|
| Summarise one story | `CLAUDE_MODEL` (Haiku 5.5) | ~$0.001 |
| Auto-summarise all new stories (opt-in) | Haiku 5.5 | ~$0.25–0.75/day with default sources |
| Generate detections | `CLAUDE_CHAT_MODEL` (Opus 5.5) | ~$0.05–0.10 |
| Agent answer | Opus 5.5, medium effort | a few cents to ~$0.30 |
| Daily digest ("Generate now" or AI schedule) | `CLAUDE_DIGEST_MODEL` (Opus 5.5) | ~$0.05–0.10 |
| Weekly brief | Opus 5.5 | ~$0.10 |
| Rule back-test (semantic) | Haiku 5.5 | < $0.01 |

!!! warning "Avoid Opus for bulk summaries"
    Summarising every story with Opus 5.5 costs about $10–20/day per environment at default volume. Keep
    `CLAUDE_MODEL` on Haiku for summaries.

## Tracking spend

- **Settings → AI usage** shows estimated spend today and over 30 days, by kind (scheduled summaries, on-demand
  summaries, detections, digests, briefs, chats), with a log of recent calls.
- The sidebar shows today's and 30-day spend. Each agent answer and each run on **Activity** shows its cost.
- Estimates use list prices and account for prompt-cache reads and writes. Your provider bill is authoritative.

## Levers

- Keep auto-summarise off, and summarise the stories or filtered views that matter.
- Disable noisy sources, or lower `MAX_ITEMS_PER_FEED_PER_RUN`.
- Run only one scheduled environment (stop the local scheduler if Azure is your primary).
