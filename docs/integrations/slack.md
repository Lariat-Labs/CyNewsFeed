# Slack

CyNewsFeed posts to Slack through **incoming webhooks**, with no bot or app permissions needed.

1. In Slack: *Apps → Incoming Webhooks* (or create an app with Incoming Webhooks), then choose a channel and copy the
   webhook URL.
2. Set `SLACK_WEBHOOK_URL`, or `slack_webhook_url` in Terraform, where it's stored in Key Vault.

## What gets posted

- **Rule alerts**, in real time: rule name, severity, story title and link, TL;DR, relevance score and reason, matched
  keywords, CVEs, and buttons for *Read article* and *Open in CyNews*.
- **Daily digest**: headline, overview and sections with linked items.

Each rule can override the webhook to route alerts to a different channel. Messages are rate-limited to about 1 per
second, with retries on HTTP 429.
