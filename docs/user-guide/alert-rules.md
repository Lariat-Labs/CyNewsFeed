# Alert rules

Rules notify you in Slack when stories mention, or are related to, what you care about.

## Modes

| Mode | Fires when | Use for |
|---|---|---|
| **hybrid** (default) | keyword/regex hit **or** AI relevance ≥ threshold | most rules |
| **semantic** | AI relevance ≥ threshold | fuzzy topics ("healthcare ransomware") |
| **keyword** | keyword/regex hit | exact identifiers; works without AI |

AI relevance (0–100) is scored against the rule's plain-English **description** in the same call that summarises a
story. Semantic scoring therefore happens when a story is summarised, either on demand or by auto-summarise. Without a
summary, hybrid and semantic rules fall back to keyword matching.

## Writing good rules

- Describe the **intent**: "Exploitation or critical vulnerabilities affecting Fortinet FortiGate or FortiOS", not just "Fortinet".
- Add keywords for exact identifiers (product names, CVE patterns via regex such as `CVE-2026-\d+`).
- The threshold defaults to 70. Lower it for broader recall, or use 85+ for squarely on-topic stories only.
- **Minimum severity** mutes low-urgency matches.
- **Back-test** a rule against the last 3–30 days before saving it; scores and reasons are shown.
- A per-rule **Slack webhook override** routes the rule to its own channel.

Keywords are case-insensitive and whole-word, with flexible whitespace. Regexes are RE2 (linear time, safe).

A rule never alerts twice for the same story; re-summarising won't re-send.
