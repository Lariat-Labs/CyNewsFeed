// Package notify sends alerts and digests to Slack via incoming webhooks.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"cynewsfeed/internal/model"
)

type Slack struct {
	defaultWebhook string
	baseURL        string
	enabled        bool
	client         *http.Client
	mu             sync.Mutex
	last           time.Time
}

func NewSlack(defaultWebhook, publicBaseURL string, enabled bool) *Slack {
	return &Slack{defaultWebhook: defaultWebhook, baseURL: publicBaseURL, enabled: enabled,
		client: &http.Client{Timeout: 15 * time.Second}}
}

// Configured reports whether a message to the given override would be sent.
func (s *Slack) Configured(override string) bool {
	return s.enabled && (override != "" || s.defaultWebhook != "")
}

var sevEmoji = map[model.Severity]string{
	model.SevCritical: ":red_circle:", model.SevHigh: ":large_orange_circle:", model.SevMedium: ":large_yellow_circle:",
	model.SevLow: ":large_blue_circle:", model.SevInfo: ":white_circle:",
}

// AlertPayload builds the Block Kit message for a rule hit.
func (s *Slack) AlertPayload(a model.Alert, it model.Item) map[string]any {
	title := fmt.Sprintf("<%s|%s>", it.Link, esc(it.Title))
	summary := it.TLDR
	if summary == "" {
		summary = it.Snippet
	}
	blocks := []any{
		section(fmt.Sprintf(":rotating_light: *%s* matched\n%s %s", esc(a.RuleName), sevEmoji[it.Severity], title)),
	}
	if summary != "" {
		blocks = append(blocks, section(esc(summary)))
	}
	ctx := fmt.Sprintf("*%s* · severity *%s* · relevance *%d*", esc(it.FeedName), it.Severity, a.Score)
	if len(a.MatchedKeywords) > 0 {
		ctx += " · keywords: " + esc(strings.Join(a.MatchedKeywords, ", "))
	}
	if a.Reason != "" {
		ctx += "\n_" + esc(a.Reason) + "_"
	}
	if cves := it.Tags.CVEs; len(cves) > 0 {
		ctx += "\n" + strings.Join(cves, " ")
	}
	blocks = append(blocks, map[string]any{"type": "context", "elements": []any{mrkdwn(ctx)}})
	blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{
		button("Read article", it.Link),
		button("Open in CyNews", s.baseURL+"/?item="+it.ID),
	}})
	return map[string]any{"text": fmt.Sprintf("[%s] %s", a.RuleName, it.Title), "blocks": blocks}
}

func (s *Slack) DigestPayload(d model.Digest) map[string]any {
	blocks := []any{
		map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": truncate("Daily brief · "+d.Date, 150)}},
		section("*" + esc(d.Headline) + "*\n" + esc(d.Overview)),
	}
	for _, sec := range d.Sections {
		var b strings.Builder
		fmt.Fprintf(&b, "*%s*\n", esc(sec.Title))
		for _, e := range sec.Items {
			line := esc(e.Line)
			if e.Link != "" {
				line = fmt.Sprintf("<%s|%s>", e.Link, line)
			}
			fmt.Fprintf(&b, "• %s\n", line)
		}
		// Section text is limited to 3000 chars.
		blocks = append(blocks, map[string]any{"type": "divider"}, section(truncate(b.String(), 2900)))
		if len(blocks) > 45 { // Slack limit is 50 blocks
			break
		}
	}
	blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{button("Open digest", s.baseURL+"/digests/"+d.Date)}})
	return map[string]any{"text": "Daily cyber brief: " + d.Headline, "blocks": blocks}
}

func (s *Slack) SendAlert(ctx context.Context, override string, a model.Alert, it model.Item) error {
	return s.post(ctx, override, s.AlertPayload(a, it))
}

func (s *Slack) SendDigest(ctx context.Context, d model.Digest) error {
	return s.post(ctx, "", s.DigestPayload(d))
}

func (s *Slack) post(ctx context.Context, override string, payload any) error {
	hook := override
	if hook == "" {
		hook = s.defaultWebhook
	}
	if !s.enabled || hook == "" {
		return nil
	}
	// Incoming webhooks allow ~1 message/second.
	s.mu.Lock()
	if wait := time.Second - time.Since(s.last); wait > 0 {
		time.Sleep(wait)
	}
	s.last = time.Now()
	s.mu.Unlock()

	body, _ := json.Marshal(payload)
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("slack: %w", err)
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			time.Sleep(time.Duration(2<<attempt) * time.Second)
			continue
		}
		if resp.StatusCode >= 300 {
			return fmt.Errorf("slack HTTP %d: %s", resp.StatusCode, string(msg))
		}
		return nil
	}
	return fmt.Errorf("slack: rate limited")
}

func section(text string) map[string]any {
	return map[string]any{"type": "section", "text": mrkdwn(truncate(text, 2900))}
}
func mrkdwn(t string) map[string]any { return map[string]any{"type": "mrkdwn", "text": t} }
func button(text, url string) map[string]any {
	return map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": text}, "url": url}
}

// esc escapes Slack mrkdwn control characters.
func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
