package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/analysis"
	"cynewsfeed/internal/sharing"
)

func (tb *Toolbox) registerAnalysis() {
	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "list_events",
			Description: "Multi-source events: stories about the same incident/disclosure grouped together (shared CVE or malware, or near-identical headlines within 4 days), ranked by number of sources, severity and recency.",
			Properties: map[string]any{
				"days":  map[string]any{"type": "integer", "description": "1-30, default 7"},
				"limit": map[string]any{"type": "integer", "description": "default 15"},
			},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				Days  int `json:"days"`
				Limit int `json:"limit"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			days := min(clampDays(a.Days, 7), 30)
			items, err := tb.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -days))
			if err != nil {
				return nil, "", err
			}
			evs := analysis.Cluster(items, 4*24*time.Hour)
			limit := a.Limit
			if limit <= 0 {
				limit = 15
			}
			if len(evs) > limit {
				evs = evs[:limit]
			}
			return map[string]any{"days": days, "events": evs}, fmt.Sprintf("Found %d multi-source events over %d days", len(evs), days), nil
		},
	})
	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "trending",
			Description: "Entities (CVEs, actors, malware, vendors, products, topics, ATT&CK techniques, OWASP LLM categories) mentioned much more in the recent window than in the preceding baseline window. 'new' means not seen in the baseline.",
			Properties: map[string]any{
				"recent_days":   map[string]any{"type": "integer", "description": "default 7"},
				"baseline_days": map[string]any{"type": "integer", "description": "default 21"},
			},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				Recent   int `json:"recent_days"`
				Baseline int `json:"baseline_days"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			r, b := clampDays(a.Recent, 7), clampDays(a.Baseline, 21)
			now := time.Now().UTC()
			items, err := tb.store.ListItems(ctx, now.AddDate(0, 0, -(r+b)))
			if err != nil {
				return nil, "", err
			}
			tr := analysis.Trends(items, now, r, b, 2)
			if len(tr) > 25 {
				tr = tr[:25]
			}
			for i := range tr {
				tr[i].Daily = nil
			}
			return map[string]any{"recent_days": r, "baseline_days": b, "rising": tr}, fmt.Sprintf("%d rising entities", len(tr)), nil
		},
	})
	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "list_iocs",
			Description: "Indicators of compromise aggregated across stories: type, value, first/last seen, max severity, related malware/actors/CVEs and the stories reporting them.",
			Properties: map[string]any{
				"days":         map[string]any{"type": "integer", "description": "1-90, default 30"},
				"type":         map[string]any{"type": "string", "enum": []string{"ip", "domain", "url", "hash", "md5", "sha1", "sha256", "email"}},
				"query":        map[string]any{"type": "string", "description": "substring match on the indicator value"},
				"min_severity": map[string]any{"type": "string", "enum": []string{"low", "medium", "high", "critical"}},
			},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				Days        int    `json:"days"`
				Type        string `json:"type"`
				Query       string `json:"query"`
				MinSeverity string `json:"min_severity"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			days := clampDays(a.Days, 30)
			items, err := tb.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -days))
			if err != nil {
				return nil, "", err
			}
			inds := sharing.Aggregate(items, sharing.Filter{Type: a.Type, Query: a.Query, MinSeverity: a.MinSeverity})
			total := len(inds)
			if len(inds) > 60 {
				inds = inds[:60]
			}
			for i := range inds {
				if len(inds[i].Stories) > 5 {
					inds[i].Stories = inds[i].Stories[:5]
				}
			}
			return map[string]any{"total": total, "indicators": inds}, fmt.Sprintf("%d indicators over %d days", total, days), nil
		},
	})
	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "framework_coverage",
			Description: "MITRE ATT&CK and MITRE ATLAS techniques (grouped by tactic) and OWASP Top 10 for LLM categories seen across summarised stories in the last N days, with story ids.",
			Properties:  map[string]any{"days": map[string]any{"type": "integer", "description": "1-90, default 30"}},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				Days int `json:"days"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			days := clampDays(a.Days, 30)
			items, err := tb.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -days))
			if err != nil {
				return nil, "", err
			}
			return analysis.Frameworks(items), fmt.Sprintf("Framework coverage over %d days", days), nil
		},
	})
}
