// Package agent implements the read-only research agent: a registry of tools
// over the CyNewsFeed dataset (also exposed as the `cynews query` CLI) and a
// provider-agnostic tool-use loop.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/store"
)

// Tool is one read-only capability. Run receives validated JSON input and
// returns a JSON-serialisable result plus a one-line human summary.
type Tool struct {
	Def ai.ToolDef
	Run func(ctx context.Context, input json.RawMessage) (result any, summary string, err error)
}

// Toolbox holds the tools available to the agent and the CLI.
type Toolbox struct {
	store store.Store
	intel *Intel
	tools map[string]Tool
	order []string
}

// Store exposes the underlying store (used by the MCP resources).
func (tb *Toolbox) Store() store.Store { return tb.store }

func NewToolbox(st store.Store, intel *Intel) *Toolbox {
	tb := &Toolbox{store: st, intel: intel, tools: map[string]Tool{}}
	tb.registerDataset()
	tb.registerAnalysis()
	tb.registerIntel()
	return tb
}

func (tb *Toolbox) add(t Tool) {
	tb.tools[t.Def.Name] = t
	tb.order = append(tb.order, t.Def.Name)
}

func (tb *Toolbox) Defs() []ai.ToolDef {
	out := make([]ai.ToolDef, 0, len(tb.order))
	for _, n := range tb.order {
		out = append(out, tb.tools[n].Def)
	}
	return out
}

func (tb *Toolbox) Names() []string { return append([]string(nil), tb.order...) }

// Call runs a tool by name. Input is validated by strict JSON decoding inside
// each tool; malformed input yields an error the model can correct.
func (tb *Toolbox) Call(ctx context.Context, name string, input json.RawMessage) (string, string, error) {
	t, ok := tb.tools[name]
	if !ok {
		return "", "", fmt.Errorf("unknown tool %q", name)
	}
	if len(input) == 0 || string(input) == "null" {
		input = json.RawMessage("{}")
	}
	if !json.Valid(input) {
		return "", "", fmt.Errorf("tool input is not valid JSON")
	}
	res, summary, err := t.Run(ctx, input)
	if err != nil {
		return "", "", err
	}
	b, err := json.Marshal(res)
	if err != nil {
		return "", "", err
	}
	s := string(b)
	const maxResult = 24000
	if len(s) > maxResult {
		s = s[:maxResult] + `…"[truncated: narrow the query for more]"`
	}
	return s, summary, nil
}

func decodeStrict(input json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(input)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

// ---------------- dataset tools ----------------

// brief is the compact story representation returned to the model.
type brief struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Source    string   `json:"source"`
	Category  string   `json:"category"`
	Published string   `json:"published"`
	Severity  string   `json:"severity"`
	TLDR      string   `json:"tldr,omitempty"`
	CVEs      []string `json:"cves,omitempty"`
	Actors    []string `json:"threat_actors,omitempty"`
	Malware   []string `json:"malware,omitempty"`
	Vendors   []string `json:"vendors,omitempty"`
	IOCs      []string `json:"iocs,omitempty"`
	Attack    []string `json:"attack,omitempty"`
	Atlas     []string `json:"atlas,omitempty"`
	OwaspLLM  []string `json:"owasp_llm,omitempty"`
	RuleHits  []string `json:"rule_hits,omitempty"`
	Link      string   `json:"link"`
}

func toBrief(it model.Item) brief {
	b := brief{ID: it.ID, Title: it.Title, Source: it.FeedName, Category: string(it.Category),
		Published: it.Published.UTC().Format("2006-01-02 15:04Z"), Severity: string(it.Severity),
		TLDR: it.TLDR, CVEs: it.Tags.CVEs, Actors: it.Tags.ThreatActors, Malware: it.Tags.Malware,
		Vendors: it.Tags.Vendors, Link: it.Link}
	if b.TLDR == "" {
		b.TLDR = it.Snippet
	}
	for _, i := range it.Tags.IOCs {
		b.IOCs = append(b.IOCs, i.Type+":"+i.Value)
	}
	for _, h := range it.RuleHits {
		b.RuleHits = append(b.RuleHits, h.RuleName)
	}
	for _, x := range it.Tags.Attack {
		b.Attack = append(b.Attack, x.ID)
	}
	for _, x := range it.Tags.Atlas {
		b.Atlas = append(b.Atlas, x.ID)
	}
	b.OwaspLLM = it.Tags.OwaspLLM
	return b
}

func clampDays(d, def int) int {
	if d <= 0 {
		return def
	}
	return min(d, 90)
}

// mentions reports whether an item mentions value as a tag or in its text.
func mentions(it model.Item, v string) bool {
	lv := strings.ToLower(v)
	for _, t := range it.Tags.All() {
		if strings.ToLower(t) == lv {
			return true
		}
	}
	hay := strings.ToLower(it.Title + " " + it.TLDR + " " + it.Snippet + " " + strings.Join(it.Bullets, " ") + " " + it.WhyItMatters)
	return strings.Contains(hay, lv)
}

func (tb *Toolbox) registerDataset() {
	tb.add(Tool{
		Def: ai.ToolDef{
			Name: "search_stories",
			Description: "Search stored cybersecurity stories (news, research, advisories, podcasts) from the last N days. " +
				"`query` matches words in titles, AI summaries and tags (all words must match). `entity` matches an exact tag or phrase " +
				"(CVE, actor, malware, vendor, product, IOC). Returns newest first with id, title, source, date, severity, summary and tags.",
			Properties: map[string]any{
				"query":        map[string]any{"type": "string", "description": "free-text words, e.g. 'ivanti exploitation'"},
				"entity":       map[string]any{"type": "string", "description": "exact entity or phrase, e.g. 'CVE-2026-1234' or 'Volt Typhoon'"},
				"days":         map[string]any{"type": "integer", "description": "look-back window, 1-90 (default 30)"},
				"category":     map[string]any{"type": "string", "enum": []string{"news", "research", "advisory", "podcast"}},
				"min_severity": map[string]any{"type": "string", "enum": []string{"low", "medium", "high", "critical"}},
				"source":       map[string]any{"type": "string", "description": "feed id to restrict to"},
				"limit":        map[string]any{"type": "integer", "description": "max results, default 15, max 40"},
			},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				Query       string `json:"query"`
				Entity      string `json:"entity"`
				Days        int    `json:"days"`
				Category    string `json:"category"`
				MinSeverity string `json:"min_severity"`
				Source      string `json:"source"`
				Limit       int    `json:"limit"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			days := clampDays(a.Days, 30)
			items, err := tb.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -days))
			if err != nil {
				return nil, "", err
			}
			items = store.FilterItems(items, model.ItemFilter{Since: time.Now().UTC().AddDate(0, 0, -days),
				Category: a.Category, Severity: a.MinSeverity, FeedID: a.Source, Query: a.Query})
			limit := a.Limit
			if limit <= 0 {
				limit = 15
			}
			limit = min(limit, 40)
			var out []brief
			total := 0
			for _, it := range items {
				if a.Entity != "" && !mentions(it, a.Entity) {
					continue
				}
				total++
				if len(out) < limit {
					out = append(out, toBrief(it))
				}
			}
			what := strings.TrimSpace(a.Query + " " + a.Entity)
			return map[string]any{"total_matches": total, "returned": len(out), "days": days, "stories": out},
				fmt.Sprintf("Searched %d days for %q: %d matches", days, what, total), nil
		},
	})

	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "get_story",
			Description: "Get one story by id with its full AI briefing (bullets, why it matters, key details, all tags, rule hits) and optionally the full source article text.",
			Properties: map[string]any{
				"id":                map[string]any{"type": "string"},
				"include_full_text": map[string]any{"type": "boolean", "description": "include the article text (up to ~12k chars)"},
			},
			Required: []string{"id"},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				ID       string `json:"id"`
				FullText bool   `json:"include_full_text"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			it, err := tb.store.GetItem(ctx, a.ID, a.FullText)
			if err != nil {
				return nil, "", fmt.Errorf("story %s: %w", a.ID, err)
			}
			res := map[string]any{"story": toBrief(*it), "bullets": it.Bullets, "why_it_matters": it.WhyItMatters,
				"key_details": it.KeyDetails, "products": it.Tags.Products, "topics": it.Tags.Topics, "author": it.Author}
			if a.FullText {
				txt := it.Content
				if len(txt) > 12000 {
					txt = txt[:12000] + "…"
				}
				res["full_text"] = txt
			}
			return res, "Read story: " + truncate(it.Title, 80), nil
		},
	})

	tb.add(Tool{
		Def: ai.ToolDef{
			Name: "entity_timeline",
			Description: "Track one entity (CVE, threat actor, malware, vendor, product, IOC, or any phrase) across all stored stories: " +
				"first/last seen, number of mentions per source, chronological mentions, and the entities that most often co-occur with it.",
			Properties: map[string]any{
				"value": map[string]any{"type": "string"},
				"days":  map[string]any{"type": "integer", "description": "1-90, default 90"},
			},
			Required: []string{"value"},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				Value string `json:"value"`
				Days  int    `json:"days"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			if strings.TrimSpace(a.Value) == "" {
				return nil, "", fmt.Errorf("value is required")
			}
			days := clampDays(a.Days, 90)
			items, err := tb.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -days))
			if err != nil {
				return nil, "", err
			}
			var hits []model.Item
			bySource := map[string]int{}
			co := map[string]int{}
			lv := strings.ToLower(a.Value)
			for _, it := range items {
				if !mentions(it, a.Value) {
					continue
				}
				hits = append(hits, it)
				bySource[it.FeedName]++
				for _, t := range it.Tags.All() {
					if strings.ToLower(t) != lv {
						co[t]++
					}
				}
			}
			sort.Slice(hits, func(i, j int) bool { return hits[i].Published.Before(hits[j].Published) })
			type kv struct {
				Name  string `json:"name"`
				Count int    `json:"count"`
			}
			var related []kv
			for k, v := range co {
				related = append(related, kv{k, v})
			}
			sort.Slice(related, func(i, j int) bool { return related[i].Count > related[j].Count })
			if len(related) > 20 {
				related = related[:20]
			}
			var timeline []brief
			// Keep the earliest and the most recent mentions when there are many.
			if len(hits) > 30 {
				for _, it := range append(hits[:10], hits[len(hits)-20:]...) {
					timeline = append(timeline, toBrief(it))
				}
			} else {
				for _, it := range hits {
					timeline = append(timeline, toBrief(it))
				}
			}
			res := map[string]any{"value": a.Value, "days": days, "mentions": len(hits), "by_source": bySource,
				"related_entities": related, "timeline": timeline}
			if len(hits) > 0 {
				res["first_seen"] = hits[0].Published.UTC().Format(time.RFC3339)
				res["last_seen"] = hits[len(hits)-1].Published.UTC().Format(time.RFC3339)
			}
			return res, fmt.Sprintf("Timeline for %q: %d mentions in %d days", a.Value, len(hits), days), nil
		},
	})

	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "top_entities",
			Description: "Most-mentioned entities of one type over the last N days, with story counts.",
			Properties: map[string]any{
				"type":  map[string]any{"type": "string", "enum": []string{"cves", "threat_actors", "malware", "vendors", "products", "topics", "iocs"}},
				"days":  map[string]any{"type": "integer", "description": "1-90, default 7"},
				"limit": map[string]any{"type": "integer", "description": "default 15"},
			},
			Required: []string{"type"},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				Type  string `json:"type"`
				Days  int    `json:"days"`
				Limit int    `json:"limit"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			days := clampDays(a.Days, 7)
			items, err := tb.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -days))
			if err != nil {
				return nil, "", err
			}
			counts := map[string]int{}
			for _, it := range items {
				var vals []string
				switch a.Type {
				case "cves":
					vals = it.Tags.CVEs
				case "threat_actors":
					vals = it.Tags.ThreatActors
				case "malware":
					vals = it.Tags.Malware
				case "vendors":
					vals = it.Tags.Vendors
				case "products":
					vals = it.Tags.Products
				case "topics":
					vals = it.Tags.Topics
				case "iocs":
					for _, i := range it.Tags.IOCs {
						vals = append(vals, i.Type+":"+i.Value)
					}
				default:
					return nil, "", fmt.Errorf("unknown type %q", a.Type)
				}
				for _, v := range vals {
					counts[v]++
				}
			}
			type kv struct {
				Name    string `json:"name"`
				Stories int    `json:"stories"`
			}
			var l []kv
			for k, v := range counts {
				l = append(l, kv{k, v})
			}
			sort.Slice(l, func(i, j int) bool {
				return l[i].Stories > l[j].Stories || (l[i].Stories == l[j].Stories && l[i].Name < l[j].Name)
			})
			limit := a.Limit
			if limit <= 0 {
				limit = 15
			}
			if len(l) > limit {
				l = l[:limit]
			}
			return map[string]any{"type": a.Type, "days": days, "top": l}, fmt.Sprintf("Top %s over %d days", a.Type, days), nil
		},
	})

	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "list_alerts",
			Description: "Alerts fired by the user's watch rules in the last N days (rule, story, relevance score, reason).",
			Properties: map[string]any{
				"days": map[string]any{"type": "integer", "description": "1-90, default 7"},
				"rule": map[string]any{"type": "string", "description": "optional rule name or id filter"},
			},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				Days int    `json:"days"`
				Rule string `json:"rule"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			days := clampDays(a.Days, 7)
			as, err := tb.store.ListAlerts(ctx, time.Now().UTC().AddDate(0, 0, -days))
			if err != nil {
				return nil, "", err
			}
			rules, _ := tb.store.ListRules(ctx)
			var ruleInfo []map[string]any
			for _, r := range rules {
				ruleInfo = append(ruleInfo, map[string]any{"id": r.ID, "name": r.Name, "description": r.Description, "mode": r.Mode, "enabled": r.Enabled})
			}
			var out []map[string]any
			for _, al := range as {
				if a.Rule != "" && !strings.EqualFold(al.RuleID, a.Rule) && !strings.EqualFold(al.RuleName, a.Rule) {
					continue
				}
				out = append(out, map[string]any{"rule": al.RuleName, "story_id": al.ItemID, "title": al.Title, "score": al.Score,
					"reason": al.Reason, "severity": al.Severity, "at": al.CreatedAt.UTC().Format(time.RFC3339)})
				if len(out) >= 50 {
					break
				}
			}
			return map[string]any{"rules": ruleInfo, "alerts": out}, fmt.Sprintf("Listed %d alerts over %d days", len(out), days), nil
		},
	})

	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "get_digest",
			Description: "Get a stored daily digest (headline, overview, sections). Omit date for the most recent one.",
			Properties:  map[string]any{"date": map[string]any{"type": "string", "description": "YYYY-MM-DD"}},
		},
		Run: func(ctx context.Context, in json.RawMessage) (any, string, error) {
			var a struct {
				Date string `json:"date"`
			}
			if err := decodeStrict(in, &a); err != nil {
				return nil, "", err
			}
			var d *model.Digest
			var err error
			if a.Date == "" {
				var ds []model.Digest
				ds, err = tb.store.ListDigests(ctx, 1)
				if err == nil && len(ds) > 0 {
					d = &ds[0]
				}
			} else {
				d, err = tb.store.GetDigest(ctx, a.Date)
			}
			if err != nil || d == nil {
				return map[string]any{"found": false}, "No digest found", nil
			}
			return d, "Read digest " + d.Date, nil
		},
	})

	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "list_sources",
			Description: "List configured news sources with category, enabled state and health.",
			Properties:  map[string]any{},
		},
		Run: func(ctx context.Context, _ json.RawMessage) (any, string, error) {
			fs, err := tb.store.ListFeeds(ctx)
			if err != nil {
				return nil, "", err
			}
			var out []map[string]any
			for _, f := range fs {
				out = append(out, map[string]any{"id": f.ID, "name": f.Name, "category": f.Category, "enabled": f.Enabled,
					"status": f.LastStatus, "items": f.ItemCount})
			}
			return out, fmt.Sprintf("Listed %d sources", len(out)), nil
		},
	})
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
