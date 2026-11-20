// Package ai provides pluggable LLM backends for summarisation, entity
// tagging, semantic rule scoring and digest generation.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cynewsfeed/internal/config"
	"cynewsfeed/internal/model"
)

type RuleBrief struct {
	ID          string
	Name        string
	Description string
	Keywords    []string
}

type EnrichInput struct {
	Title     string
	Source    string
	Category  model.Category
	Link      string
	Published time.Time
	Text      string
	Rules     []RuleBrief
}

type RuleScore struct {
	RuleID string `json:"rule_id"`
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

type Enrichment struct {
	Attack       []model.Technique `json:"attack"`
	Atlas        []model.Technique `json:"atlas"`
	OwaspLLM     []string          `json:"owasp_llm"`
	TLDR         string            `json:"tldr"`
	Bullets      []string          `json:"bullets"`
	WhyItMatters string            `json:"why_it_matters"`
	Severity     string            `json:"severity"`
	Tags         wireTags          `json:"tags"`
	KeyDetails   []model.KeyDetail `json:"key_details"`
	RuleScores   []RuleScore       `json:"rule_scores"`
}

type wireTags struct {
	CVEs         []string    `json:"cves"`
	ThreatActors []string    `json:"threat_actors"`
	Malware      []string    `json:"malware"`
	Vendors      []string    `json:"vendors"`
	Products     []string    `json:"products"`
	Topics       []string    `json:"topics"`
	IOCs         []model.IOC `json:"iocs"`
}

func (w wireTags) Model() model.Tags {
	return model.Tags{CVEs: w.CVEs, ThreatActors: w.ThreatActors, Malware: w.Malware,
		Vendors: w.Vendors, Products: w.Products, Topics: w.Topics, IOCs: w.IOCs}
}

type ItemBrief struct {
	ID      string
	Title   string
	Summary string
}

type ItemScore struct {
	ItemID string `json:"item_id"`
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

type DigestItem struct {
	ID       string
	Title    string
	Source   string
	Category string
	Severity string
	TLDR     string
	Tags     []string
	RuleHits []string
}

type DigestInput struct {
	Date  string
	Items []DigestItem
}

type DigestOutput struct {
	Headline string `json:"headline"`
	Overview string `json:"overview"`
	Sections []struct {
		Title string `json:"title"`
		Items []struct {
			ItemID string `json:"item_id"`
			Line   string `json:"line"`
		} `json:"items"`
	} `json:"sections"`
}

type Usage struct {
	Model      string
	Input      int64 // total input tokens, including cache reads/writes
	Output     int64
	Cached     int64   // cache-read input tokens
	CacheWrite int64   // cache-creation input tokens
	Cost       float64 // estimated USD, filled by Add
}

type Provider interface {
	Name() string
	Model() string
	Enrich(ctx context.Context, in EnrichInput) (*Enrichment, Usage, error)
	ScoreBatch(ctx context.Context, rule RuleBrief, items []ItemBrief) ([]ItemScore, Usage, error)
	Digest(ctx context.Context, in DigestInput) (*DigestOutput, Usage, error)
	Detections(ctx context.Context, story string, formats []string) ([]model.Detection, Usage, error)
	WeeklyBrief(ctx context.Context, input string) (*BriefOutput, Usage, error)
}

type BriefOutput struct {
	Title            string             `json:"title"`
	ExecutiveSummary string             `json:"executive_summary"`
	KeyRisks         []model.ReportRisk `json:"key_risks"`
	TopEvents        []struct {
		Title   string   `json:"title"`
		Why     string   `json:"why"`
		ItemIDs []string `json:"item_ids"`
	} `json:"top_events"`
	MetricsNote     string   `json:"metrics_note"`
	Recommendations []string `json:"recommendations"`
}

// task selects per-task model/effort settings inside a backend.
type task int

const (
	taskItem task = iota
	taskDigest
	taskDetect // detection engineering: uses the chat/agent model
)

// llm is the minimal capability each backend implements: one system+user
// turn constrained to a JSON schema, returning the raw JSON text.
type llm interface {
	name() string
	model(t task) string
	completeJSON(ctx context.Context, t task, system, user, schemaName string, schema map[string]any) (string, Usage, error)
}

// engine implements Provider on top of any llm using shared prompts/schemas.
type engine struct {
	l        llm
	maxChars int
}

func (e *engine) Name() string  { return e.l.name() }
func (e *engine) Model() string { return e.l.model(taskItem) }

func (e *engine) Enrich(ctx context.Context, in EnrichInput) (*Enrichment, Usage, error) {
	text := in.Text
	if e.maxChars > 0 && len(text) > e.maxChars {
		// Article bodies beyond this are almost always comments/boilerplate;
		// the cap is configurable via AI_MAX_CHARS.
		text = text[:e.maxChars] + "\n[…truncated]"
	}
	user := fmt.Sprintf("<article>\nSource: %s\nCategory: %s\nPublished: %s\nTitle: %s\nURL: %s\n\n%s\n</article>",
		in.Source, in.Category, in.Published.Format(time.RFC1123), in.Title, in.Link, text)
	raw, u, err := e.l.completeJSON(ctx, taskItem, enrichSystemPrompt(in.Rules), user, "item_enrichment", enrichSchema)
	if err != nil {
		return nil, u, err
	}
	var out Enrichment
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, u, fmt.Errorf("decode enrichment: %w", err)
	}
	for i := range out.RuleScores {
		out.RuleScores[i].Score = clamp(out.RuleScores[i].Score)
	}
	return &out, u, nil
}

func (e *engine) ScoreBatch(ctx context.Context, rule RuleBrief, items []ItemBrief) ([]ItemScore, Usage, error) {
	var b strings.Builder
	for _, it := range items {
		fmt.Fprintf(&b, "<item id=%q>\n%s\n%s\n</item>\n", it.ID, it.Title, it.Summary)
	}
	raw, u, err := e.l.completeJSON(ctx, taskItem, scoreSystemPrompt(rule), b.String(), "rule_scores", scoreSchema)
	if err != nil {
		return nil, u, err
	}
	var out struct {
		Scores []ItemScore `json:"scores"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, u, fmt.Errorf("decode scores: %w", err)
	}
	for i := range out.Scores {
		out.Scores[i].Score = clamp(out.Scores[i].Score)
	}
	return out.Scores, u, nil
}

func (e *engine) Digest(ctx context.Context, in DigestInput) (*DigestOutput, Usage, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "Date: %s\nCandidate items (%d):\n", in.Date, len(in.Items))
	for _, it := range in.Items {
		fmt.Fprintf(&b, "<item id=%q source=%q category=%q severity=%q>\n%s\n%s\n", it.ID, it.Source, it.Category, it.Severity, it.Title, it.TLDR)
		if len(it.Tags) > 0 {
			fmt.Fprintf(&b, "tags: %s\n", strings.Join(it.Tags, ", "))
		}
		if len(it.RuleHits) > 0 {
			fmt.Fprintf(&b, "matched watch rules: %s\n", strings.Join(it.RuleHits, ", "))
		}
		b.WriteString("</item>\n")
	}
	raw, u, err := e.l.completeJSON(ctx, taskDigest, digestSystemPrompt, b.String(), "daily_digest", digestSchema)
	if err != nil {
		return nil, u, err
	}
	var out DigestOutput
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, u, fmt.Errorf("decode digest: %w", err)
	}
	return &out, u, nil
}

func (e *engine) Detections(ctx context.Context, story string, formats []string) ([]model.Detection, Usage, error) {
	user := fmt.Sprintf("Requested formats: %s\n\n<story>\n%s\n</story>", strings.Join(formats, ", "), story)
	raw, u, err := e.l.completeJSON(ctx, taskDetect, detectionPrompt, user, "detections", detectionSchema)
	if err != nil {
		return nil, u, err
	}
	var out struct {
		Detections []model.Detection `json:"detections"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, u, fmt.Errorf("decode detections: %w", err)
	}
	return out.Detections, u, nil
}

func (e *engine) WeeklyBrief(ctx context.Context, input string) (*BriefOutput, Usage, error) {
	raw, u, err := e.l.completeJSON(ctx, taskDigest, briefPrompt, input, "weekly_brief", briefSchema)
	if err != nil {
		return nil, u, err
	}
	var out BriefOutput
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, u, fmt.Errorf("decode brief: %w", err)
	}
	return &out, u, nil
}

func clamp(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

// New builds the configured provider.
func New(cfg *config.Config) (Provider, error) {
	switch cfg.AIProvider {
	case "claude":
		l, err := newClaude(cfg)
		if err != nil {
			return nil, err
		}
		return &engine{l: l, maxChars: cfg.AIMaxChars}, nil
	case "azureopenai":
		return &engine{l: newAzureOpenAI(cfg), maxChars: cfg.AIMaxChars}, nil
	case "ollama":
		return &engine{l: newOllama(cfg), maxChars: cfg.AIMaxChars}, nil
	case "none", "":
		return Heuristic{}, nil
	}
	return nil, fmt.Errorf("unknown AI provider %q", cfg.AIProvider)
}
