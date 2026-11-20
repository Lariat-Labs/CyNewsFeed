// Package model defines the domain types shared across the app.
package model

import (
	"encoding/json"
	"strings"
	"time"
)

type FeedKind string

const (
	FeedRSS     FeedKind = "rss"
	FeedCISAKEV FeedKind = "cisa-kev"
	FeedOSV     FeedKind = "osv-watch" // AI supply-chain watch over the package inventory
)

type Category string

const (
	CatNews     Category = "news"
	CatResearch Category = "research"
	CatAdvisory Category = "advisory"
	CatPodcast  Category = "podcast"
	CatAI       Category = "ai-security"
)

type Feed struct {
	ID           string    `json:"id" yaml:"id"`
	Name         string    `json:"name" yaml:"name"`
	URL          string    `json:"url" yaml:"url"`
	SiteURL      string    `json:"siteUrl,omitempty" yaml:"siteUrl,omitempty"`
	Kind         FeedKind  `json:"kind" yaml:"kind"`
	Category     Category  `json:"category" yaml:"category"`
	Enabled      bool      `json:"enabled" yaml:"enabled"`
	Weight       int       `json:"weight" yaml:"weight"` // 1-5 ranking weight for digests
	ETag         string    `json:"-" yaml:"-"`
	LastModified string    `json:"-" yaml:"-"`
	LastFetched  time.Time `json:"lastFetched,omitzero" yaml:"-"`
	LastStatus   string    `json:"lastStatus,omitempty" yaml:"-"` // ok | not-modified | error
	LastError    string    `json:"lastError,omitempty" yaml:"-"`
	LastNewItems int       `json:"lastNewItems" yaml:"-"`
	ItemCount    int       `json:"itemCount" yaml:"-"`
	CreatedAt    time.Time `json:"createdAt,omitzero" yaml:"-"`
}

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

var severityRank = map[Severity]int{SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4}

func (s Severity) Rank() int { return severityRank[s] }

func NormalizeSeverity(s string) Severity {
	sv := Severity(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := severityRank[sv]; ok {
		return sv
	}
	return SevInfo
}

type Tags struct {
	CVEs         []string `json:"cves"`
	ThreatActors []string `json:"threatActors"`
	Malware      []string `json:"malware"`
	Vendors      []string `json:"vendors"`
	Products     []string `json:"products"`
	Topics       []string `json:"topics"`
	IOCs         []IOC    `json:"iocs,omitempty"`
	// Framework mappings (from AI summaries, or explicit IDs found in text).
	Attack   []Technique `json:"attack,omitempty"`   // MITRE ATT&CK Enterprise
	Atlas    []Technique `json:"atlas,omitempty"`    // MITRE ATLAS (AI/ML)
	OwaspLLM []string    `json:"owaspLlm,omitempty"` // OWASP Top 10 for LLM Apps 2025: LLM01..LLM10
}

// Technique is a MITRE ATT&CK or ATLAS technique reference.
type Technique struct {
	ID     string `json:"id"` // T1190, T1059.001, AML.T0051
	Name   string `json:"name,omitempty"`
	Tactic string `json:"tactic,omitempty"`
}

// IOC is a network or file indicator of compromise, stored refanged.
type IOC struct {
	Type  string `json:"type"` // ip | domain | url | md5 | sha1 | sha256 | email
	Value string `json:"value"`
}

// KeyDetail is a follow-up-worthy phrase the AI flagged in the summary.
type KeyDetail struct {
	Text   string `json:"text"`   // exact substring of tldr/bullets/whyItMatters
	Kind   string `json:"kind"`   // deadline | exploitation | impact | action | scope | other
	Reason string `json:"reason"` // why it's worth following up
}

// All returns every tag value (used for tag filtering).
func (t Tags) All() []string {
	var out []string
	for _, l := range [][]string{t.CVEs, t.ThreatActors, t.Malware, t.Vendors, t.Products, t.Topics} {
		out = append(out, l...)
	}
	for _, i := range t.IOCs {
		out = append(out, i.Value)
	}
	for _, x := range t.Attack {
		out = append(out, x.ID)
	}
	for _, x := range t.Atlas {
		out = append(out, x.ID)
	}
	out = append(out, t.OwaspLLM...)
	return out
}

type RuleHit struct {
	RuleID          string   `json:"ruleId"`
	RuleName        string   `json:"ruleName"`
	Score           int      `json:"score"`
	Reason          string   `json:"reason,omitempty"`
	MatchedKeywords []string `json:"matchedKeywords,omitempty"`
}

type AIStatus string

const (
	AIPending AIStatus = "pending"
	AIDone    AIStatus = "done"
	AIError   AIStatus = "error"
	AISkipped AIStatus = "skipped"
)

type Item struct {
	ID           string      `json:"id"`
	FeedID       string      `json:"feedId"`
	FeedName     string      `json:"feedName"`
	Category     Category    `json:"category"`
	Title        string      `json:"title"`
	Link         string      `json:"link"`
	Published    time.Time   `json:"published"`
	Fetched      time.Time   `json:"fetched"`
	Author       string      `json:"author,omitempty"`
	Snippet      string      `json:"snippet,omitempty"`
	TLDR         string      `json:"tldr,omitempty"`
	Bullets      []string    `json:"bullets,omitempty"`
	WhyItMatters string      `json:"whyItMatters,omitempty"`
	KeyDetails   []KeyDetail `json:"keyDetails,omitempty"`
	Detections   []Detection `json:"detections,omitempty"`
	Severity     Severity    `json:"severity"`
	Tags         Tags        `json:"tags"`
	RuleHits     []RuleHit   `json:"ruleHits,omitempty"`
	AudioURL     string      `json:"audioUrl,omitempty"`
	ImageURL     string      `json:"imageUrl,omitempty"`
	Duration     string      `json:"duration,omitempty"`
	AIStatus     AIStatus    `json:"aiStatus"`
	AIModel      string      `json:"aiModel,omitempty"`
	AIAttempts   int         `json:"aiAttempts"`
	AIError      string      `json:"aiError,omitempty"`
	Read         bool        `json:"read"`
	Starred      bool        `json:"starred"`

	// Content is the full text used for AI enrichment. Stored in blob storage,
	// never in the table entity; only populated on detail reads.
	Content string `json:"content,omitempty"`
}

type RuleMode string

const (
	ModeKeyword  RuleMode = "keyword"
	ModeSemantic RuleMode = "semantic"
	ModeHybrid   RuleMode = "hybrid"
)

type Rule struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"` // plain-English intent used for semantic matching
	Keywords     []string  `json:"keywords"`
	Regexes      []string  `json:"regexes"`
	Mode         RuleMode  `json:"mode"`
	Threshold    int       `json:"threshold"`
	MinSeverity  Severity  `json:"minSeverity,omitempty"`
	SlackWebhook string    `json:"slackWebhook,omitempty"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"createdAt,omitzero"`
	UpdatedAt    time.Time `json:"updatedAt,omitzero"`
}

// Semantic reports whether the rule wants LLM relevance scoring.
func (r Rule) Semantic() bool { return r.Mode == ModeSemantic || r.Mode == ModeHybrid }

type Alert struct {
	ID              string    `json:"id"`
	RuleID          string    `json:"ruleId"`
	RuleName        string    `json:"ruleName"`
	ItemID          string    `json:"itemId"`
	Title           string    `json:"title"`
	Link            string    `json:"link"`
	FeedName        string    `json:"feedName"`
	Severity        Severity  `json:"severity"`
	Score           int       `json:"score"`
	Reason          string    `json:"reason,omitempty"`
	MatchedKeywords []string  `json:"matchedKeywords,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	Notified        bool      `json:"notified"`
	NotifyError     string    `json:"notifyError,omitempty"`
}

type FeedRunStat struct {
	FeedID   string `json:"feedId"`
	Status   string `json:"status"`
	New      int    `json:"new"`
	Seen     int    `json:"seen"`
	Error    string `json:"error,omitempty"`
	Duration int64  `json:"durationMs"`
}

type RunStats struct {
	Feeds        int           `json:"feeds"`
	FeedErrors   int           `json:"feedErrors"`
	NewItems     int           `json:"newItems"`
	Enriched     int           `json:"enriched"`
	AIErrors     int           `json:"aiErrors"`
	Retried      int           `json:"retried"`
	Alerts       int           `json:"alerts"`
	Purged       int           `json:"purged"`
	CostUSD      float64       `json:"costUsd"`
	InputTokens  int64         `json:"inputTokens"`
	OutputTokens int64         `json:"outputTokens"`
	CachedTokens int64         `json:"cachedTokens"`
	PerFeed      []FeedRunStat `json:"perFeed,omitempty"`
}

type Run struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"` // aggregate | digest
	Trigger  string    `json:"trigger"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitzero"`
	Status   string    `json:"status"` // running | ok | error
	Error    string    `json:"error,omitempty"`
	Stats    RunStats  `json:"stats"`
}

type DigestEntry struct {
	ItemID string `json:"itemId"`
	Line   string `json:"line"`
	Title  string `json:"title,omitempty"`
	Link   string `json:"link,omitempty"`
}

type DigestSection struct {
	Title string        `json:"title"`
	Items []DigestEntry `json:"items"`
}

type Digest struct {
	Date      string          `json:"date"` // YYYY-MM-DD
	Headline  string          `json:"headline"`
	Overview  string          `json:"overview"`
	Sections  []DigestSection `json:"sections"`
	ItemCount int             `json:"itemCount"`
	Model     string          `json:"model,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
}

// ItemFilter is used by list queries.
type ItemFilter struct {
	Days     int
	Since    time.Time
	Category string
	Severity string // minimum severity
	FeedID   string
	Tag      string
	Query    string
	RuleID   string
	OnlyHits bool
	Starred  bool
	Unread   bool
	Limit    int
}

// ---------------- Chat ----------------

type Chat struct {
	ID        string    `json:"id"`
	User      string    `json:"user"` // Entra principal ID ("local" when auth is off)
	UserName  string    `json:"userName,omitempty"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Messages  int       `json:"messages"`
	Provider  string    `json:"provider,omitempty"`
}

// ToolStep records one tool call the agent made while answering.
type ToolStep struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Input   string `json:"input"`             // JSON arguments
	Summary string `json:"summary,omitempty"` // short human-readable result
	Result  string `json:"result,omitempty"`  // JSON result sent to the model (truncated)
	IsError bool   `json:"isError,omitempty"`
}

// ChatMessage is one persisted turn. Assistant turns may span several model
// calls (tool loop); Blocks keeps the provider-native content so the
// conversation can be replayed exactly when a chat is resumed.
type ChatMessage struct {
	Seq       int             `json:"seq"`
	Role      string          `json:"role"` // user | assistant
	Text      string          `json:"text"`
	Steps     []ToolStep      `json:"steps,omitempty"`
	Context   *ChatContext    `json:"context,omitempty"`
	Model     string          `json:"model,omitempty"`
	Error     string          `json:"error,omitempty"`
	Usage     *TokenUsage     `json:"usage,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
	Native    json.RawMessage `json:"native,omitempty"` // provider transcript for exact replay
}

// ChatContext is attached when a message was started from a highlight.
type ChatContext struct {
	EntityType  string `json:"entityType,omitempty"`
	EntityValue string `json:"entityValue,omitempty"`
	ItemID      string `json:"itemId,omitempty"`
	ItemTitle   string `json:"itemTitle,omitempty"`
}

// TokenUsage is the token spend of one AI operation.
type TokenUsage struct {
	Model   string  `json:"model,omitempty"`
	Input   int64   `json:"input"`
	Output  int64   `json:"output"`
	Cached  int64   `json:"cached"`
	CostUSD float64 `json:"costUsd"`
}

// UsageRecord is one entry in the AI spend ledger.
type UsageRecord struct {
	ID    string    `json:"id"`
	Kind  string    `json:"kind"` // aggregate | summarize | digest | chat
	Ref   string    `json:"ref,omitempty"`
	User  string    `json:"user,omitempty"`
	At    time.Time `json:"at"`
	Items int       `json:"items,omitempty"`
	TokenUsage
}

// AISettings controls automatic (scheduled) AI usage. Both default to off:
// stories are only summarised on demand unless enabled.
type AISettings struct {
	AutoSummarize     bool `json:"autoSummarize"`
	ScheduledDigestAI bool `json:"scheduledDigestAI"`
}

// Detection is a generated hunting/detection query for a story.
type Detection struct {
	Format      string `json:"format"` // kql | spl | sigma | yara
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Query       string `json:"query"`
	Confidence  string `json:"confidence,omitempty"` // low | medium | high
	Notes       string `json:"notes,omitempty"`      // tuning / false-positive guidance
	Valid       bool   `json:"valid"`                // passed structural validation
	Issue       string `json:"issue,omitempty"`
}

// InventoryPackage is one entry of the AI supply-chain inventory.
type InventoryPackage struct {
	Ecosystem string `json:"ecosystem"` // PyPI | npm | Go | crates.io | Maven | NuGet | RubyGems
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"` // optional: only advisories affecting this version
}

// Report is an AI-written periodic (weekly) executive brief.
type Report struct {
	ID               string         `json:"id"` // e.g. 2026-W47
	Title            string         `json:"title"`
	PeriodStart      time.Time      `json:"periodStart"`
	PeriodEnd        time.Time      `json:"periodEnd"`
	ExecutiveSummary string         `json:"executiveSummary"`
	KeyRisks         []ReportRisk   `json:"keyRisks"`
	TopEvents        []ReportEvent  `json:"topEvents"`
	Metrics          map[string]int `json:"metrics"`
	MetricsNote      string         `json:"metricsNote,omitempty"`
	Recommendations  []string       `json:"recommendations"`
	Model            string         `json:"model,omitempty"`
	CreatedAt        time.Time      `json:"createdAt"`
}

type ReportRisk struct {
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
}

type ReportEvent struct {
	Title   string   `json:"title"`
	Why     string   `json:"why"`
	ItemIDs []string `json:"itemIds,omitempty"`
}
