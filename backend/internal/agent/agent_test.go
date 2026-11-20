package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/store"
)

// scriptedChatter replays a fixed sequence of steps and records what it saw.
type scriptedChatter struct {
	steps    []ai.StepResult
	sessions []*scriptedSession
}

type scriptedSession struct {
	c       *scriptedChatter
	native  []json.RawMessage
	plain   []ai.PlainMsg
	log     []string
	pending []json.RawMessage
	i       *int
}

func (c *scriptedChatter) ChatProvider() string { return "fake" }
func (c *scriptedChatter) ChatModel() string    { return "fake-chat" }
func (c *scriptedChatter) NewSession(_ string, _ []ai.ToolDef, native []json.RawMessage, plain []ai.PlainMsg) (ai.Session, error) {
	idx := 0
	if len(c.sessions) > 0 {
		idx = *c.sessions[len(c.sessions)-1].i
	}
	s := &scriptedSession{c: c, native: native, plain: plain, i: &idx}
	c.sessions = append(c.sessions, s)
	return s, nil
}
func (s *scriptedSession) add(entry string) {
	s.log = append(s.log, entry)
	b, _ := json.Marshal(entry)
	s.pending = append(s.pending, b)
}
func (s *scriptedSession) AddUser(t string) { s.add("user:" + t) }
func (s *scriptedSession) AddToolResults(rs []ai.ToolResult) {
	for _, r := range rs {
		s.add("tool:" + r.Name + ":" + r.Content)
	}
}
func (s *scriptedSession) Step(_ context.Context, onText func(string)) (*ai.StepResult, error) {
	st := s.c.steps[*s.i]
	*s.i++
	if onText != nil && st.Text != "" {
		onText(st.Text)
	}
	s.add("assistant:" + st.Text)
	return &st, nil
}
func (s *scriptedSession) Drain() []json.RawMessage {
	out := s.pending
	s.pending = nil
	return out
}

// fakeProvider exposes the scripted chatter through ai.AsChatter.
type fakeProvider struct{ *scriptedChatter }

func (fakeProvider) Name() string  { return "fake" }
func (fakeProvider) Model() string { return "fake" }
func (fakeProvider) Enrich(context.Context, ai.EnrichInput) (*ai.Enrichment, ai.Usage, error) {
	return nil, ai.Usage{}, nil
}
func (fakeProvider) ScoreBatch(context.Context, ai.RuleBrief, []ai.ItemBrief) ([]ai.ItemScore, ai.Usage, error) {
	return nil, ai.Usage{}, nil
}
func (fakeProvider) Digest(context.Context, ai.DigestInput) (*ai.DigestOutput, ai.Usage, error) {
	return nil, ai.Usage{}, nil
}
func (fakeProvider) Detections(context.Context, string, []string) ([]model.Detection, ai.Usage, error) {
	return nil, ai.Usage{}, nil
}
func (fakeProvider) WeeklyBrief(context.Context, string) (*ai.BriefOutput, ai.Usage, error) {
	return nil, ai.Usage{}, nil
}

func seed(t *testing.T) *store.Memory {
	st := store.NewMemory()
	ctx := context.Background()
	now := time.Now().UTC()
	items := []model.Item{
		{ID: "a1", Title: "Ivanti zero-day exploited", FeedName: "News", Published: now.Add(-48 * time.Hour), Severity: model.SevCritical,
			TLDR: "Attackers exploit CVE-2026-1111 in Ivanti Connect Secure.", Tags: model.Tags{CVEs: []string{"CVE-2026-1111"}, ThreatActors: []string{"UNC5221"},
				IOCs: []model.IOC{{Type: "ip", Value: "203.0.113.9"}}}},
		{ID: "a2", Title: "CISA adds Ivanti flaw to KEV", FeedName: "CISA", Published: now.Add(-24 * time.Hour), Severity: model.SevHigh,
			TLDR: "CVE-2026-1111 added to KEV.", Tags: model.Tags{CVEs: []string{"CVE-2026-1111"}}},
		{ID: "a3", Title: "Unrelated phishing story", FeedName: "Blog", Published: now.Add(-2 * time.Hour), Severity: model.SevLow, TLDR: "Phishing kit."},
	}
	for i := range items {
		_ = st.PutItem(ctx, &items[i])
	}
	return st
}

func TestToolsOverDataset(t *testing.T) {
	st := seed(t)
	tb := NewToolbox(st, nil)
	ctx := context.Background()

	out, summary, err := tb.Call(ctx, "search_stories", json.RawMessage(`{"entity":"cve-2026-1111"}`))
	if err != nil || !strings.Contains(summary, "2 matches") || !strings.Contains(out, `"a1"`) || strings.Contains(out, `"a3"`) {
		t.Fatalf("search: %s / %s / %v", summary, out, err)
	}
	out, _, err = tb.Call(ctx, "entity_timeline", json.RawMessage(`{"value":"CVE-2026-1111"}`))
	if err != nil {
		t.Fatal(err)
	}
	var tl struct {
		Mentions  int            `json:"mentions"`
		FirstSeen string         `json:"first_seen"`
		Timeline  []brief        `json:"timeline"`
		BySource  map[string]int `json:"by_source"`
		Related   []struct {
			Name string `json:"name"`
		} `json:"related_entities"`
	}
	_ = json.Unmarshal([]byte(out), &tl)
	if tl.Mentions != 2 || tl.Timeline[0].ID != "a1" || tl.BySource["CISA"] != 1 || len(tl.Related) == 0 {
		t.Fatalf("timeline %+v", tl)
	}
	out, _, _ = tb.Call(ctx, "top_entities", json.RawMessage(`{"type":"iocs"}`))
	if !strings.Contains(out, "ip:203.0.113.9") {
		t.Fatalf("top iocs: %s", out)
	}
	if _, _, err := tb.Call(ctx, "search_stories", json.RawMessage(`{"bogus":1}`)); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
	if _, _, err := tb.Call(ctx, "get_story", json.RawMessage(`{"id":"nope"}`)); err == nil {
		t.Fatal("missing story should error")
	}
	if _, _, err := tb.Call(ctx, "rm_rf", nil); err == nil {
		t.Fatal("unknown tool should error")
	}
}

func TestReplyLoopPersistsAndResumes(t *testing.T) {
	st := seed(t)
	ctx := context.Background()
	sc := &scriptedChatter{steps: []ai.StepResult{
		{Text: "Searching.", ToolCalls: []ai.ToolCall{
			{ID: "t1", Name: "search_stories", Input: json.RawMessage(`{"entity":"CVE-2026-1111"}`)},
			{ID: "t2", Name: "get_story", Input: json.RawMessage(`{"id":"missing"}`)},
		}},
		{Text: "CVE-2026-1111 is exploited [[story:a1]]."},
		{Text: "Follow-up answer."},
		{Text: "Plain answer."},
	}}
	ag, err := New(fakeProvider{sc}, NewToolbox(st, nil), st, 5, 90)
	if err != nil {
		t.Fatal(err)
	}
	chat := &model.Chat{ID: "c1", User: "u1", Title: "New chat", CreatedAt: time.Now()}
	_ = st.PutChat(ctx, chat)

	var events []string
	msg, err := ag.Reply(ctx, chat, "Tell me about CVE-2026-1111", "Tell me about CVE-2026-1111", nil, func(e Event) { events = append(events, e.Type) })
	if err != nil {
		t.Fatal(err)
	}
	if msg.Text != "Searching.\n\nCVE-2026-1111 is exploited [[story:a1]]." || len(msg.Steps) != 2 {
		t.Fatalf("msg %+v", msg)
	}
	var errStep *model.ToolStep
	for i := range msg.Steps {
		if msg.Steps[i].IsError {
			errStep = &msg.Steps[i]
		}
	}
	if errStep == nil || errStep.Name != "get_story" {
		t.Fatalf("expected get_story error step: %+v", msg.Steps)
	}
	joined := strings.Join(events, ",")
	if !strings.HasPrefix(joined, "text,text,step_start,step_start,step_end,step_end,text") || !strings.HasSuffix(joined, "done") {
		t.Fatalf("events %s", joined)
	}
	msgs, _ := st.ListChatMessages(ctx, "c1")
	if len(msgs) != 2 || msgs[0].Role != "user" || msgs[1].Role != "assistant" || len(msgs[1].Native) == 0 {
		t.Fatalf("persisted %+v", msgs)
	}
	c, _ := st.GetChat(ctx, "u1", "c1")
	if c.Messages != 2 || c.Provider != "fake" {
		t.Fatalf("chat %+v", c)
	}

	// Resume: the native transcript (user, assistant, 2 tool results, assistant) is replayed.
	if _, err := ag.Reply(ctx, c, "And?", "And?", nil, nil); err != nil {
		t.Fatal(err)
	}
	s2 := sc.sessions[1]
	if len(s2.native) != 5 || len(s2.plain) != 2 {
		t.Fatalf("resume native=%d plain=%d", len(s2.native), len(s2.plain))
	}

	// A chat from another provider falls back to plain text.
	c.Provider = "other"
	if _, err := ag.Reply(ctx, c, "Again?", "Again?", nil, nil); err != nil {
		t.Fatal(err)
	}
	if s3 := sc.sessions[2]; len(s3.native) != 0 || len(s3.plain) != 4 {
		t.Fatalf("provider switch should replay plain text: native=%d plain=%d", len(s3.native), len(s3.plain))
	}
}

func TestPrompts(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutSetting(ctx, "prompts", `{"cve":"Custom {{value}}","unknown":"x"}`)
	p := Prompts(ctx, st)
	if p["cve"] != "Custom {{value}}" || p["actor"] != DefaultPrompts["actor"] {
		t.Fatalf("prompts %v", p["cve"])
	}
	got := RenderPrompt(DefaultPrompts["detail"], model.ChatContext{EntityType: "detail", EntityValue: "patch by Friday", ItemTitle: "Story"}, "deadline")
	if !strings.Contains(got, `"patch by Friday"`) || !strings.Contains(got, "deadline") || strings.Contains(got, "{{") {
		t.Fatalf("render %s", got)
	}
	if PromptKind("sha256") != "ioc" || PromptKind("product") != "vendor" || PromptKind("topic") != "default" {
		t.Fatal("prompt kinds")
	}
}

func TestIntelLookups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/kev"):
			w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-1111","dueDate":"2026-12-01","knownRansomwareCampaignUse":"Known"}]}`))
		case strings.HasPrefix(r.URL.Path, "/nvd"):
			w.Write([]byte(`{"vulnerabilities":[{"cve":{"published":"2026-11-01","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"RCE in Ivanti"}],
			"metrics":{"cvssMetricV31":[{"source":"nvd","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"AV:N"}}]}}}]}`))
		case strings.HasPrefix(r.URL.Path, "/vt/ip_addresses/203.0.113.9"):
			if r.Header.Get("x-apikey") != "vtkey" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":7},"as_owner":"Bad ISP","irrelevant":"x"}}}`))
		case strings.HasPrefix(r.URL.Path, "/abuse/check"):
			w.Write([]byte(`{"data":{"abuseConfidenceScore":93,"totalReports":40}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	in := NewIntel("test", "", "vtkey", "abkey")
	in.KEVURL, in.NVDBase, in.VTBase, in.AbuseBase = srv.URL+"/kev", srv.URL+"/nvd", srv.URL+"/vt", srv.URL+"/abuse"
	tb := NewToolbox(store.NewMemory(), in)
	ctx := context.Background()

	out, summary, err := tb.Call(ctx, "lookup_cve", json.RawMessage(`{"cve":"cve-2026-1111"}`))
	if err != nil || !strings.Contains(summary, "in CISA KEV") || !strings.Contains(out, "RCE in Ivanti") || !strings.Contains(out, "9.8") {
		t.Fatalf("cve: %s %s %v", summary, out, err)
	}
	out, summary, err = tb.Call(ctx, "ioc_reputation", json.RawMessage(`{"type":"ip","value":"203.0.113[.]9"}`))
	if err != nil || !strings.Contains(summary, "VT malicious: 7") || !strings.Contains(out, "abuseConfidenceScore") || strings.Contains(out, "irrelevant") {
		t.Fatalf("rep: %s %s %v", summary, out, err)
	}
	if !strings.Contains(summary, "203.0.113[.]9") {
		t.Fatalf("summary should be defanged: %s", summary)
	}
	// Without keys the reputation tool is not offered.
	if names := strings.Join(NewToolbox(store.NewMemory(), NewIntel("t", "", "", "")).Names(), ","); strings.Contains(names, "ioc_reputation") {
		t.Fatalf("tools %s", names)
	}
}
