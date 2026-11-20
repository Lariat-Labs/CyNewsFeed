package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/config"
	"cynewsfeed/internal/feeds"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/notify"
	"cynewsfeed/internal/store"
)

// fakeAI scores the "vpn" rule high for titles containing "VPN" and can be
// told to fail.
type fakeAI struct {
	fail  atomic.Bool
	calls atomic.Int32
}

func (f *fakeAI) Name() string  { return "fake" }
func (f *fakeAI) Model() string { return "fake-1" }
func (f *fakeAI) Enrich(_ context.Context, in ai.EnrichInput) (*ai.Enrichment, ai.Usage, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return nil, ai.Usage{}, errors.New("boom")
	}
	e := &ai.Enrichment{TLDR: "Summary of " + in.Title, Bullets: []string{"- one", "two"}, Severity: "medium"}
	for _, r := range in.Rules {
		score := 10
		if r.ID == "vpn" && strings.Contains(in.Title, "VPN") {
			score = 88
		}
		e.RuleScores = append(e.RuleScores, ai.RuleScore{RuleID: r.ID, Score: score, Reason: "test"})
	}
	if strings.Contains(in.Title, "VPN") {
		e.Severity = "critical"
	}
	return e, ai.Usage{Model: "fake-1", Input: 100, Output: 20}, nil
}
func (f *fakeAI) ScoreBatch(_ context.Context, _ ai.RuleBrief, items []ai.ItemBrief) ([]ai.ItemScore, ai.Usage, error) {
	var out []ai.ItemScore
	for _, it := range items {
		s := 5
		if strings.Contains(it.Title, "VPN") {
			s = 90
		}
		out = append(out, ai.ItemScore{ItemID: it.ID, Score: s})
	}
	return out, ai.Usage{}, nil
}
func (f *fakeAI) Digest(_ context.Context, in ai.DigestInput) (*ai.DigestOutput, ai.Usage, error) {
	out := &ai.DigestOutput{Headline: "Big day", Overview: "Stuff happened"}
	out.Sections = append(out.Sections, struct {
		Title string `json:"title"`
		Items []struct {
			ItemID string `json:"item_id"`
			Line   string `json:"line"`
		} `json:"items"`
	}{Title: "Top"})
	for _, it := range in.Items {
		out.Sections[0].Items = append(out.Sections[0].Items, struct {
			ItemID string `json:"item_id"`
			Line   string `json:"line"`
		}{it.ID, it.Title})
	}
	out.Sections[0].Items = append(out.Sections[0].Items, struct {
		ItemID string `json:"item_id"`
		Line   string `json:"line"`
	}{"hallucinated", "should be dropped"})
	return out, ai.Usage{Model: "fake-1"}, nil
}

func (f *fakeAI) Detections(_ context.Context, story string, formats []string) ([]model.Detection, ai.Usage, error) {
	f.calls.Add(1)
	if !strings.Contains(story, "CVE-2026-4242") {
		return nil, ai.Usage{}, errors.New("story missing context")
	}
	return []model.Detection{
		{Format: "sigma", Title: "VPN exploit", Query: "```yaml\ntitle: VPN exploit\nlogsource:\n  category: webserver\ndetection:\n  sel:\n    cs-uri-stem|contains: '/dana-na/'\n  condition: sel\n```"},
		{Format: "kql", Title: "Broken", Query: "DeviceNetworkEvents | where (RemoteIP == \"1.2.3.4\""},
	}, ai.Usage{Model: "fake-1", Input: 500, Output: 200}, nil
}

func (f *fakeAI) WeeklyBrief(_ context.Context, input string) (*ai.BriefOutput, ai.Usage, error) {
	f.calls.Add(1)
	out := &ai.BriefOutput{Title: "Week of VPN pain", ExecutiveSummary: "Summary.", Recommendations: []string{"Patch VPNs"},
		KeyRisks: []model.ReportRisk{{Title: "VPN", Detail: "d", Recommendation: "r"}}}
	ids := regexp.MustCompile(`id ([a-f0-9]{20})`).FindAllStringSubmatch(input, -1)
	ev := struct {
		Title   string   `json:"title"`
		Why     string   `json:"why"`
		ItemIDs []string `json:"item_ids"`
	}{Title: "VPN zero-day", Why: "w", ItemIDs: []string{"hallucinated"}}
	for _, m := range ids {
		ev.ItemIDs = append(ev.ItemIDs, m[1])
	}
	out.TopEvents = append(out.TopEvents, ev)
	return out, ai.Usage{Model: "fake-1", Input: 1000, Output: 300}, nil
}

func feedServer(t *testing.T) *httptest.Server {
	now := time.Now().UTC()
	doc := `<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>
<item><title>Acme VPN zero-day exploited</title><link>https://news.example/vpn</link><description>Attackers exploit CVE-2026-4242 in Acme VPN appliances, a long enough description to avoid fetching full text in tests. ` + strings.Repeat("Details. ", 80) + `</description><pubDate>%s</pubDate></item>
<item><title>New LockBit ransomware variant</title><link>https://news.example/lockbit?utm_source=rss</link><description>LockBit returns. ` + strings.Repeat("More. ", 120) + `</description><pubDate>%s</pubDate></item>
<item><title>Ancient story</title><link>https://news.example/old</link><description>old</description><pubDate>%s</pubDate></item>
</channel></rss>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, doc, now.Format(time.RFC1123Z), now.Add(-time.Hour).Format(time.RFC1123Z), now.AddDate(0, 0, -30).Format(time.RFC1123Z))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type slackSink struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func (s *slackSink) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		s.mu.Lock()
		s.msgs = append(s.msgs, m)
		s.mu.Unlock()
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setup(t *testing.T) (*Pipeline, *store.Memory, *fakeAI, *slackSink) {
	t.Helper()
	fsrv := feedServer(t)
	sink := &slackSink{}
	ssrv := sink.server(t)
	cfg := &config.Config{BackfillDays: 3, FetchConcurrency: 4, AIConcurrency: 2, MaxItemsPerFeedPerRun: 25,
		RetentionDays: 90, FetchTimeout: 5 * time.Second, Location: time.UTC, SeedDefaultFeeds: false, AutoSummarize: true}
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.UpsertFeed(ctx, &model.Feed{ID: "test", Name: "Test News", URL: fsrv.URL, Kind: model.FeedRSS, Category: model.CatNews, Enabled: true, Weight: 3})
	_ = st.UpsertRule(ctx, &model.Rule{ID: "vpn", Name: "VPN exploitation", Description: "Exploitation of VPN appliances", Mode: model.ModeSemantic, Threshold: 70, Enabled: true})
	_ = st.UpsertRule(ctx, &model.Rule{ID: "ransom", Name: "Ransomware", Keywords: []string{"lockbit"}, Mode: model.ModeKeyword, Enabled: true})
	_ = st.UpsertRule(ctx, &model.Rule{ID: "off", Name: "Disabled", Keywords: []string{"acme"}, Mode: model.ModeKeyword, Enabled: false})
	fake := &fakeAI{}
	p := New(cfg, st, feeds.NewFetcher(5*time.Second, "test"), fake, notify.NewSlack(ssrv.URL, "http://app", true))
	return p, st, fake, sink
}

func TestAggregateEndToEnd(t *testing.T) {
	p, st, fake, sink := setup(t)
	ctx := context.Background()
	run, err := p.RunAggregate(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if run.Stats.NewItems != 2 || run.Stats.Enriched != 2 || run.Stats.Alerts != 2 {
		t.Fatalf("stats %+v", run.Stats)
	}
	items, _ := st.ListItems(ctx, time.Now().AddDate(0, 0, -7))
	if len(items) != 2 {
		t.Fatalf("items %d", len(items))
	}
	byTitle := map[string]model.Item{}
	for _, it := range items {
		byTitle[it.Title] = it
	}
	vpn := byTitle["Acme VPN zero-day exploited"]
	if vpn.Severity != model.SevCritical || vpn.AIStatus != model.AIDone || len(vpn.RuleHits) != 1 || vpn.RuleHits[0].RuleID != "vpn" {
		t.Fatalf("vpn item %+v", vpn)
	}
	if len(vpn.Tags.CVEs) != 1 || vpn.Tags.CVEs[0] != "CVE-2026-4242" {
		t.Fatalf("regex CVEs not merged: %v", vpn.Tags.CVEs)
	}
	if vpn.Bullets[0] != "one" {
		t.Fatalf("bullets not cleaned: %v", vpn.Bullets)
	}
	lb := byTitle["New LockBit ransomware variant"]
	if len(lb.RuleHits) != 1 || lb.RuleHits[0].RuleID != "ransom" {
		t.Fatalf("lockbit hits %+v", lb.RuleHits)
	}
	if len(sink.msgs) != 2 {
		t.Fatalf("slack messages %d", len(sink.msgs))
	}
	alerts, _ := st.ListAlerts(ctx, time.Now().Add(-time.Hour))
	for _, a := range alerts {
		if !a.Notified {
			t.Errorf("alert not marked notified: %+v", a)
		}
	}
	f, _ := st.GetFeed(ctx, "test")
	if f.LastStatus != "ok" || f.ItemCount != 2 {
		t.Fatalf("feed health %+v", f)
	}

	// Second run: everything is deduped, no new AI calls or alerts.
	calls := fake.calls.Load()
	run2, err := p.RunAggregate(ctx, "test")
	if err != nil || run2.Stats.NewItems != 0 || fake.calls.Load() != calls || len(sink.msgs) != 2 {
		t.Fatalf("second run not idempotent: %+v err %v", run2.Stats, err)
	}

	// Digest drops hallucinated IDs and links real items.
	d, err := p.RunDigest(ctx, "test", true)
	if err != nil {
		t.Fatal(err)
	}
	if d.Headline != "Big day" || len(d.Sections[0].Items) != 2 || d.Sections[0].Items[0].Link == "" {
		t.Fatalf("digest %+v", d)
	}
	if len(sink.msgs) != 3 {
		t.Fatalf("digest not posted to slack")
	}
}

func TestAIFailureRetriesWithoutDuplicateAlerts(t *testing.T) {
	p, st, fake, sink := setup(t)
	ctx := context.Background()
	fake.fail.Store(true)
	run, err := p.RunAggregate(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if run.Stats.AIErrors != 2 {
		t.Fatalf("stats %+v", run.Stats)
	}
	// Keyword rule still fires without AI; semantic rule cannot.
	if run.Stats.Alerts != 1 || len(sink.msgs) != 1 {
		t.Fatalf("alerts %d msgs %d", run.Stats.Alerts, len(sink.msgs))
	}
	fake.fail.Store(false)
	run, err = p.RunAggregate(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if run.Stats.Retried != 2 || run.Stats.Enriched != 2 {
		t.Fatalf("retry stats %+v", run.Stats)
	}
	// Now the semantic VPN rule fires; LockBit keyword alert is not repeated.
	if run.Stats.Alerts != 1 || len(sink.msgs) != 2 {
		t.Fatalf("retry alerts %d msgs %d", run.Stats.Alerts, len(sink.msgs))
	}
	items, _ := st.ListItems(ctx, time.Now().AddDate(0, 0, -7))
	for _, it := range items {
		if it.AIStatus != model.AIDone {
			t.Errorf("item %s still %s", it.Title, it.AIStatus)
		}
	}
}

func TestRunLock(t *testing.T) {
	p, st, _, _ := setup(t)
	unlock, _ := st.Lock(context.Background(), "aggregate")
	defer unlock()
	if _, err := p.RunAggregate(context.Background(), "test"); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}

func TestTestRule(t *testing.T) {
	p, _, _, _ := setup(t)
	ctx := context.Background()
	if _, err := p.RunAggregate(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	res, err := p.TestRule(ctx, model.Rule{ID: "t", Name: "VPN", Description: "VPN exploitation", Mode: model.ModeHybrid, Threshold: 70}, 7, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || !res[0].WouldAlert || res[0].Score != 90 {
		t.Fatalf("results %+v", res)
	}
}

func TestSummariesOffByDefaultAndOnDemand(t *testing.T) {
	p, st, fake, sink := setup(t)
	ctx := context.Background()
	p.cfg.AutoSummarize = false // the shipped default
	run, err := p.RunAggregate(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls.Load() != 0 || run.Stats.Enriched != 0 || run.Stats.CostUSD != 0 {
		t.Fatalf("scheduled run must not call AI: calls=%d stats=%+v", fake.calls.Load(), run.Stats)
	}
	items, _ := st.ListItems(ctx, time.Now().AddDate(0, 0, -7))
	var vpnID string
	for _, it := range items {
		if it.AIStatus != model.AISkipped || it.TLDR == "" {
			t.Fatalf("expected heuristic, skipped item: %+v", it)
		}
		if strings.Contains(it.Title, "VPN") {
			vpnID = it.ID
			if len(it.Tags.CVEs) != 1 {
				t.Fatalf("regex CVEs should still be extracted: %v", it.Tags.CVEs)
			}
		}
	}
	// Keyword rule still alerts for free; the semantic VPN rule cannot yet.
	if run.Stats.Alerts != 1 || len(sink.msgs) != 1 {
		t.Fatalf("alerts=%d msgs=%d", run.Stats.Alerts, len(sink.msgs))
	}

	// On-demand summary uses AI, fires the semantic rule once, records usage.
	out, usage, err := p.SummarizeItems(ctx, []string{vpnID}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls.Load() != 1 || out[0].AIStatus != model.AIDone || out[0].Severity != model.SevCritical || usage.Input != 100 {
		t.Fatalf("summarize: calls=%d item=%+v usage=%+v", fake.calls.Load(), out[0], usage)
	}
	if len(sink.msgs) != 2 {
		t.Fatalf("semantic alert should fire after summarizing: %d", len(sink.msgs))
	}
	if _, _, err := p.SummarizeItems(ctx, []string{vpnID}, "tester"); err != nil || len(sink.msgs) != 2 {
		t.Fatalf("re-summarizing must not re-alert: %v msgs=%d", err, len(sink.msgs))
	}
	recs, _ := st.ListUsage(ctx, time.Now().Add(-time.Hour))
	if len(recs) != 2 || recs[0].Kind != "summarize" {
		t.Fatalf("usage ledger %+v", recs)
	}

	// Stored setting overrides env default.
	_ = p.SaveAISettings(ctx, model.AISettings{AutoSummarize: true})
	if !p.AISettings(ctx).AutoSummarize {
		t.Fatal("setting not applied")
	}

	// Scheduled digest without AI makes no model call.
	before := fake.calls.Load()
	d, err := p.RunDigest(ctx, "test", false)
	if err != nil || fake.calls.Load() != before || d.Headline == "Big day" {
		t.Fatalf("heuristic digest: %+v err=%v", d, err)
	}
}

func TestEstimateCost(t *testing.T) {
	var u ai.Usage
	u.Add(ai.Usage{Model: "claude-opus-5-5", Input: 1_000_000, Output: 100_000})
	if u.Cost < 5.99 || u.Cost > 6.01 {
		t.Fatalf("opus cost %v", u.Cost)
	}
	var h ai.Usage
	h.Add(ai.Usage{Model: "claude-haiku-5-5", Input: 1_000_000, Cached: 500_000, Output: 100_000})
	if h.Cost < 0.0999 || h.Cost > 0.1051 { // 0.05 + 0.005 + 0.05
		t.Fatalf("haiku cost %v", h.Cost)
	}
}

func TestDetectionsAndWeeklyBrief(t *testing.T) {
	p, st, _, _ := setup(t)
	ctx := context.Background()
	if _, err := p.RunAggregate(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	items, _ := st.ListItems(ctx, time.Now().AddDate(0, 0, -7))
	var vpn model.Item
	for _, it := range items {
		if strings.Contains(it.Title, "VPN") {
			vpn = it
		}
	}
	ds, usage, err := p.GenerateDetections(ctx, vpn.ID, nil)
	if err != nil || len(ds) != 2 || usage.Input != 500 {
		t.Fatalf("detections %+v %v", ds, err)
	}
	if !ds[0].Valid || strings.HasPrefix(ds[0].Query, "```") || ds[1].Valid || ds[1].Issue == "" {
		t.Fatalf("validation %+v", ds)
	}
	stored, _ := st.GetItem(ctx, vpn.ID, false)
	if len(stored.Detections) != 2 {
		t.Fatal("detections not stored on item")
	}

	r, err := p.WeeklyBrief(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Title != "Week of VPN pain" || r.Metrics["stories"] != 2 || len(r.TopEvents) != 1 {
		t.Fatalf("report %+v", r)
	}
	for _, id := range r.TopEvents[0].ItemIDs {
		if id == "hallucinated" {
			t.Fatal("invalid ids must be dropped")
		}
	}
	if got, err := st.GetReport(ctx, r.ID); err != nil || got.Title != r.Title {
		t.Fatalf("stored report %v %v", got, err)
	}
	md := ReportMarkdown(r, "https://app")
	if !strings.Contains(md, "# Week of VPN pain") || !strings.Contains(md, "| stories | 2 |") {
		t.Fatalf("markdown:\n%s", md)
	}
	recs, _ := st.ListUsage(ctx, time.Now().Add(-time.Hour))
	kinds := map[string]bool{}
	for _, u := range recs {
		kinds[u.Kind] = true
	}
	if !kinds["detections"] || !kinds["brief"] {
		t.Fatalf("usage kinds %v", kinds)
	}
}
