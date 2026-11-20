package analysis

import (
	"testing"
	"time"

	"cynewsfeed/internal/model"
)

func TestClusterAndTrends(t *testing.T) {
	now := time.Now().UTC()
	it := func(id, feed, title string, ago time.Duration, cves []string, mal []string, sev model.Severity) model.Item {
		return model.Item{ID: id, FeedID: feed, FeedName: feed, Title: title, Published: now.Add(-ago), Severity: sev,
			Tags: model.Tags{CVEs: cves, Malware: mal}}
	}
	items := []model.Item{
		it("a", "bleeping", "Ivanti Connect Secure zero-day exploited in the wild", 2*time.Hour, []string{"CVE-2026-1"}, nil, model.SevCritical),
		it("b", "record", "CISA orders agencies to patch Ivanti flaw", 5*time.Hour, []string{"CVE-2026-1"}, nil, model.SevHigh),
		it("c", "talos", "New QuietCrab backdoor targets telecoms", 3*time.Hour, nil, []string{"QuietCrab"}, model.SevHigh),
		it("d", "sophos", "QuietCrab malware linked to espionage campaign", 30*time.Hour, nil, []string{"QuietCrab"}, model.SevMedium),
		it("e", "news", "Google Chrome 140 released with new features", 1*time.Hour, nil, nil, model.SevInfo),
		it("f", "news2", "Microsoft Teams adds meeting recap", 2*time.Hour, nil, nil, model.SevInfo),
		// Same CVE but far outside the window: must not join.
		it("g", "old", "Older Ivanti story", 20*24*time.Hour, []string{"CVE-2026-1"}, nil, model.SevHigh),
		// Title-similarity cluster without shared entities.
		it("h", "ars", "Salt Typhoon breached three more US telecom carriers", 4*time.Hour, nil, nil, model.SevHigh),
		it("i", "record", "Salt Typhoon breached US telecom carriers, officials say", 6*time.Hour, nil, nil, model.SevHigh),
	}
	evs := Cluster(items, 4*24*time.Hour)
	if len(evs) != 3 {
		for _, e := range evs {
			t.Logf("%s %v", e.Title, e.Items)
		}
		t.Fatalf("want 3 events, got %d", len(evs))
	}
	if evs[0].Title != "Ivanti Connect Secure zero-day exploited in the wild" || evs[0].Sources != 2 || evs[0].Severity != model.SevCritical {
		t.Fatalf("top event %+v", evs[0])
	}
	for _, e := range evs {
		for _, x := range e.Items {
			if x.ID == "g" || x.ID == "e" || x.ID == "f" {
				t.Fatalf("unrelated item %s clustered into %q", x.ID, e.Title)
			}
		}
	}

	// Trends: QuietCrab appears 3x recently, never in baseline.
	items = append(items, it("j", "x", "QuietCrab again", 10*time.Hour, nil, []string{"QuietCrab"}, model.SevLow))
	tr := Trends(items, now, 3, 9, 2)
	if len(tr) == 0 || tr[0].Name != "QuietCrab" || !tr[0].New || tr[0].Recent != 3 || len(tr[0].Daily) != 12 {
		t.Fatalf("trends %+v", tr)
	}
}

func TestFrameworks(t *testing.T) {
	items := []model.Item{
		{ID: "1", Tags: model.Tags{Attack: []model.Technique{{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access"}}, OwaspLLM: []string{"LLM01"}}},
		{ID: "2", Tags: model.Tags{Attack: []model.Technique{{ID: "T1190", Tactic: "Initial Access"}, {ID: "T1059"}}, Atlas: []model.Technique{{ID: "AML.T0051", Tactic: "Initial Access"}}}},
	}
	c := Frameworks(items)
	ia := c.Attack["Initial Access"]
	if len(ia) != 1 || ia[0].Count != 2 || ia[0].Name == "" || len(c.Attack["Unspecified"]) != 1 {
		t.Fatalf("attack %+v", c.Attack)
	}
	if c.OWASP["LLM01"] != 1 || c.TaggedAI != 2 || c.TaggedAttack != 2 || c.Atlas["Initial Access"][0].ID != "AML.T0051" {
		t.Fatalf("coverage %+v", c)
	}
}
