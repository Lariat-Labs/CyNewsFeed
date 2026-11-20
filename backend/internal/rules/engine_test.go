package rules

import (
	"testing"

	"cynewsfeed/internal/model"
)

func mustCompile(t *testing.T, r model.Rule) *Compiled {
	t.Helper()
	c, err := Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKeywordBoundaries(t *testing.T) {
	c := mustCompile(t, model.Rule{ID: "r", Keywords: []string{"Okta", "MOVEit Transfer", "C++"}, Mode: model.ModeKeyword})
	cases := map[string]int{
		"Okta support system breached":       1,
		"Oktaberfest is not a vendor":        0,
		"Progress MOVEit   Transfer flaw":    1, // flexible whitespace
		"moveit transfer exploited":          1, // case-insensitive
		"Bug in C++ runtime and okta tenant": 2,
		"nothing relevant here":              0,
	}
	for text, want := range cases {
		if got := len(c.KeywordHits(text)); got != want {
			t.Errorf("%q: got %d hits want %d", text, got, want)
		}
	}
}

func TestRegex(t *testing.T) {
	c := mustCompile(t, model.Rule{ID: "r", Regexes: []string{`CVE-2026-\d+`}, Mode: model.ModeKeyword})
	hits := c.KeywordHits("Patch for cve-2026-12345 released")
	if len(hits) != 1 || hits[0] != "cve-2026-12345" {
		t.Fatalf("hits = %v", hits)
	}
	if _, err := Compile(model.Rule{Regexes: []string{"("}}); err == nil {
		t.Fatal("expected invalid regex error")
	}
}

func TestEvaluateModes(t *testing.T) {
	base := model.Rule{ID: "r", Name: "R", Keywords: []string{"x"}, Threshold: 70}
	tests := []struct {
		name  string
		mode  model.RuleMode
		kws   []string
		llm   int
		sev   model.Severity
		min   model.Severity
		want  bool
		score int
	}{
		{"keyword hit", model.ModeKeyword, []string{"x"}, -1, model.SevInfo, "", true, 100},
		{"keyword miss", model.ModeKeyword, nil, 95, model.SevInfo, "", false, 100},
		{"semantic above", model.ModeSemantic, nil, 75, model.SevInfo, "", true, 75},
		{"semantic below", model.ModeSemantic, []string{"x"}, 60, model.SevInfo, "", false, 60},
		{"hybrid kw boosts", model.ModeHybrid, []string{"x"}, 40, model.SevInfo, "", true, 55},
		{"hybrid llm only", model.ModeHybrid, nil, 80, model.SevInfo, "", true, 80},
		{"hybrid neither", model.ModeHybrid, nil, 50, model.SevInfo, "", false, 50},
		{"no llm degrades to keyword", model.ModeSemantic, []string{"x"}, -1, model.SevInfo, "", true, 100},
		{"min severity blocks", model.ModeKeyword, []string{"x"}, -1, model.SevLow, model.SevHigh, false, 0},
		{"min severity passes", model.ModeKeyword, []string{"x"}, -1, model.SevCritical, model.SevHigh, true, 100},
	}
	for _, tc := range tests {
		r := base
		r.Mode, r.MinSeverity = tc.mode, tc.min
		c := mustCompile(t, r)
		hit, ok := c.Evaluate(tc.kws, tc.llm, "", tc.sev)
		if ok != tc.want || (ok && hit.Score != tc.score) {
			t.Errorf("%s: ok=%v score=%d, want ok=%v score=%d", tc.name, ok, hit.Score, tc.want, tc.score)
		}
	}
}
