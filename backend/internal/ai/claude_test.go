package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"cynewsfeed/internal/config"
)

// fakeAnthropic records the last request and returns a canned Messages response.
func fakeAnthropic(t *testing.T, stopReason, text string) (*httptest.Server, *map[string]any, *http.Header) {
	t.Helper()
	var body map[string]any
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/messages") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		hdr = r.Header.Clone()
		resp := map[string]any{
			"id": "msg_test", "type": "message", "role": "assistant", "model": body["model"],
			"content":     []any{map[string]any{"type": "text", "text": text}},
			"stop_reason": stopReason,
			"usage":       map[string]any{"input_tokens": 1200, "output_tokens": 300, "cache_read_input_tokens": 800, "cache_creation_input_tokens": 0},
		}
		if stopReason == "refusal" {
			resp["stop_details"] = map[string]any{"type": "refusal", "category": "cyber", "explanation": "test"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &body, &hdr
}

func testCfg() *config.Config {
	return &config.Config{AnthropicAPIKey: "test-key", ClaudeModel: "claude-opus-5-5", ClaudeDigestModel: "claude-opus-5-5",
		ClaudeEffort: "low", ClaudeDigestEffort: "medium", ClaudeFallbacks: true, AIMaxChars: 1000}
}

func TestClaudeEnrichRequestShape(t *testing.T) {
	out := `{"tldr":"Attackers exploit CVE-2026-1234 in Acme VPN.","bullets":["Patch now"],"why_it_matters":"Widely deployed.",
		"severity":"critical","tags":{"cves":["CVE-2026-1234"],"threat_actors":[],"malware":[],"vendors":["Acme"],"products":["Acme VPN"],"topics":["vulnerability"]},
		"rule_scores":[{"rule_id":"vpn","score":140,"reason":"VPN zero-day"}]}`
	srv, body, hdr := fakeAnthropic(t, "end_turn", out)
	l, err := newClaude(testCfg(), option.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{l: l, maxChars: 1000}
	enr, usage, err := e.Enrich(context.Background(), EnrichInput{
		Title: "Acme VPN zero-day", Source: "Test", Category: "news", Link: "https://x", Published: time.Now(),
		Text: strings.Repeat("a", 5000), Rules: []RuleBrief{{ID: "vpn", Name: "VPN", Description: "VPN appliance exploitation"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if enr.Severity != "critical" || enr.Tags.CVEs[0] != "CVE-2026-1234" {
		t.Fatalf("bad enrichment %+v", enr)
	}
	if enr.RuleScores[0].Score != 100 {
		t.Fatalf("score not clamped: %d", enr.RuleScores[0].Score)
	}
	if usage.Input != 2000 || usage.Cached != 800 || usage.Output != 300 {
		t.Fatalf("usage %+v", usage)
	}

	b := *body
	if b["model"] != "claude-opus-5-5" {
		t.Errorf("model = %v", b["model"])
	}
	if b["fallbacks"] != "default" {
		t.Errorf("fallbacks = %v", b["fallbacks"])
	}
	if !strings.Contains(hdr.Get("anthropic-beta"), "server-side-fallback-2026-07-01") {
		t.Errorf("beta header = %q", hdr.Get("anthropic-beta"))
	}
	oc, _ := b["output_config"].(map[string]any)
	if oc["effort"] != "low" {
		t.Errorf("effort = %v", oc["effort"])
	}
	format, _ := oc["format"].(map[string]any)
	if format["type"] != "json_schema" || format["schema"] == nil {
		t.Errorf("format = %v", format)
	}
	if _, ok := b["thinking"]; ok {
		t.Errorf("thinking should be omitted (adaptive by default)")
	}
	sys, _ := b["system"].([]any)
	if len(sys) != 1 || !strings.Contains(sys[0].(map[string]any)["text"].(string), "rule_id: vpn") {
		t.Errorf("system prompt missing rules: %v", sys)
	}
	if sys[0].(map[string]any)["cache_control"] == nil {
		t.Errorf("system prompt not cacheable")
	}
	msgs := b["messages"].([]any)
	content := msgs[0].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(content, "[…truncated]") || len(content) > 1500 {
		t.Errorf("article text not capped (len %d)", len(content))
	}
}

func TestClaudeRefusalIsError(t *testing.T) {
	srv, _, _ := fakeAnthropic(t, "refusal", "")
	l, _ := newClaude(testCfg(), option.WithBaseURL(srv.URL))
	_, _, err := (&engine{l: l}).Enrich(context.Background(), EnrichInput{Title: "x", Text: "y"})
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("want refusal error, got %v", err)
	}
}

func TestClaudeHaikuSkipsFallbacks(t *testing.T) {
	srv, body, hdr := fakeAnthropic(t, "end_turn", `{"scores":[{"item_id":"a","score":80,"reason":"r"}]}`)
	cfg := testCfg()
	cfg.ClaudeModel = "claude-haiku-5-5"
	l, _ := newClaude(cfg, option.WithBaseURL(srv.URL))
	scores, _, err := (&engine{l: l}).ScoreBatch(context.Background(), RuleBrief{Name: "r", Description: "d"}, []ItemBrief{{ID: "a", Title: "t"}})
	if err != nil || len(scores) != 1 || scores[0].Score != 80 {
		t.Fatalf("scores %v err %v", scores, err)
	}
	if _, ok := (*body)["fallbacks"]; ok {
		t.Errorf("haiku request must not send fallbacks")
	}
	if hdr.Get("anthropic-beta") != "" {
		t.Errorf("unexpected beta header %q", hdr.Get("anthropic-beta"))
	}
}

func TestDigestUsesDigestModelAndEffort(t *testing.T) {
	srv, body, _ := fakeAnthropic(t, "end_turn", `{"headline":"h","overview":"o","sections":[{"title":"s","items":[{"item_id":"1","line":"l"}]}]}`)
	cfg := testCfg()
	cfg.ClaudeDigestModel = "claude-sonnet-5-5"
	l, _ := newClaude(cfg, option.WithBaseURL(srv.URL))
	d, _, err := (&engine{l: l}).Digest(context.Background(), DigestInput{Date: "2026-11-19", Items: []DigestItem{{ID: "1", Title: "t"}}})
	if err != nil || d.Headline != "h" {
		t.Fatalf("digest %v err %v", d, err)
	}
	if (*body)["model"] != "claude-sonnet-5-5" {
		t.Errorf("model = %v", (*body)["model"])
	}
	if (*body)["output_config"].(map[string]any)["effort"] != "medium" {
		t.Errorf("effort = %v", (*body)["output_config"])
	}
}

func TestSchemasStrict(t *testing.T) {
	// Every object must list all properties as required and forbid extras
	// (required by Claude structured outputs and Azure OpenAI strict mode).
	var walk func(path string, s map[string]any)
	walk = func(path string, s map[string]any) {
		if s["type"] == "object" {
			props := s["properties"].(Ordered)
			req := s["required"].([]string)
			if len(req) != len(props.Keys) || s["additionalProperties"] != false {
				t.Errorf("%s: not strict", path)
			}
			for _, k := range props.Keys {
				walk(path+"."+k, props.Props[k].(map[string]any))
			}
		}
		if s["type"] == "array" {
			walk(path+"[]", s["items"].(map[string]any))
		}
	}
	walk("enrich", enrichSchema)
	walk("score", scoreSchema)
	walk("digest", digestSchema)
}

func TestSchemaPropertyOrder(t *testing.T) {
	b, _ := json.Marshal(detectionSchema)
	js := string(b)
	if strings.Index(js, `"title"`) > strings.Index(js, `"query"`) {
		t.Fatalf("title must precede query: %s", js)
	}
	b, _ = json.Marshal(enrichSchema)
	js = string(b)
	if strings.Index(js, `"tldr"`) > strings.Index(js, `"tags"`) {
		t.Fatalf("tldr must precede tags")
	}
}
