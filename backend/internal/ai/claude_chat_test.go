package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

func sse(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range events {
		var m map[string]any
		_ = json.Unmarshal([]byte(e), &m)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", m["type"], e)
	}
}

// Two-step conversation: (1) thinking + text + tool_use, (2) final text.
func TestClaudeChatToolLoopAndReplay(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		bodies = append(bodies, body)
		if len(bodies) == 1 {
			sse(w,
				`{"type":"message_start","message":{"id":"m1","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"stop_reason":null,"usage":{"input_tokens":50,"output_tokens":1}}}`,
				`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`,
				`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"SIG123"}}`,
				`{"type":"content_block_stop","index":0}`,
				`{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
				`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Let me search."}}`,
				`{"type":"content_block_stop","index":1}`,
				`{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_1","name":"search_stories","input":{}}}`,
				`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"entity\":"}}`,
				`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"\"CVE-2026-1\"}"}}`,
				`{"type":"content_block_stop","index":2}`,
				`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":40}}`,
				`{"type":"message_stop"}`,
			)
			return
		}
		sse(w,
			`{"type":"message_start","message":{"id":"m2","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"stop_reason":null,"usage":{"input_tokens":90,"output_tokens":1}}}`,
			`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Found it [[story:abc]]."}}`,
			`{"type":"content_block_stop","index":0}`,
			`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":12}}`,
			`{"type":"message_stop"}`,
		)
	}))
	defer srv.Close()

	cfg := testCfg()
	cfg.ClaudeChatModel, cfg.ClaudeChatEffort = "claude-opus-5-5", "medium"
	c, _ := newClaude(cfg, option.WithBaseURL(srv.URL))
	tools := []ToolDef{{Name: "search_stories", Description: "search", Properties: map[string]any{"entity": map[string]any{"type": "string"}}}}
	sess, err := c.NewSession("SYSTEM", tools, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sess.AddUser("What about CVE-2026-1?")
	var streamed strings.Builder
	res, err := sess.Step(context.Background(), func(s string) { streamed.WriteString(s) })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolCalls) != 1 || res.ToolCalls[0].Name != "search_stories" || string(res.ToolCalls[0].Input) != `{"entity":"CVE-2026-1"}` {
		t.Fatalf("tool calls %+v", res.ToolCalls)
	}
	sess.AddToolResults([]ToolResult{{CallID: "toolu_1", Name: "search_stories", Content: `{"total":1}`}})
	res, err = sess.Step(context.Background(), func(s string) { streamed.WriteString(s) })
	if err != nil || res.Text != "Found it [[story:abc]]." {
		t.Fatalf("res %+v err %v", res, err)
	}
	if streamed.String() != "Let me search.Found it [[story:abc]]." {
		t.Fatalf("streamed %q", streamed.String())
	}

	// First request: tools with eager streaming, auto-caching, effort, fallbacks.
	b0 := bodies[0]
	tl := b0["tools"].([]any)[0].(map[string]any)
	if tl["eager_input_streaming"] != true || b0["cache_control"] == nil || b0["fallbacks"] != "default" {
		t.Errorf("request 1 shape: %v", b0)
	}
	if b0["output_config"].(map[string]any)["effort"] != "medium" || b0["stream"] != true {
		t.Errorf("request 1 config: %v", b0)
	}

	// Second request must replay the assistant turn unchanged (thinking
	// signature included) followed by the tool_result.
	msgs := bodies[1]["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("want 3 messages, got %d", len(msgs))
	}
	asst := msgs[1].(map[string]any)["content"].([]any)
	if asst[0].(map[string]any)["type"] != "thinking" || asst[0].(map[string]any)["signature"] != "SIG123" {
		t.Errorf("thinking block not replayed: %v", asst[0])
	}
	tr := msgs[2].(map[string]any)["content"].([]any)[0].(map[string]any)
	if tr["type"] != "tool_result" || tr["tool_use_id"] != "toolu_1" {
		t.Errorf("tool result: %v", tr)
	}

	// Resume: persisted native entries rebuild the identical transcript.
	native := sess.Drain()
	if len(native) != 4 {
		t.Fatalf("native entries %d", len(native))
	}
	resumed, err := c.NewSession("SYSTEM", tools, native, nil)
	if err != nil {
		t.Fatal(err)
	}
	resumed.AddUser("And now?")
	_, _ = resumed.Step(context.Background(), nil)
	replayed := bodies[2]["messages"].([]any)
	if len(replayed) != 5 {
		t.Fatalf("resumed transcript has %d messages", len(replayed))
	}
	a1, _ := json.Marshal(msgs[1])
	a2, _ := json.Marshal(replayed[1])
	if string(a1) != string(a2) {
		t.Errorf("assistant turn changed on resume:\n%s\n%s", a1, a2)
	}
}
