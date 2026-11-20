package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cynewsfeed/internal/agent"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/store"
)

func server(t *testing.T) *Server {
	st := store.NewMemory()
	_ = st.PutItem(context.Background(), &model.Item{ID: "x1", Title: "Ivanti zero-day", Published: time.Now(), Severity: model.SevHigh,
		Tags: model.Tags{CVEs: []string{"CVE-2026-1"}, IOCs: []model.IOC{{Type: "ip", Value: "203.0.113.5"}}}})
	return New(agent.NewToolbox(st, nil), "test")
}

func call(t *testing.T, s *Server, msg string) map[string]any {
	t.Helper()
	out := s.Handle(context.Background(), []byte(msg))
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("bad response %s: %v", out, err)
	}
	return m
}

func TestProtocol(t *testing.T) {
	s := server(t)
	init := call(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	res := init["result"].(map[string]any)
	if res["protocolVersion"] != "2025-03-26" || res["serverInfo"].(map[string]any)["name"] != "cynewsfeed" {
		t.Fatalf("initialize %v", init)
	}
	if out := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); out != nil {
		t.Fatalf("notification must not get a response: %s", out)
	}
	list := call(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := list["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, x := range tools {
		tm := x.(map[string]any)
		names[tm["name"].(string)] = true
		if tm["inputSchema"].(map[string]any)["type"] != "object" {
			t.Fatalf("bad schema %v", tm)
		}
	}
	for _, n := range []string{"search_stories", "entity_timeline", "list_events", "trending", "list_iocs", "framework_coverage"} {
		if !names[n] {
			t.Errorf("missing tool %s", n)
		}
	}
	r := call(t, s, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_iocs","arguments":{"type":"ip"}}}`)
	rr := r["result"].(map[string]any)
	if rr["isError"] != false || !strings.Contains(rr["content"].([]any)[0].(map[string]any)["text"].(string), "203.0.113.5") || rr["structuredContent"] == nil {
		t.Fatalf("tools/call %v", r)
	}
	bad := call(t, s, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_story","arguments":{"id":"nope"}}}`)
	if bad["result"].(map[string]any)["isError"] != true {
		t.Fatalf("tool errors must be in-band: %v", bad)
	}
	unk := call(t, s, `{"jsonrpc":"2.0","id":5,"method":"bogus"}`)
	if unk["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Fatalf("unknown method %v", unk)
	}
}

func TestHTTPAuthAndStdio(t *testing.T) {
	s := server(t)
	s.Token = "secret"
	srv := httptest.NewServer(s)
	defer srv.Close()
	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	resp, _ := http.Post(srv.URL, "application/json", strings.NewReader(body))
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", srv.URL, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	req.Header.Set("Authorization", "Bearer secret")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 202 {
		t.Fatalf("notification want 202, got %d", resp.StatusCode)
	}

	var out bytes.Buffer
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	if err := s.ServeStdio(context.Background(), in, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), `"id":1`) {
		t.Fatalf("stdio output %q", out.String())
	}
}
