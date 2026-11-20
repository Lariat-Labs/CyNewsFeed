// Package mcp exposes the read-only CyNewsFeed toolbox as a Model Context
// Protocol server, over Streamable HTTP (POST /mcp) and stdio (`cynews mcp`).
package mcp

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"cynewsfeed/internal/agent"
)

const latestProtocol = "2025-06-18"

var supported = map[string]bool{"2025-06-18": true, "2025-03-26": true, "2024-11-05": true}

type Server struct {
	tools   *agent.Toolbox
	version string
	Token   string // bearer token for HTTP; empty + Open=false disables HTTP
	Open    bool   // no auth (local development only)
}

func New(tb *agent.Toolbox, version string) *Server { return &Server{tools: tb, version: version} }

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const instructions = `CyNewsFeed: a read-only cybersecurity intelligence dataset (news, vendor research, advisories, CISA KEV, podcasts, AI-security sources and an OSV supply-chain watch) with AI summaries and tags (CVEs, threat actors, malware, IOCs, MITRE ATT&CK/ATLAS, OWASP LLM Top 10). Use search_stories / entity_timeline / list_events / trending to research; get_story for detail; list_iocs for indicators; lookup_cve for NVD and KEV data. Cite story ids and links.`

// Handle processes one JSON-RPC message (or batch) and returns the response
// bytes, or nil for notifications.
func (s *Server) Handle(ctx context.Context, raw []byte) []byte {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var batch []json.RawMessage
		if err := json.Unmarshal(raw, &batch); err != nil {
			return mustJSON(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
		}
		var out []json.RawMessage
		for _, m := range batch {
			if r := s.handleOne(ctx, m); r != nil {
				out = append(out, r)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return mustJSON(out)
	}
	return s.handleOne(ctx, raw)
}

func (s *Server) handleOne(ctx context.Context, raw []byte) []byte {
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return mustJSON(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
	}
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	result, rerr := s.dispatch(ctx, req)
	if isNotification {
		return nil
	}
	resp := response{JSONRPC: "2.0", ID: req.ID}
	if rerr != nil {
		resp.Error = rerr
	} else {
		resp.Result = result
	}
	return mustJSON(resp)
}

func (s *Server) dispatch(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		pv := latestProtocol
		if supported[p.ProtocolVersion] {
			pv = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": pv,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "cynewsfeed", "title": "CyNewsFeed threat intel", "version": s.version},
			"instructions":    instructions,
		}, nil
	case "notifications/initialized", "notifications/cancelled":
		return nil, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		var tools []map[string]any
		for _, d := range s.tools.Defs() {
			req := d.Required
			if req == nil {
				req = []string{}
			}
			tools = append(tools, map[string]any{
				"name": d.Name, "description": d.Description,
				"inputSchema": map[string]any{"type": "object", "properties": d.Properties, "required": req},
				"annotations": map[string]any{"readOnlyHint": true, "openWorldHint": d.Name == "lookup_cve" || d.Name == "ioc_reputation"},
			})
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{-32602, "invalid params: name is required"}
		}
		out, summary, err := s.tools.Call(ctx, p.Name, p.Arguments)
		if err != nil {
			if strings.HasPrefix(err.Error(), "unknown tool") {
				return nil, &rpcError{-32602, err.Error()}
			}
			// Tool execution errors are reported in-band so the model can recover.
			return map[string]any{"content": []map[string]any{{"type": "text", "text": "Error: " + err.Error()}}, "isError": true}, nil
		}
		var structured any
		_ = json.Unmarshal([]byte(out), &structured)
		res := map[string]any{"content": []map[string]any{{"type": "text", "text": out}}, "isError": false}
		if m, ok := structured.(map[string]any); ok {
			res["structuredContent"] = m
		}
		_ = summary
		return res, nil
	case "resources/list":
		return map[string]any{"resources": []any{}}, nil
	case "prompts/list":
		return map[string]any{"prompts": []any{}}, nil
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// ServeHTTP implements the Streamable HTTP transport (JSON responses, no SSE stream).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.Open {
		if s.Token == "" {
			http.Error(w, "MCP over HTTP is disabled (set MCP_TOKEN)", http.StatusNotFound)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cynewsfeed-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK) // stateless: nothing to terminate
		return
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "this server does not offer an SSE stream; use POST", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	out := s.Handle(r.Context(), body)
	if out == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// ServeStdio speaks newline-delimited JSON-RPC on stdin/stdout (for local MCP clients).
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp := s.Handle(ctx, line); resp != nil {
				mu.Lock()
				fmt.Fprintf(out, "%s\n", resp)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return sc.Err()
}
