package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// ---------------- Azure OpenAI chat (tool calling) ----------------

func (a *azureOpenAI) ChatProvider() string { return "azureopenai" }
func (a *azureOpenAI) ChatModel() string {
	if a.chatDeploy != "" {
		return a.chatDeploy
	}
	return a.itemDeployment
}

type oaiMsg struct {
	Role       string        `json:"role"`
	Content    *string       `json:"content"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaiSession struct {
	a       *azureOpenAI
	tools   []map[string]any
	msgs    []oaiMsg
	pending []json.RawMessage
}

func strp(s string) *string { return &s }

func (a *azureOpenAI) NewSession(system string, tools []ToolDef, native []json.RawMessage, plain []PlainMsg) (Session, error) {
	s := &oaiSession{a: a, msgs: []oaiMsg{{Role: "system", Content: strp(system)}}}
	for _, t := range tools {
		s.tools = append(s.tools, map[string]any{"type": "function", "function": map[string]any{
			"name": t.Name, "description": t.Description,
			"parameters": map[string]any{"type": "object", "properties": t.Properties, "required": nonNil(t.Required)},
		}})
	}
	if len(native) > 0 {
		for _, raw := range native {
			var m oaiMsg
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, fmt.Errorf("decode chat history: %w", err)
			}
			s.msgs = append(s.msgs, m)
		}
	} else {
		for _, p := range plain {
			s.msgs = append(s.msgs, oaiMsg{Role: p.Role, Content: strp(p.Text)})
		}
	}
	return s, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *oaiSession) push(m oaiMsg) {
	s.msgs = append(s.msgs, m)
	b, _ := json.Marshal(m)
	s.pending = append(s.pending, b)
}

func (s *oaiSession) AddUser(text string) { s.push(oaiMsg{Role: "user", Content: strp(text)}) }

func (s *oaiSession) AddToolResults(rs []ToolResult) {
	for _, r := range rs {
		s.push(oaiMsg{Role: "tool", ToolCallID: r.CallID, Content: strp(r.Content)})
	}
}

func (s *oaiSession) Drain() []json.RawMessage {
	out := s.pending
	s.pending = nil
	return out
}

func (s *oaiSession) Step(ctx context.Context, onText func(string)) (*StepResult, error) {
	dep := s.a.ChatModel()
	u := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s", s.a.endpoint, url.PathEscape(dep), url.QueryEscape(s.a.apiVersion))
	body := map[string]any{"messages": s.msgs, "max_completion_tokens": 8000}
	if len(s.tools) > 0 {
		body["tools"] = s.tools
	}
	var out struct {
		Model   string `json:"model"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      oaiMsg `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := postJSON(ctx, s.a.client, u, map[string]string{"api-key": s.a.key}, body, &out); err != nil {
		return nil, fmt.Errorf("azure openai: %w", err)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("azure openai: no choices")
	}
	m := out.Choices[0].Message
	m.Role = "assistant"
	s.push(m)
	res := &StepResult{Usage: Usage{Model: firstNonEmptyStr(out.Model, dep), Input: out.Usage.PromptTokens, Output: out.Usage.CompletionTokens}}
	if m.Content != nil {
		res.Text = *m.Content
		if onText != nil && res.Text != "" {
			onText(res.Text)
		}
	}
	for _, tc := range m.ToolCalls {
		res.ToolCalls = append(res.ToolCalls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Input: json.RawMessage(tc.Function.Arguments)})
	}
	return res, nil
}

// ---------------- Ollama chat (tool calling) ----------------

func (o *ollama) ChatProvider() string { return "ollama" }
func (o *ollama) ChatModel() string    { return o.mdl }

type ollamaMsg struct {
	Role      string `json:"role"`
	Content   string `json:"content"`
	ToolName  string `json:"tool_name,omitempty"`
	ToolCalls []struct {
		Function struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls,omitempty"`
}

type ollamaSession struct {
	o       *ollama
	tools   []map[string]any
	msgs    []ollamaMsg
	pending []json.RawMessage
}

func (o *ollama) NewSession(system string, tools []ToolDef, native []json.RawMessage, plain []PlainMsg) (Session, error) {
	s := &ollamaSession{o: o, msgs: []ollamaMsg{{Role: "system", Content: system}}}
	for _, t := range tools {
		s.tools = append(s.tools, map[string]any{"type": "function", "function": map[string]any{
			"name": t.Name, "description": t.Description,
			"parameters": map[string]any{"type": "object", "properties": t.Properties, "required": nonNil(t.Required)},
		}})
	}
	if len(native) > 0 {
		for _, raw := range native {
			var m ollamaMsg
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, fmt.Errorf("decode chat history: %w", err)
			}
			s.msgs = append(s.msgs, m)
		}
	} else {
		for _, p := range plain {
			s.msgs = append(s.msgs, ollamaMsg{Role: p.Role, Content: p.Text})
		}
	}
	return s, nil
}

func (s *ollamaSession) push(m ollamaMsg) {
	s.msgs = append(s.msgs, m)
	b, _ := json.Marshal(m)
	s.pending = append(s.pending, b)
}

func (s *ollamaSession) AddUser(text string) { s.push(ollamaMsg{Role: "user", Content: text}) }

func (s *ollamaSession) AddToolResults(rs []ToolResult) {
	for _, r := range rs {
		s.push(ollamaMsg{Role: "tool", ToolName: r.Name, Content: r.Content})
	}
}

func (s *ollamaSession) Drain() []json.RawMessage {
	out := s.pending
	s.pending = nil
	return out
}

func (s *ollamaSession) Step(ctx context.Context, onText func(string)) (*StepResult, error) {
	body := map[string]any{"model": s.o.mdl, "stream": false, "messages": s.msgs, "tools": s.tools,
		"options": map[string]any{"temperature": 0.2, "num_ctx": 32768}}
	var out struct {
		Message         ollamaMsg `json:"message"`
		PromptEvalCount int64     `json:"prompt_eval_count"`
		EvalCount       int64     `json:"eval_count"`
	}
	if err := postJSON(ctx, s.o.client, s.o.base+"/api/chat", nil, body, &out); err != nil {
		return nil, fmt.Errorf("ollama: %w", err)
	}
	m := out.Message
	m.Role = "assistant"
	s.push(m)
	res := &StepResult{Text: m.Content, Usage: Usage{Model: s.o.mdl, Input: out.PromptEvalCount, Output: out.EvalCount}}
	if onText != nil && m.Content != "" {
		onText(m.Content)
	}
	for i, tc := range m.ToolCalls {
		res.ToolCalls = append(res.ToolCalls, ToolCall{ID: fmt.Sprintf("call_%d", i), Name: tc.Function.Name, Input: tc.Function.Arguments})
	}
	return res, nil
}
