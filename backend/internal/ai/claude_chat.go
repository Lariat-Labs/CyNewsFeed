package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/packages/param"
)

func (c *claude) ChatProvider() string { return "claude" }
func (c *claude) ChatModel() string    { return c.chatModel }

type claudeSession struct {
	c        *claude
	system   string
	tools    []anthropic.BetaToolUnionParam
	messages []anthropic.BetaMessageParam
	pending  []json.RawMessage
}

func (c *claude) NewSession(system string, tools []ToolDef, native []json.RawMessage, plain []PlainMsg) (Session, error) {
	s := &claudeSession{c: c, system: system}
	for _, t := range tools {
		tp := anthropic.BetaToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: anthropic.BetaToolInputSchemaParam{Properties: t.Properties, Required: t.Required},
			// Stream tool arguments as they are generated; inputs are validated
			// by the agent before any tool runs.
			EagerInputStreaming: anthropic.Bool(true),
		}
		s.tools = append(s.tools, anthropic.BetaToolUnionParam{OfTool: &tp})
	}
	if len(native) > 0 {
		for _, raw := range native {
			m, err := decodeClaudeMessage(raw)
			if err != nil {
				return nil, err
			}
			s.messages = append(s.messages, m)
		}
	} else {
		for _, p := range plain {
			if p.Role == "assistant" {
				s.messages = append(s.messages, anthropic.BetaMessageParam{OfAssistant: &anthropic.BetaAssistantMessageParam{
					Content: []anthropic.BetaContentBlockParamUnion{anthropic.NewBetaTextBlock(p.Text)},
				}})
			} else {
				s.messages = append(s.messages, anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(p.Text)))
			}
		}
	}
	return s, nil
}

// decodeClaudeMessage restores a persisted message param verbatim, so thinking
// blocks, signatures and fallback blocks are replayed unchanged.
func decodeClaudeMessage(raw json.RawMessage) (anthropic.BetaMessageParam, error) {
	var head struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return anthropic.BetaMessageParam{}, fmt.Errorf("decode chat history: %w", err)
	}
	switch head.Role {
	case "assistant":
		var m anthropic.BetaAssistantMessageParam
		param.SetJSON(raw, &m)
		return anthropic.BetaMessageParam{OfAssistant: &m}, nil
	case "user":
		var m anthropic.BetaUserMessageParam
		param.SetJSON(raw, &m)
		return anthropic.BetaMessageParam{OfUser: &m}, nil
	}
	return anthropic.BetaMessageParam{}, fmt.Errorf("unknown role %q in chat history", head.Role)
}

func (s *claudeSession) push(m anthropic.BetaMessageParam) {
	s.messages = append(s.messages, m)
	if b, err := json.Marshal(m); err == nil {
		s.pending = append(s.pending, b)
	}
}

func (s *claudeSession) AddUser(text string) {
	s.push(anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(text)))
}

func (s *claudeSession) AddToolResults(results []ToolResult) {
	blocks := make([]anthropic.BetaContentBlockParamUnion, 0, len(results))
	for _, r := range results {
		blocks = append(blocks, anthropic.NewBetaToolResultBlock(r.CallID, r.Content, r.IsError))
	}
	// All results for one assistant turn go back in a single user message.
	s.push(anthropic.NewBetaUserMessage(blocks...))
}

func (s *claudeSession) Drain() []json.RawMessage {
	out := s.pending
	s.pending = nil
	return out
}

func (s *claudeSession) Step(ctx context.Context, onText func(string)) (*StepResult, error) {
	c := s.c
	params := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(c.chatModel),
		MaxTokens: 64000,
		System: []anthropic.BetaTextBlockParam{{
			Text:         s.system,
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		}},
		Messages: s.messages,
		Tools:    s.tools,
		// Auto-cache the growing conversation prefix across tool-loop steps.
		CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
	}
	if c.chatEffort != "" {
		params.OutputConfig.Effort = anthropic.BetaOutputConfigEffort(c.chatEffort)
	}
	if c.fallbacks && !strings.Contains(c.chatModel, "haiku") {
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
		params.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
	}

	stream := c.client.Beta.Messages.NewStreaming(ctx, params)
	msg := anthropic.BetaMessage{}
	for stream.Next() {
		ev := stream.Current()
		if err := msg.Accumulate(ev); err != nil {
			return nil, fmt.Errorf("claude stream: %w", err)
		}
		if d, ok := ev.AsAny().(anthropic.BetaRawContentBlockDeltaEvent); ok {
			if t, ok := d.Delta.AsAny().(anthropic.BetaTextDelta); ok && onText != nil {
				onText(t.Text)
			}
		}
	}
	if err := stream.Err(); err != nil {
		var apiErr *anthropic.Error
		if errors.As(err, &apiErr) && (apiErr.StatusCode == 401 || apiErr.StatusCode == 403) {
			return nil, fmt.Errorf("claude auth failed (check ANTHROPIC_API_KEY): %w", err)
		}
		return nil, fmt.Errorf("claude: %w", err)
	}

	res := &StepResult{Usage: Usage{
		Model:      string(msg.Model),
		Input:      msg.Usage.InputTokens + msg.Usage.CacheCreationInputTokens + msg.Usage.CacheReadInputTokens,
		Output:     msg.Usage.OutputTokens,
		Cached:     msg.Usage.CacheReadInputTokens,
		CacheWrite: msg.Usage.CacheCreationInputTokens,
	}}
	switch msg.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return res, fmt.Errorf("claude declined to answer (category %q)", msg.StopDetails.Category)
	case anthropic.BetaStopReasonMaxTokens:
		return res, errors.New("the answer hit the output token limit")
	}

	// Append the full assistant turn (thinking, text, tool_use) before tool results.
	s.push(msg.ToParam())

	var text strings.Builder
	for _, block := range msg.Content {
		switch b := block.AsAny().(type) {
		case anthropic.BetaTextBlock:
			text.WriteString(b.Text)
		case anthropic.BetaToolUseBlock:
			res.ToolCalls = append(res.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Input: json.RawMessage(b.JSON.Input.Raw())})
		}
	}
	res.Text = text.String()
	return res, nil
}
