package ai

import (
	"context"
	"encoding/json"
	"errors"
)

// ErrChatUnsupported is returned when the configured provider cannot chat.
var ErrChatUnsupported = errors.New("the agent needs an AI provider (set AI_PROVIDER to claude, azureopenai or ollama)")

// ToolDef describes a client-side tool the model may call.
type ToolDef struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
}

type ToolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

type ToolResult struct {
	CallID  string
	Name    string
	Content string
	IsError bool
}

// PlainMsg is a provider-neutral history entry, used when a chat is resumed
// on a different provider than the one that produced it.
type PlainMsg struct {
	Role string // user | assistant
	Text string
}

type StepResult struct {
	Text      string
	ToolCalls []ToolCall
	Usage     Usage
}

// Session is one agent conversation. It owns the provider-native transcript;
// Drain returns the native entries appended since the previous Drain so they
// can be persisted and replayed byte-for-byte on resume (append-only).
type Session interface {
	AddUser(text string)
	AddToolResults(results []ToolResult)
	// Step makes one model call, streaming text through onText, and appends
	// the assistant turn to the transcript.
	Step(ctx context.Context, onText func(string)) (*StepResult, error)
	Drain() []json.RawMessage
}

// Chatter is implemented by providers that support tool-using chat.
type Chatter interface {
	ChatProvider() string
	ChatModel() string
	// NewSession resumes from native entries when available, else from plain history.
	NewSession(system string, tools []ToolDef, native []json.RawMessage, plain []PlainMsg) (Session, error)
}

// AsChatter returns the provider's chat capability, if any.
func AsChatter(p Provider) (Chatter, bool) {
	if e, ok := p.(*engine); ok {
		if c, ok := e.l.(Chatter); ok {
			return c, true
		}
	}
	c, ok := p.(Chatter)
	return c, ok
}
