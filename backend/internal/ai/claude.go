package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"cynewsfeed/internal/config"
)

// claude calls the Anthropic Messages API via the official Go SDK, using
// structured outputs so responses always match the JSON schema.
type claude struct {
	client       anthropic.Client
	itemModel    string
	digestModel  string
	itemEffort   string
	digestEffort string
	chatModel    string
	chatEffort   string
	fallbacks    bool
}

func newClaude(cfg *config.Config, extra ...option.RequestOption) (*claude, error) {
	opts := []option.RequestOption{option.WithMaxRetries(4)}
	if cfg.AnthropicAPIKey != "" {
		opts = append(opts, option.WithAPIKey(cfg.AnthropicAPIKey))
	}
	opts = append(opts, extra...)
	return &claude{
		client:       anthropic.NewClient(opts...),
		itemModel:    cfg.ClaudeModel,
		digestModel:  cfg.ClaudeDigestModel,
		itemEffort:   cfg.ClaudeEffort,
		digestEffort: cfg.ClaudeDigestEffort,
		chatModel:    cfg.ClaudeChatModel,
		chatEffort:   cfg.ClaudeChatEffort,
		fallbacks:    cfg.ClaudeFallbacks,
	}, nil
}

func (c *claude) name() string { return "claude" }

func (c *claude) model(t task) string {
	switch t {
	case taskDigest:
		return c.digestModel
	case taskDetect:
		return c.chatModel
	}
	return c.itemModel
}

func (c *claude) completeJSON(ctx context.Context, t task, system, user, _ string, schema map[string]any) (string, Usage, error) {
	model := c.model(t)
	effort := c.itemEffort
	switch t {
	case taskDigest:
		effort = c.digestEffort
	case taskDetect:
		effort = c.chatEffort
	}
	params := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 16000,
		// The system prompt (instructions + watch rules) is identical across
		// items in a run, so mark it cacheable.
		System: []anthropic.BetaTextBlockParam{{
			Text:         system,
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user)),
		},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Format: anthropic.BetaJSONOutputFormatParam{Schema: schema},
		},
	}
	if effort != "" {
		params.OutputConfig.Effort = anthropic.BetaOutputConfigEffort(effort)
	}
	// Security news can occasionally trip safety classifiers; server-side
	// fallbacks re-serve a declined request on a suitable model in the same call.
	// Not supported on Haiku models.
	if c.fallbacks && !strings.Contains(model, "haiku") {
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
		params.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
	}

	resp, err := c.client.Beta.Messages.New(ctx, params)
	if err != nil {
		var apiErr *anthropic.Error
		if errors.As(err, &apiErr) {
			switch apiErr.StatusCode {
			case 400:
				return "", Usage{Model: model}, fmt.Errorf("claude bad request: %w", err)
			case 401, 403:
				return "", Usage{Model: model}, fmt.Errorf("claude auth failed (check ANTHROPIC_API_KEY): %w", err)
			case 429:
				return "", Usage{Model: model}, fmt.Errorf("claude rate limited after retries: %w", err)
			}
		}
		return "", Usage{Model: model}, fmt.Errorf("claude: %w", err)
	}
	u := Usage{
		Model:      string(resp.Model),
		Input:      resp.Usage.InputTokens + resp.Usage.CacheCreationInputTokens + resp.Usage.CacheReadInputTokens,
		Output:     resp.Usage.OutputTokens,
		Cached:     resp.Usage.CacheReadInputTokens,
		CacheWrite: resp.Usage.CacheCreationInputTokens,
	}
	switch resp.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return "", u, fmt.Errorf("claude declined the request (category %q)", resp.StopDetails.Category)
	case anthropic.BetaStopReasonMaxTokens:
		return "", u, errors.New("claude response hit max_tokens")
	}
	var b strings.Builder
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			b.WriteString(tb.Text)
		}
	}
	if b.Len() == 0 {
		return "", u, errors.New("claude returned no text")
	}
	return b.String(), u, nil
}
