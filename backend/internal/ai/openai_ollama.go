package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"cynewsfeed/internal/config"
)

// postJSON POSTs body and decodes the response, retrying 429/5xx with backoff.
func postJSON(ctx context.Context, client *http.Client, u string, headers map[string]string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return json.Unmarshal(data, out)
			}
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 300))
			if resp.StatusCode != 429 && resp.StatusCode < 500 {
				return lastErr
			}
			if ra, _ := strconv.Atoi(resp.Header.Get("Retry-After")); ra > 0 && ra < 60 {
				if !sleep(ctx, time.Duration(ra)*time.Second) {
					return ctx.Err()
				}
				continue
			}
		}
		if !sleep(ctx, time.Duration(1<<attempt)*time.Second) {
			return ctx.Err()
		}
	}
	return lastErr
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------------- Azure OpenAI ----------------

type azureOpenAI struct {
	client                       *http.Client
	endpoint, key, apiVersion    string
	itemDeployment, digestDeploy string
	chatDeploy                   string
}

func newAzureOpenAI(cfg *config.Config) *azureOpenAI {
	dd := cfg.AzureOpenAIDigestDeployment
	if dd == "" {
		dd = cfg.AzureOpenAIDeployment
	}
	return &azureOpenAI{
		client:   &http.Client{Timeout: 3 * time.Minute},
		endpoint: cfg.AzureOpenAIEndpoint, key: cfg.AzureOpenAIKey, apiVersion: cfg.AzureOpenAIAPIVersion,
		itemDeployment: cfg.AzureOpenAIDeployment, digestDeploy: dd, chatDeploy: cfg.AzureOpenAIChatDeployment,
	}
}

func (a *azureOpenAI) name() string { return "azureopenai" }

func (a *azureOpenAI) model(t task) string {
	switch t {
	case taskDigest:
		return a.digestDeploy
	case taskDetect:
		if a.chatDeploy != "" {
			return a.chatDeploy
		}
		return a.digestDeploy
	}
	return a.itemDeployment
}

func (a *azureOpenAI) completeJSON(ctx context.Context, t task, system, user, schemaName string, schema map[string]any) (string, Usage, error) {
	dep := a.model(t)
	u := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s", a.endpoint, url.PathEscape(dep), url.QueryEscape(a.apiVersion))
	body := map[string]any{
		"messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}},
		"response_format": map[string]any{
			"type":        "json_schema",
			"json_schema": map[string]any{"name": schemaName, "strict": true, "schema": schema},
		},
		"max_completion_tokens": 8000,
	}
	var out struct {
		Model   string `json:"model"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content string `json:"content"`
				Refusal string `json:"refusal"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens        int64 `json:"prompt_tokens"`
			CompletionTokens    int64 `json:"completion_tokens"`
			PromptTokensDetails struct {
				CachedTokens int64 `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if err := postJSON(ctx, a.client, u, map[string]string{"api-key": a.key}, body, &out); err != nil {
		return "", Usage{Model: dep}, fmt.Errorf("azure openai: %w", err)
	}
	us := Usage{Model: firstNonEmptyStr(out.Model, dep), Input: out.Usage.PromptTokens, Output: out.Usage.CompletionTokens, Cached: out.Usage.PromptTokensDetails.CachedTokens}
	if len(out.Choices) == 0 {
		return "", us, fmt.Errorf("azure openai: no choices")
	}
	ch := out.Choices[0]
	if ch.Message.Refusal != "" {
		return "", us, fmt.Errorf("azure openai refused: %s", ch.Message.Refusal)
	}
	if ch.FinishReason == "length" {
		return "", us, fmt.Errorf("azure openai: response truncated")
	}
	return ch.Message.Content, us, nil
}

// ---------------- Ollama ----------------

type ollama struct {
	client *http.Client
	base   string
	mdl    string
}

func newOllama(cfg *config.Config) *ollama {
	return &ollama{client: &http.Client{Timeout: 10 * time.Minute}, base: cfg.OllamaURL, mdl: cfg.OllamaModel}
}

func (o *ollama) name() string      { return "ollama" }
func (o *ollama) model(task) string { return o.mdl }

func (o *ollama) completeJSON(ctx context.Context, _ task, system, user, _ string, schema map[string]any) (string, Usage, error) {
	body := map[string]any{
		"model":    o.mdl,
		"stream":   false,
		"format":   schema,
		"messages": []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}},
		"options":  map[string]any{"temperature": 0.2, "num_ctx": 16384},
	}
	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		PromptEvalCount int64 `json:"prompt_eval_count"`
		EvalCount       int64 `json:"eval_count"`
	}
	if err := postJSON(ctx, o.client, o.base+"/api/chat", nil, body, &out); err != nil {
		return "", Usage{Model: o.mdl}, fmt.Errorf("ollama: %w", err)
	}
	return out.Message.Content, Usage{Model: o.mdl, Input: out.PromptEvalCount, Output: out.EvalCount}, nil
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
