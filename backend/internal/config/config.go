// Package config loads runtime configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port          string
	PublicBaseURL string
	LogLevel      string
	LogFormat     string

	// Storage
	StorageMode          string // azure | memory
	StorageConnString    string // Azurite / connection string
	StorageAccount       string // account name (managed identity)
	StorageTablePrefix   string
	StorageBlobContainer string

	// AI
	AIProvider    string // claude | azureopenai | ollama | none
	AIConcurrency int
	AIMaxChars    int

	AnthropicAPIKey    string
	ClaudeModel        string
	ClaudeDigestModel  string
	ClaudeEffort       string
	ClaudeDigestEffort string
	ClaudeFallbacks    bool
	ClaudeChatModel    string
	ClaudeChatEffort   string

	AzureOpenAIEndpoint         string
	AzureOpenAIKey              string
	AzureOpenAIDeployment       string
	AzureOpenAIDigestDeployment string
	AzureOpenAIChatDeployment   string
	AzureOpenAIAPIVersion       string

	OllamaURL   string
	OllamaModel string

	// Notifications
	SlackWebhookURL string
	SlackEnabled    bool

	// Scheduling
	SchedulerEnabled bool
	RunOnStart       bool
	FetchCron        string
	DigestCron       string
	Location         *time.Location

	// Pipeline
	RetentionDays         int
	BackfillDays          int
	FetchConcurrency      int
	FetchTimeout          time.Duration
	FetchFullText         bool
	MaxItemsPerFeedPerRun int
	DefaultRuleThreshold  int
	SeedDefaultFeeds      bool
	AutoSummarize         bool
	ScheduledDigestAI     bool
	UserAgent             string

	// Auth
	AuthMode string // none | easyauth

	// Sharing / integrations
	TAXIIToken    string
	MCPToken      string
	MISPURL       string
	MISPKey       string
	MISPVerifyTLS bool
	OSVURL        string

	// Agent
	AgentMaxSteps int
	VirusTotalKey string
	AbuseIPDBKey  string
	NVDKey        string
}

func Load() (*Config, error) {
	tzName := env("TZ", "UTC")
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		return nil, fmt.Errorf("invalid TZ %q: %w", tzName, err)
	}
	c := &Config{
		Port:          env("PORT", "8080"),
		PublicBaseURL: strings.TrimRight(env("PUBLIC_BASE_URL", "http://localhost:8080"), "/"),
		LogLevel:      env("LOG_LEVEL", "info"),
		LogFormat:     env("LOG_FORMAT", "text"),

		StorageMode:          env("STORAGE_MODE", "azure"),
		StorageConnString:    env("AZURE_STORAGE_CONNECTION_STRING", ""),
		StorageAccount:       env("AZURE_STORAGE_ACCOUNT", ""),
		StorageTablePrefix:   env("STORAGE_TABLE_PREFIX", "cynews"),
		StorageBlobContainer: env("STORAGE_BLOB_CONTAINER", "cynews"),

		AIProvider:    strings.ToLower(env("AI_PROVIDER", "none")),
		AIConcurrency: envInt("AI_CONCURRENCY", 4),
		AIMaxChars:    envInt("AI_MAX_CHARS", 24000),

		AnthropicAPIKey:    env("ANTHROPIC_API_KEY", ""),
		ClaudeModel:        env("CLAUDE_MODEL", "claude-haiku-5-5"),
		ClaudeDigestModel:  env("CLAUDE_DIGEST_MODEL", "claude-opus-5-5"),
		ClaudeEffort:       env("CLAUDE_EFFORT", "low"),
		ClaudeDigestEffort: env("CLAUDE_DIGEST_EFFORT", "medium"),
		ClaudeFallbacks:    envBool("CLAUDE_FALLBACKS", true),
		ClaudeChatModel:    env("CLAUDE_CHAT_MODEL", "claude-opus-5-5"),
		ClaudeChatEffort:   env("CLAUDE_CHAT_EFFORT", "medium"),

		AzureOpenAIEndpoint:         strings.TrimRight(env("AZURE_OPENAI_ENDPOINT", ""), "/"),
		AzureOpenAIKey:              env("AZURE_OPENAI_API_KEY", ""),
		AzureOpenAIDeployment:       env("AZURE_OPENAI_DEPLOYMENT", ""),
		AzureOpenAIDigestDeployment: env("AZURE_OPENAI_DIGEST_DEPLOYMENT", ""),
		AzureOpenAIChatDeployment:   env("AZURE_OPENAI_CHAT_DEPLOYMENT", ""),
		AzureOpenAIAPIVersion:       env("AZURE_OPENAI_API_VERSION", "2024-10-21"),

		OllamaURL:   strings.TrimRight(env("OLLAMA_URL", "http://localhost:11434"), "/"),
		OllamaModel: env("OLLAMA_MODEL", "llama3.1:8b"),

		SlackWebhookURL: env("SLACK_WEBHOOK_URL", ""),
		SlackEnabled:    envBool("SLACK_ENABLED", true),

		SchedulerEnabled: envBool("SCHEDULER_ENABLED", false),
		RunOnStart:       envBool("RUN_ON_START", false),
		FetchCron:        env("FETCH_CRON", "0 * * * *"),
		DigestCron:       env("DIGEST_CRON", "0 8 * * *"),
		Location:         loc,

		RetentionDays:         envInt("RETENTION_DAYS", 90),
		BackfillDays:          envInt("BACKFILL_DAYS", 3),
		FetchConcurrency:      envInt("FETCH_CONCURRENCY", 8),
		FetchTimeout:          time.Duration(envInt("FETCH_TIMEOUT_SECONDS", 20)) * time.Second,
		FetchFullText:         envBool("FETCH_FULL_TEXT", true),
		MaxItemsPerFeedPerRun: envInt("MAX_ITEMS_PER_FEED_PER_RUN", 25),
		DefaultRuleThreshold:  envInt("DEFAULT_RULE_THRESHOLD", 70),
		SeedDefaultFeeds:      envBool("SEED_DEFAULT_FEEDS", true),
		AutoSummarize:         envBool("AUTO_SUMMARIZE", false),
		ScheduledDigestAI:     envBool("SCHEDULED_DIGEST_AI", false),
		UserAgent:             env("USER_AGENT", "CyNewsFeed/1.0 (+https://github.com/; RSS aggregator)"),

		AuthMode: env("AUTH_MODE", "none"),

		TAXIIToken:    env("TAXII_TOKEN", ""),
		MCPToken:      env("MCP_TOKEN", ""),
		MISPURL:       env("MISP_URL", ""),
		MISPKey:       env("MISP_KEY", ""),
		MISPVerifyTLS: envBool("MISP_VERIFY_TLS", true),
		OSVURL:        env("OSV_URL", "https://api.osv.dev/v1/query"),
		AgentMaxSteps: envInt("AGENT_MAX_STEPS", 12),
		VirusTotalKey: env("VIRUSTOTAL_API_KEY", ""),
		AbuseIPDBKey:  env("ABUSEIPDB_API_KEY", ""),
		NVDKey:        env("NVD_API_KEY", ""),
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	switch c.StorageMode {
	case "memory":
	case "azure":
		if c.StorageConnString == "" && c.StorageAccount == "" {
			return fmt.Errorf("STORAGE_MODE=azure requires AZURE_STORAGE_CONNECTION_STRING or AZURE_STORAGE_ACCOUNT")
		}
	default:
		return fmt.Errorf("unknown STORAGE_MODE %q", c.StorageMode)
	}
	switch c.AIProvider {
	case "none":
	case "claude":
		// The SDK can also resolve credentials from an `ant auth login` profile,
		// so a missing ANTHROPIC_API_KEY is not fatal here.
	case "azureopenai":
		if c.AzureOpenAIEndpoint == "" || c.AzureOpenAIKey == "" || c.AzureOpenAIDeployment == "" {
			return fmt.Errorf("AI_PROVIDER=azureopenai requires AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_DEPLOYMENT")
		}
	case "ollama":
	default:
		return fmt.Errorf("unknown AI_PROVIDER %q", c.AIProvider)
	}
	return nil
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envInt(k string, def int) int {
	if v := env(k, ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(k string, def bool) bool {
	if v := env(k, ""); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
