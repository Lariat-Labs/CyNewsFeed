// Command cynews is the CyNewsFeed server, aggregator and digest job.
//
//	cynews serve    HTTP API + SPA (+ in-process scheduler when SCHEDULER_ENABLED=true)
//	cynews run      one aggregation pass, then exit (Container Apps Job / cron)
//	cynews digest   build and post the daily digest, then exit
//	cynews seed     seed default feeds (add --overwrite to reset them)
//	cynews query    run an agent tool against the dataset: cynews query <tool> '<json>' (or --list)
//	cynews ask      ask the research agent a question from the terminal
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/robfig/cron/v3"

	"cynewsfeed/internal/agent"
	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/api"
	"cynewsfeed/internal/config"
	"cynewsfeed/internal/feeds"
	"cynewsfeed/internal/mcp"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/notify"
	"cynewsfeed/internal/pipeline"
	"cynewsfeed/internal/store"
	"cynewsfeed/internal/web"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd == "version" || cmd == "--version" || cmd == "-v" {
		fmt.Println("cynews", version)
		return nil
	}
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		fmt.Println("usage: cynews [serve|run|digest|seed [--overwrite]|query <tool> [json]|query --list|ask <question>]")
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.Version = version
	setupLogging(cfg)
	if cmd == "mcp" {
		// stdout carries the protocol: keep logs on stderr only.
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := newStore(cfg)
	if err != nil {
		return err
	}
	if err := st.Init(ctx); err != nil {
		return fmt.Errorf("init storage: %w", err)
	}
	provider, err := ai.New(cfg)
	if err != nil {
		return err
	}
	fetcher := feeds.NewFetcher(cfg.FetchTimeout, cfg.UserAgent)
	if cfg.FetchAllowPrivate {
		fetcher = feeds.NewFetcherAllowPrivate(cfg.FetchTimeout, cfg.UserAgent)
	}
	pipe := pipeline.New(cfg, st, fetcher, provider,
		notify.NewSlack(cfg.SlackWebhookURL, cfg.PublicBaseURL, cfg.SlackEnabled))
	toolbox := agent.NewToolbox(st, agent.NewIntel(cfg.UserAgent, cfg.NVDKey, cfg.VirusTotalKey, cfg.AbuseIPDBKey))
	ag, agErr := agent.New(provider, toolbox, st, cfg.AgentMaxSteps, cfg.RetentionDays)
	if cmd != "query" && cmd != "mcp" {
		slog.Info("cynews starting", "version", version, "cmd", cmd, "storage", cfg.StorageMode, "ai", provider.Name(), "model", provider.Model(), "agent", agErr == nil)
	}

	switch cmd {
	case "serve":
		mcpSrv := mcp.New(toolbox, version)
		mcpSrv.Token, mcpSrv.Open = cfg.MCPToken, cfg.AuthMode == "none" && cfg.MCPToken == ""
		return serve(ctx, cfg, st, pipe, ag, agErr, mcpSrv)
	case "query":
		return query(ctx, toolbox, os.Args[2:])
	case "mcp":
		// stdio transport for local MCP clients (Claude Code, Claude Desktop, Cursor, ...)
		return mcp.New(toolbox, version).ServeStdio(ctx, os.Stdin, os.Stdout)
	case "ask":
		if agErr != nil {
			return agErr
		}
		return ask(ctx, ag, st, strings.Join(os.Args[2:], " "))
	case "run":
		_, err := pipe.RunAggregate(ctx, "scheduled")
		if errors.Is(err, store.ErrLocked) {
			slog.Warn("another aggregation is running; skipping")
			return nil
		}
		return err
	case "digest":
		_, err := pipe.RunDigest(ctx, "scheduled", pipe.AISettings(ctx).ScheduledDigestAI)
		if errors.Is(err, store.ErrLocked) {
			slog.Warn("another digest is running; skipping")
			return nil
		}
		return err
	case "seed":
		overwrite := len(os.Args) > 2 && os.Args[2] == "--overwrite"
		n, err := pipe.Seed(ctx, overwrite)
		slog.Info("seeded feeds", "count", n)
		return err
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func newStore(cfg *config.Config) (store.Store, error) {
	if cfg.StorageMode == "memory" {
		slog.Warn("using in-memory storage: data is lost on restart")
		return store.NewMemory(), nil
	}
	return store.NewAzure(cfg.StorageConnString, cfg.StorageAccount, cfg.StorageTablePrefix, cfg.StorageBlobContainer)
}

func serve(ctx context.Context, cfg *config.Config, st store.Store, pipe *pipeline.Pipeline, ag *agent.Agent, agErr error, mcpSrv http.Handler) error {
	if cfg.SeedDefaultFeeds {
		if n, err := pipe.SyncDefaults(ctx); err != nil {
			slog.Warn("seed feeds", "err", err)
		} else if n > 0 {
			slog.Info("seeded default feeds", "count", n)
		}
	}
	srv := api.New(cfg, st, pipe, web.FS(), ag, agErr, mcpSrv)

	if cfg.SchedulerEnabled {
		c := cron.New(cron.WithLocation(cfg.Location))
		aggregate := func(trigger string) {
			rctx, cancel := context.WithTimeout(ctx, 55*time.Minute)
			defer cancel()
			if _, err := pipe.RunAggregate(rctx, trigger); err != nil && !errors.Is(err, store.ErrLocked) {
				slog.Error("scheduled aggregation", "err", err)
			}
			srv.InvalidateCache()
		}
		if _, err := c.AddFunc(cfg.FetchCron, func() { aggregate("scheduled") }); err != nil {
			return fmt.Errorf("FETCH_CRON: %w", err)
		}
		if _, err := c.AddFunc(cfg.DigestCron, func() {
			rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
			defer cancel()
			if _, err := pipe.RunDigest(rctx, "scheduled", pipe.AISettings(rctx).ScheduledDigestAI); err != nil && !errors.Is(err, store.ErrLocked) {
				slog.Error("scheduled digest", "err", err)
			}
		}); err != nil {
			return fmt.Errorf("DIGEST_CRON: %w", err)
		}
		c.Start()
		defer c.Stop()
		slog.Info("scheduler enabled", "fetch", cfg.FetchCron, "digest", cfg.DigestCron, "tz", cfg.Location.String())
		if cfg.RunOnStart {
			go aggregate("startup")
		}
	}

	httpSrv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      5 * time.Minute, // rule back-tests and digests can take a while
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", httpSrv.Addr, "url", cfg.PublicBaseURL)
		errCh <- httpSrv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func setupLogging(cfg *config.Config) {
	var lvl slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler = slog.NewTextHandler(os.Stdout, opts)
	if cfg.LogFormat == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(h))
}

// query runs one agent tool and prints its JSON result: the same code path the
// agent uses, so you can see exactly what it sees.
func query(ctx context.Context, tb *agent.Toolbox, args []string) error {
	if len(args) == 0 || args[0] == "--list" {
		for _, d := range tb.Defs() {
			b, _ := json.Marshal(d.Properties)
			fmt.Printf("%-16s %s\n%16s args: %s\n\n", d.Name, d.Description, "", b)
		}
		return nil
	}
	input := "{}"
	if len(args) > 1 {
		input = args[1]
	}
	out, summary, err := tb.Call(ctx, args[0], json.RawMessage(input))
	if err != nil {
		return err
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, []byte(out), "", "  ") == nil {
		out = pretty.String()
	}
	fmt.Fprintln(os.Stderr, summary)
	fmt.Println(out)
	return nil
}

// ask runs a one-off agent conversation in the terminal (saved as a "local" chat).
func ask(ctx context.Context, ag *agent.Agent, st store.Store, question string) error {
	if strings.TrimSpace(question) == "" {
		return fmt.Errorf("usage: cynews ask <question>")
	}
	now := time.Now().UTC()
	c := &model.Chat{ID: store.InvTS(now) + "cli", User: "local", UserName: "cli", Title: question, CreatedAt: now, UpdatedAt: now}
	if len([]rune(c.Title)) > 80 {
		c.Title = string([]rune(c.Title)[:80]) + "…"
	}
	if err := st.PutChat(ctx, c); err != nil {
		return err
	}
	_, err := ag.Reply(ctx, c, question, question, nil, func(e agent.Event) {
		switch e.Type {
		case "text":
			fmt.Print(e.Delta)
		case "step_start":
			fmt.Fprintf(os.Stderr, "\n  → %s %s\n", e.Step.Name, e.Step.Input)
		case "step_end":
			fmt.Fprintf(os.Stderr, "  ✓ %s\n", e.Step.Summary)
		}
	})
	fmt.Println()
	return err
}
