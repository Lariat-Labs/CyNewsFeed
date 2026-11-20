// Package pipeline orchestrates aggregation runs, AI enrichment, rule
// matching, alerting, retention and the daily digest.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/config"
	"cynewsfeed/internal/feeds"
	"cynewsfeed/internal/frameworks"
	"cynewsfeed/internal/ioc"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/notify"
	"cynewsfeed/internal/rules"
	"cynewsfeed/internal/store"
)

const maxAIAttempts = 3

type Pipeline struct {
	cfg     *config.Config
	store   store.Store
	fetcher *feeds.Fetcher
	ai      ai.Provider
	slack   *notify.Slack
	running atomic.Bool
}

func New(cfg *config.Config, st store.Store, f *feeds.Fetcher, p ai.Provider, s *notify.Slack) *Pipeline {
	return &Pipeline{cfg: cfg, store: st, fetcher: f, ai: p, slack: s}
}

func (p *Pipeline) AIProvider() ai.Provider { return p.ai }
func (p *Pipeline) Fetcher() *feeds.Fetcher { return p.fetcher }

// AISettings returns the effective automatic-AI policy (stored setting, else env defaults).
func (p *Pipeline) AISettings(ctx context.Context) model.AISettings {
	s := model.AISettings{AutoSummarize: p.cfg.AutoSummarize, ScheduledDigestAI: p.cfg.ScheduledDigestAI}
	if raw, err := p.store.GetSetting(ctx, "ai"); err == nil {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	return s
}

func (p *Pipeline) SaveAISettings(ctx context.Context, s model.AISettings) error {
	b, _ := json.Marshal(s)
	return p.store.PutSetting(ctx, "ai", string(b))
}

// recordUsage appends to the AI spend ledger (best effort).
func (p *Pipeline) recordUsage(ctx context.Context, kind, ref string, items int, u ai.Usage) {
	if u.Input == 0 && u.Output == 0 {
		return
	}
	rec := &model.UsageRecord{ID: kind + "-" + store.InvTS(time.Now()), Kind: kind, Ref: ref, At: time.Now().UTC(), Items: items,
		TokenUsage: model.TokenUsage{Model: u.Model, Input: u.Input, Output: u.Output, Cached: u.Cached, CostUSD: u.Cost}}
	if err := p.store.PutUsage(context.WithoutCancel(ctx), rec); err != nil {
		slog.Warn("record usage", "err", err)
	}
}

// Running reports whether an aggregation is in progress in this process.
func (p *Pipeline) Running() bool { return p.running.Load() }

// Inventory returns the AI supply-chain package inventory (stored, else defaults).
func (p *Pipeline) Inventory(ctx context.Context) []model.InventoryPackage {
	if raw, err := p.store.GetSetting(ctx, "inventory"); err == nil {
		var inv []model.InventoryPackage
		if json.Unmarshal([]byte(raw), &inv) == nil {
			return inv
		}
	}
	return feeds.DefaultInventory
}

func (p *Pipeline) SaveInventory(ctx context.Context, inv []model.InventoryPackage) error {
	b, _ := json.Marshal(inv)
	return p.store.PutSetting(ctx, "inventory", string(b))
}

// SyncDefaults adds built-in sources introduced in newer versions exactly
// once, so upgrades get new feeds without resurrecting ones the user deleted.
func (p *Pipeline) SyncDefaults(ctx context.Context) (int, error) {
	defs, err := feeds.Defaults()
	if err != nil {
		return 0, err
	}
	existing, err := p.store.ListFeeds(ctx)
	if err != nil {
		return 0, err
	}
	known := map[string]bool{}
	if raw, err := p.store.GetSetting(ctx, "defaults_seeded"); err == nil {
		var ids []string
		_ = json.Unmarshal([]byte(raw), &ids)
		for _, id := range ids {
			known[id] = true
		}
	} else {
		for _, f := range existing {
			known[f.ID] = true
		}
	}
	have := map[string]bool{}
	for _, f := range existing {
		have[f.ID] = true
	}
	added := 0
	var all []string
	for i := range defs {
		d := defs[i]
		all = append(all, d.ID)
		if known[d.ID] || have[d.ID] {
			continue
		}
		d.CreatedAt = time.Now().UTC()
		if err := p.store.UpsertFeed(ctx, &d); err != nil {
			return added, err
		}
		added++
	}
	b, _ := json.Marshal(all)
	return added, p.store.PutSetting(ctx, "defaults_seeded", string(b))
}

// SeedIfEmpty inserts the default feed list when no feeds exist.
func (p *Pipeline) SeedIfEmpty(ctx context.Context) (int, error) {
	existing, err := p.store.ListFeeds(ctx)
	if err != nil || len(existing) > 0 {
		return 0, err
	}
	return p.Seed(ctx, false)
}

// Seed upserts default feeds; when overwrite is false, existing IDs are kept.
func (p *Pipeline) Seed(ctx context.Context, overwrite bool) (int, error) {
	defs, err := feeds.Defaults()
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range defs {
		f := defs[i]
		if !overwrite {
			if _, err := p.store.GetFeed(ctx, f.ID); err == nil {
				continue
			}
		}
		f.CreatedAt = time.Now().UTC()
		if err := p.store.UpsertFeed(ctx, &f); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

type collector struct {
	mu    sync.Mutex
	s     model.RunStats
	usage ai.Usage
}

func (c *collector) add(fn func(s *model.RunStats)) {
	c.mu.Lock()
	fn(&c.s)
	c.mu.Unlock()
}

// RunAggregate performs one full aggregation pass.
func (p *Pipeline) RunAggregate(ctx context.Context, trigger string) (*model.Run, error) {
	unlock, err := p.store.Lock(ctx, "aggregate")
	if err != nil {
		return nil, err
	}
	defer unlock()
	p.running.Store(true)
	defer p.running.Store(false)

	start := time.Now().UTC()
	run := &model.Run{ID: store.InvTS(start), Kind: "aggregate", Trigger: trigger, Started: start, Status: "running"}
	_ = p.store.PutRun(ctx, run)
	log := slog.With("run", "aggregate", "trigger", trigger)
	log.Info("aggregation started")

	stats := &collector{}
	err = p.aggregate(ctx, stats, log)

	run.Finished = time.Now().UTC()
	run.Stats = stats.s
	run.Stats.CostUSD = stats.usage.Cost
	p.recordUsage(ctx, "aggregate", run.ID, stats.s.Enriched, stats.usage)
	run.Status = "ok"
	if err != nil {
		run.Status, run.Error = "error", err.Error()
	}
	if perr := p.store.PutRun(context.WithoutCancel(ctx), run); perr != nil {
		log.Error("save run", "err", perr)
	}
	log.Info("aggregation finished", "status", run.Status, "new", stats.s.NewItems, "alerts", stats.s.Alerts,
		"feedErrors", stats.s.FeedErrors, "aiErrors", stats.s.AIErrors, "duration", run.Finished.Sub(start).Round(time.Millisecond))
	return run, err
}

func (p *Pipeline) aggregate(ctx context.Context, stats *collector, log *slog.Logger) error {
	if p.cfg.SeedDefaultFeeds {
		if n, err := p.SyncDefaults(ctx); err != nil {
			log.Warn("sync default feeds", "err", err)
		} else if n > 0 {
			log.Info("added new built-in sources", "count", n)
		}
	}
	p.migrate(ctx, log)
	allFeeds, err := p.store.ListFeeds(ctx)
	if err != nil {
		return fmt.Errorf("list feeds: %w", err)
	}
	compiled, err := p.compiledRules(ctx, log)
	if err != nil {
		return err
	}

	// ---- fetch ----
	var enabled []model.Feed
	for _, f := range allFeeds {
		if f.Enabled {
			enabled = append(enabled, f)
		}
	}
	stats.add(func(s *model.RunStats) { s.Feeds = len(enabled) })
	cutoff := time.Now().UTC().AddDate(0, 0, -p.cfg.BackfillDays)
	var (
		newItems []*model.Item
		mu       sync.Mutex
		seen     sync.Map // cross-feed dedupe within a run
		wg       sync.WaitGroup
		sem      = make(chan struct{}, max(1, p.cfg.FetchConcurrency))
	)
	for _, f := range enabled {
		wg.Add(1)
		go func(f model.Feed) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			items, st := p.fetchFeed(ctx, f, cutoff, &seen)
			mu.Lock()
			newItems = append(newItems, items...)
			mu.Unlock()
			stats.add(func(s *model.RunStats) {
				s.PerFeed = append(s.PerFeed, st)
				s.NewItems += st.New
				if st.Status == "error" {
					s.FeedErrors++
				}
			})
		}(f)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// ---- retries for previously failed enrichment ----
	useAI := p.AISettings(ctx).AutoSummarize && p.ai.Name() != "none"
	var retries []*model.Item
	if useAI {
		if retries, err = p.retryCandidates(ctx); err != nil {
			log.Warn("list retry candidates", "err", err)
		}
	}
	stats.add(func(s *model.RunStats) { s.Retried = len(retries) })

	// ---- enrich + match + store + alert ----
	work := append(newItems, retries...)
	aiSem := make(chan struct{}, max(1, p.cfg.AIConcurrency))
	for _, it := range work {
		wg.Add(1)
		go func(it *model.Item) {
			defer wg.Done()
			aiSem <- struct{}{}
			defer func() { <-aiSem }()
			if ctx.Err() != nil {
				return
			}
			p.processItem(ctx, it, compiled, stats, log, useAI)
		}(it)
	}
	wg.Wait()

	// ---- retention ----
	if p.cfg.RetentionDays > 0 {
		n, err := p.store.PurgeItemsBefore(ctx, time.Now().UTC().AddDate(0, 0, -p.cfg.RetentionDays))
		if err != nil {
			log.Warn("purge", "err", err)
		}
		stats.add(func(s *model.RunStats) { s.Purged = n })
	}
	return ctx.Err()
}

func (p *Pipeline) compiledRules(ctx context.Context, log *slog.Logger) ([]*rules.Compiled, error) {
	rs, err := p.store.ListRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	var out []*rules.Compiled
	for _, r := range rs {
		if !r.Enabled {
			continue
		}
		c, err := rules.Compile(r)
		if err != nil {
			log.Warn("skipping invalid rule", "rule", r.Name, "err", err)
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func (p *Pipeline) fetchFeed(ctx context.Context, f model.Feed, cutoff time.Time, seen *sync.Map) ([]*model.Item, model.FeedRunStat) {
	t0 := time.Now()
	st := model.FeedRunStat{FeedID: f.ID}
	var res *feeds.Result
	var err error
	if f.Kind == model.FeedOSV {
		res, err = p.fetcher.FetchOSV(ctx, f, p.Inventory(ctx))
	} else {
		res, err = p.fetcher.Fetch(ctx, f)
	}
	f.LastFetched = time.Now().UTC()
	var out []*model.Item
	switch {
	case err != nil:
		st.Status, st.Error = "error", truncate(err.Error(), 300)
		f.LastStatus, f.LastError = "error", st.Error
	case res.NotModified:
		st.Status = "not-modified"
		f.LastStatus, f.LastError = "not-modified", ""
	default:
		st.Status = "ok"
		f.LastStatus, f.LastError = "ok", ""
		f.ETag, f.LastModified = res.ETag, res.LastModified
		if f.SiteURL == "" {
			f.SiteURL = res.SiteURL
		}
		items := res.Items
		sort.SliceStable(items, func(i, j int) bool { return items[i].Published.After(items[j].Published) })
		for i := range items {
			it := items[i]
			if it.Published.Before(cutoff) {
				continue
			}
			if len(out) >= p.cfg.MaxItemsPerFeedPerRun {
				break
			}
			if _, dup := seen.LoadOrStore(it.ID, true); dup {
				continue
			}
			exists, err := p.store.ItemExists(ctx, it.ID)
			if err != nil {
				st.Error = "dedupe: " + err.Error()
				continue
			}
			if exists {
				st.Seen++
				continue
			}
			out = append(out, &it)
		}
	}
	st.New = len(out)
	f.LastNewItems = len(out)
	f.ItemCount += len(out)
	if err := p.store.UpsertFeed(context.WithoutCancel(ctx), &f); err != nil {
		slog.Warn("update feed health", "feed", f.ID, "err", err)
	}
	st.Duration = time.Since(t0).Milliseconds()
	return out, st
}

func (p *Pipeline) retryCandidates(ctx context.Context) ([]*model.Item, error) {
	if p.ai.Name() == "none" {
		return nil, nil
	}
	items, err := p.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -2))
	if err != nil {
		return nil, err
	}
	var out []*model.Item
	for i := range items {
		if items[i].AIStatus == model.AIError && items[i].AIAttempts < maxAIAttempts {
			full, err := p.store.GetItem(ctx, items[i].ID, true)
			if err == nil {
				out = append(out, full)
			}
		}
	}
	return out, nil
}

// processItem enriches one item with AI, evaluates rules, stores it and sends alerts.
// With useAI=false the free heuristic enricher runs instead (lead-sentence
// TL;DR, keyword severity, regex CVEs/IOCs, keyword-only rules) and the item
// is marked "skipped" so it can be summarised on demand later.
func (p *Pipeline) processItem(ctx context.Context, it *model.Item, compiled []*rules.Compiled, stats *collector, log *slog.Logger, useAI bool) {
	var provider ai.Provider = ai.Heuristic{}
	if useAI {
		provider = p.ai
	}
	// Full text for short article snippets (skip podcasts/advisories with structured content).
	if p.cfg.FetchFullText && it.Category != model.CatPodcast && it.FeedID != "cisa-kev" && len(it.Content) < 600 && it.Link != "" && it.AIAttempts == 0 {
		fctx, cancel := context.WithTimeout(ctx, p.cfg.FetchTimeout)
		if txt, err := p.fetcher.FullText(fctx, it.Link); err == nil && len(txt) > len(it.Content) {
			it.Content = txt
		}
		cancel()
	}
	text := strings.TrimSpace(it.Content)
	if text == "" {
		text = it.Snippet
	}

	var briefs []ai.RuleBrief
	for _, c := range compiled {
		if c.Rule.Semantic() {
			briefs = append(briefs, ai.RuleBrief{ID: c.Rule.ID, Name: c.Rule.Name, Description: c.Rule.Description, Keywords: c.Rule.Keywords})
		}
	}

	baseSeverity := it.Severity
	if useAI {
		it.AIAttempts++
	} else {
		briefs = nil
	}
	enr, usage, err := provider.Enrich(ctx, ai.EnrichInput{
		Title: it.Title, Source: it.FeedName, Category: it.Category, Link: it.Link,
		Published: it.Published, Text: text, Rules: briefs,
	})
	stats.add(func(s *model.RunStats) {
		s.InputTokens += usage.Input
		s.OutputTokens += usage.Output
		s.CachedTokens += usage.Cached
	})
	stats.mu.Lock()
	stats.usage.Add(usage)
	stats.mu.Unlock()
	scores := map[string]ai.RuleScore{}
	aiOK := err == nil
	if err != nil {
		it.AIStatus, it.AIError = model.AIError, truncate(err.Error(), 300)
		log.Warn("ai enrich failed", "item", it.ID, "title", truncate(it.Title, 80), "attempt", it.AIAttempts, "err", err)
		stats.add(func(s *model.RunStats) { s.AIErrors++ })
	} else {
		it.AIStatus, it.AIError, it.AIModel = model.AIDone, "", usage.Model
		if !useAI {
			it.AIStatus, it.AIModel = model.AISkipped, ""
		}
		it.TLDR = strings.TrimSpace(enr.TLDR)
		it.Bullets = cleanList(enr.Bullets)
		it.WhyItMatters = strings.TrimSpace(enr.WhyItMatters)
		sev := model.NormalizeSeverity(enr.Severity)
		if baseSeverity.Rank() > sev.Rank() && it.FeedID == "cisa-kev" {
			sev = baseSeverity // KEV entries are by definition exploited
		}
		it.Severity = sev
		it.Tags = mergeTags(it.Tags, enr.Tags.Model())
		for _, s := range enr.RuleScores {
			scores[s.RuleID] = s
		}
		if useAI {
			stats.add(func(s *model.RunStats) { s.Enriched++ })
		}
	}
	it.Tags.CVEs = dedupe(append(it.Tags.CVEs, feeds.ExtractCVEs(it.Title, text)...), true)
	it.Tags.IOCs = ioc.Merge(it.Tags.IOCs, ioc.Extract(sourceHosts(it), it.Title, text))
	xa, xl, xo := frameworks.ExtractExplicit(it.Title + "\n" + text)
	if aiOK && useAI {
		it.Tags.Attack = frameworks.Merge(frameworks.Clean(enr.Attack, false), it.Tags.Attack)
		it.Tags.Atlas = frameworks.Merge(frameworks.Clean(enr.Atlas, true), it.Tags.Atlas)
		it.Tags.OwaspLLM = frameworks.CleanOWASP(append(it.Tags.OwaspLLM, enr.OwaspLLM...))
	}
	it.Tags.Attack = frameworks.Merge(it.Tags.Attack, xa)
	it.Tags.Atlas = frameworks.Merge(it.Tags.Atlas, xl)
	it.Tags.OwaspLLM = frameworks.CleanOWASP(append(it.Tags.OwaspLLM, xo...))
	if aiOK && useAI {
		it.KeyDetails = validKeyDetails(enr.KeyDetails, it)
	}

	// ---- rules ----
	already := map[string]bool{}
	for _, h := range it.RuleHits {
		already[h.RuleID] = true
	}
	matchText := strings.Join([]string{it.Title, it.Snippet, text, it.TLDR, strings.Join(it.Tags.All(), " ")}, "\n")
	var alerts []model.Alert
	for _, c := range compiled {
		if already[c.Rule.ID] {
			continue
		}
		llm, reason := -1, ""
		if aiOK && useAI && c.Rule.Semantic() {
			llm = 0
			if s, ok := scores[c.Rule.ID]; ok {
				llm, reason = s.Score, s.Reason
			}
		}
		hit, ok := c.Evaluate(c.KeywordHits(matchText), llm, reason, it.Severity)
		if !ok {
			continue
		}
		it.RuleHits = append(it.RuleHits, hit)
		alerts = append(alerts, model.Alert{
			ID: c.Rule.ID + "_" + it.ID, RuleID: c.Rule.ID, RuleName: c.Rule.Name, ItemID: it.ID,
			Title: it.Title, Link: it.Link, FeedName: it.FeedName, Severity: it.Severity,
			Score: hit.Score, Reason: hit.Reason, MatchedKeywords: hit.MatchedKeywords, CreatedAt: time.Now().UTC(),
		})
	}

	if err := p.store.PutItem(ctx, it); err != nil {
		log.Error("store item", "item", it.ID, "err", err)
		return
	}
	webhooks := map[string]string{}
	for _, c := range compiled {
		webhooks[c.Rule.ID] = c.Rule.SlackWebhook
	}
	for i := range alerts {
		a := &alerts[i]
		if p.slack.Configured(webhooks[a.RuleID]) {
			if err := p.slack.SendAlert(ctx, webhooks[a.RuleID], *a, *it); err != nil {
				a.NotifyError = truncate(err.Error(), 300)
				log.Warn("slack alert", "rule", a.RuleName, "err", err)
			} else {
				a.Notified = true
			}
		}
		if err := p.store.PutAlert(ctx, a); err != nil {
			log.Error("store alert", "err", err)
		}
	}
	stats.add(func(s *model.RunStats) { s.Alerts += len(alerts) })
}

// ---------------- On-demand summaries ----------------

// SummarizeItems runs AI enrichment for specific stories (the "Summarize"
// button). Semantic rules are evaluated too; rules that already fired are not
// re-alerted.
func (p *Pipeline) SummarizeItems(ctx context.Context, ids []string, user string) ([]model.Item, ai.Usage, error) {
	if p.ai.Name() == "none" {
		return nil, ai.Usage{}, errors.New("no AI provider configured (AI_PROVIDER=none)")
	}
	compiled, err := p.compiledRules(ctx, slog.Default())
	if err != nil {
		return nil, ai.Usage{}, err
	}
	stats := &collector{}
	log := slog.With("op", "summarize")
	out := make([]model.Item, len(ids))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, p.cfg.AIConcurrency))
	var firstErr error
	var mu sync.Mutex
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			it, err := p.store.GetItem(ctx, id, true)
			if err != nil {
				mu.Lock()
				firstErr = fmt.Errorf("story %s: %w", id, err)
				mu.Unlock()
				return
			}
			if it.AIAttempts == 0 {
				it.AIAttempts = 1 // content was already fetched at ingest; skip refetch
			}
			p.processItem(ctx, it, compiled, stats, log, true)
			it.Content = ""
			out[i] = *it
		}(i, id)
	}
	wg.Wait()
	p.recordUsage(ctx, "summarize", strings.Join(ids, ","), len(ids), stats.usage)
	if stats.s.AIErrors > 0 && stats.s.Enriched == 0 {
		return out, stats.usage, fmt.Errorf("AI summary failed: %s", out[0].AIError)
	}
	return out, stats.usage, firstErr
}

// ---------------- Digest ----------------

// RunDigest builds the digest for the 24h ending now, stores it and posts it to Slack.
// useAI=false builds a ranked headline list without any model call.
func (p *Pipeline) RunDigest(ctx context.Context, trigger string, useAI bool) (*model.Digest, error) {
	unlock, err := p.store.Lock(ctx, "digest")
	if err != nil {
		return nil, err
	}
	defer unlock()
	start := time.Now().UTC()
	run := &model.Run{ID: store.InvTS(start), Kind: "digest", Trigger: trigger, Started: start, Status: "running"}
	_ = p.store.PutRun(ctx, run)

	var provider ai.Provider = ai.Heuristic{}
	if useAI {
		provider = p.ai
	}
	d, usage, err := p.buildDigest(ctx, start, provider)
	run.Finished = time.Now().UTC()
	run.Stats.InputTokens, run.Stats.OutputTokens = usage.Input, usage.Output
	var acc ai.Usage
	acc.Add(usage)
	run.Stats.CostUSD = acc.Cost
	p.recordUsage(ctx, "digest", run.ID, 0, acc)
	if err != nil {
		run.Status, run.Error = "error", err.Error()
		_ = p.store.PutRun(context.WithoutCancel(ctx), run)
		return nil, err
	}
	run.Status = "ok"
	run.Stats.NewItems = d.ItemCount
	if err := p.store.PutDigest(ctx, d); err != nil {
		return nil, err
	}
	if p.slack.Configured("") {
		if err := p.slack.SendDigest(ctx, *d); err != nil {
			slog.Warn("slack digest", "err", err)
			run.Error = "slack: " + err.Error()
		}
	}
	_ = p.store.PutRun(context.WithoutCancel(ctx), run)
	slog.Info("digest created", "date", d.Date, "items", d.ItemCount)
	return d, nil
}

func (p *Pipeline) buildDigest(ctx context.Context, now time.Time, provider ai.Provider) (*model.Digest, ai.Usage, error) {
	since := now.Add(-24 * time.Hour)
	items, err := p.store.ListItems(ctx, since.Add(-24*time.Hour))
	if err != nil {
		return nil, ai.Usage{}, err
	}
	fs, _ := p.store.ListFeeds(ctx)
	weight := map[string]int{}
	for _, f := range fs {
		weight[f.ID] = f.Weight
	}
	var cands []model.Item
	for _, it := range items {
		if it.Published.After(since) || it.Fetched.After(since) {
			cands = append(cands, it)
		}
	}
	if len(cands) == 0 {
		return nil, ai.Usage{}, errors.New("no items in the last 24 hours")
	}
	score := func(it model.Item) int {
		s := it.Severity.Rank()*10 + len(it.RuleHits)*15 + weight[it.FeedID]*2
		if it.FeedID == "cisa-kev" {
			s += 5
		}
		return s
	}
	sort.SliceStable(cands, func(i, j int) bool { return score(cands[i]) > score(cands[j]) })
	if len(cands) > 80 {
		cands = cands[:80]
	}
	byID := map[string]model.Item{}
	in := ai.DigestInput{Date: now.In(p.cfg.Location).Format("2006-01-02")}
	for _, it := range cands {
		byID[it.ID] = it
		var hits []string
		for _, h := range it.RuleHits {
			hits = append(hits, h.RuleName)
		}
		tldr := it.TLDR
		if tldr == "" {
			tldr = it.Snippet
		}
		in.Items = append(in.Items, ai.DigestItem{ID: it.ID, Title: it.Title, Source: it.FeedName, Category: string(it.Category),
			Severity: string(it.Severity), TLDR: truncate(tldr, 400), Tags: it.Tags.All(), RuleHits: hits})
	}
	out, usage, err := provider.Digest(ctx, in)
	if err != nil {
		return nil, usage, err
	}
	d := &model.Digest{Date: in.Date, Headline: out.Headline, Overview: out.Overview, ItemCount: len(cands),
		Model: usage.Model, CreatedAt: time.Now().UTC()}
	for _, s := range out.Sections {
		sec := model.DigestSection{Title: s.Title}
		for _, e := range s.Items {
			it, ok := byID[e.ItemID]
			if !ok {
				continue // ignore hallucinated IDs
			}
			sec.Items = append(sec.Items, model.DigestEntry{ItemID: e.ItemID, Line: e.Line, Title: it.Title, Link: it.Link})
		}
		if len(sec.Items) > 0 {
			d.Sections = append(d.Sections, sec)
		}
	}
	return d, usage, nil
}

// ---------------- Rule back-testing ----------------

type TestResult struct {
	Item       model.Item `json:"item"`
	Score      int        `json:"score"`
	Reason     string     `json:"reason,omitempty"`
	Keywords   []string   `json:"keywords,omitempty"`
	WouldAlert bool       `json:"wouldAlert"`
}

// TestRule evaluates a (possibly unsaved) rule against recent items.
// LLM scoring is applied to at most maxLLM items (keyword hits first).
func (p *Pipeline) TestRule(ctx context.Context, r model.Rule, days, maxLLM int) ([]TestResult, error) {
	c, err := rules.Compile(r)
	if err != nil {
		return nil, err
	}
	items, err := p.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -days))
	if err != nil {
		return nil, err
	}
	type cand struct {
		it  model.Item
		kws []string
	}
	var withKW, without []cand
	for _, it := range items {
		text := strings.Join([]string{it.Title, it.Snippet, it.TLDR, strings.Join(it.Bullets, " "), strings.Join(it.Tags.All(), " ")}, "\n")
		k := c.KeywordHits(text)
		if len(k) > 0 {
			withKW = append(withKW, cand{it, k})
		} else {
			without = append(without, cand{it, nil})
		}
	}
	ordered := append(withKW, without...)
	scores := map[string]ai.ItemScore{}
	useLLM := c.Rule.Semantic() && p.ai.Name() != "none"
	if useLLM {
		pool := ordered
		if len(pool) > maxLLM {
			pool = pool[:maxLLM]
		}
		brief := ai.RuleBrief{ID: r.ID, Name: r.Name, Description: r.Description, Keywords: r.Keywords}
		for i := 0; i < len(pool); i += 40 {
			end := min(i+40, len(pool))
			var batch []ai.ItemBrief
			for _, cd := range pool[i:end] {
				sum := cd.it.TLDR
				if sum == "" {
					sum = cd.it.Snippet
				}
				batch = append(batch, ai.ItemBrief{ID: cd.it.ID, Title: cd.it.Title, Summary: truncate(sum, 500)})
			}
			res, _, err := p.ai.ScoreBatch(ctx, brief, batch)
			if err != nil {
				return nil, fmt.Errorf("llm scoring: %w", err)
			}
			for _, s := range res {
				scores[s.ItemID] = s
			}
		}
	}
	var out []TestResult
	for _, cd := range ordered {
		llm, reason := -1, ""
		if useLLM {
			s, ok := scores[cd.it.ID]
			if !ok && len(cd.kws) == 0 {
				continue // not scored and no keyword hit
			}
			if ok {
				llm, reason = s.Score, s.Reason
			}
		}
		hit, would := c.Evaluate(cd.kws, llm, reason, cd.it.Severity)
		if !would && hit.Score < 30 {
			continue
		}
		it := cd.it
		it.Content = ""
		out = append(out, TestResult{Item: it, Score: hit.Score, Reason: hit.Reason, Keywords: cd.kws, WouldAlert: would})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > 100 {
		out = out[:100]
	}
	return out, nil
}

// ---------------- helpers ----------------

func mergeTags(a, b model.Tags) model.Tags {
	return model.Tags{
		CVEs:         dedupe(append(a.CVEs, b.CVEs...), true),
		ThreatActors: dedupe(append(a.ThreatActors, b.ThreatActors...), false),
		Malware:      dedupe(append(a.Malware, b.Malware...), false),
		Vendors:      dedupe(append(a.Vendors, b.Vendors...), false),
		Products:     dedupe(append(a.Products, b.Products...), false),
		Topics:       dedupe(append(a.Topics, b.Topics...), false),
		IOCs:         ioc.Merge(a.IOCs, b.IOCs),
		Attack:       a.Attack,
		Atlas:        a.Atlas,
		OwaspLLM:     a.OwaspLLM,
	}
}

// validKeyDetails keeps only phrases that appear verbatim in the summary text,
// so the UI can highlight them reliably.
func validKeyDetails(in []model.KeyDetail, it *model.Item) []model.KeyDetail {
	hay := it.TLDR + "\n" + strings.Join(it.Bullets, "\n") + "\n" + it.WhyItMatters
	var out []model.KeyDetail
	for _, k := range in {
		k.Text = strings.TrimSpace(k.Text)
		if len(k.Text) >= 4 && strings.Contains(hay, k.Text) {
			out = append(out, k)
		}
	}
	return out
}

func sourceHosts(it *model.Item) []string {
	if u, err := url.Parse(it.Link); err == nil && u.Host != "" {
		return []string{u.Hostname()}
	}
	return nil
}

func dedupe(in []string, upper bool) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if upper {
			v = strings.ToUpper(v)
		}
		k := strings.ToLower(v)
		if v == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
}

func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(strings.TrimLeft(s, "-•* ")); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// migrate runs one-time data fixes, recorded in settings so each runs once.
func (p *Pipeline) migrate(ctx context.Context, log *slog.Logger) {
	const key = "migration_iocs_v3"
	if _, err := p.store.GetSetting(ctx, key); err == nil {
		return
	}
	items, err := p.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -max(1, p.cfg.RetentionDays)))
	if err != nil {
		log.Warn("migration: list items", "err", err)
		return
	}
	fixed := 0
	for i := range items {
		it := items[i]
		clean := ioc.Sanitize(it.Tags.IOCs)
		if len(clean) != len(it.Tags.IOCs) {
			it.Tags.IOCs = clean
			if err := p.store.PutItem(ctx, &it); err != nil {
				log.Warn("migration: save item", "err", err)
				return
			}
			fixed++
		}
	}
	_ = p.store.PutSetting(ctx, key, time.Now().UTC().Format(time.RFC3339))
	log.Info("migration: cleaned IOC false positives", "items", fixed)
}
