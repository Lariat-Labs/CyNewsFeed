// Package api exposes the REST API and serves the embedded SPA.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"cynewsfeed/internal/agent"
	"cynewsfeed/internal/config"
	"cynewsfeed/internal/feeds"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/pipeline"
	"cynewsfeed/internal/rules"
	"cynewsfeed/internal/sharing"
	"cynewsfeed/internal/store"
)

type Server struct {
	cfg   *config.Config
	store store.Store
	pipe  *pipeline.Pipeline
	spa   fs.FS

	agent    *agent.Agent
	agentErr string
	mcp      http.Handler
	misp     *sharing.MISP

	exposureMu sync.Mutex
	exposure   *exposureCache

	cacheMu sync.Mutex
	cache   map[int]cachedItems
}

type cachedItems struct {
	at    time.Time
	items []model.Item
}

func New(cfg *config.Config, st store.Store, p *pipeline.Pipeline, spa fs.FS, ag *agent.Agent, agentErr error, mcpHandler http.Handler) *Server {
	s := &Server{cfg: cfg, store: st, pipe: p, spa: spa, cache: map[int]cachedItems{}, agent: ag, mcp: mcpHandler,
		misp: sharing.NewMISP(cfg.MISPURL, cfg.MISPKey, cfg.MISPVerifyTLS)}
	if agentErr != nil {
		s.agentErr = agentErr.Error()
	}
	return s
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.RequestID, middleware.Recoverer, requestLogger, securityHeaders)
	r.Use(middleware.Compress(5, "text/html", "text/css", "text/javascript", "application/javascript", "application/json", "image/svg+xml"))
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })

	// Machine-to-machine endpoints with their own token auth. In Azure these
	// paths are excluded from Easy Auth (see infra/terraform/auth.tf).
	open := s.cfg.AuthMode == "none"
	taxii := &sharing.TAXII{BaseURL: s.cfg.PublicBaseURL, Token: s.cfg.TAXIIToken, Open: open && s.cfg.TAXIIToken == "",
		Items: func(ctx context.Context) ([]model.Item, error) { return s.itemsSince(ctx, max(1, s.cfg.RetentionDays)) }}
	r.Route("/taxii2", taxii.Routes)
	if s.mcp != nil {
		r.Handle("/mcp", s.mcp)
	}

	r.Route("/api", func(r chi.Router) {
		r.Use(s.auth)
		r.Get("/me", s.me)
		r.Get("/config", s.publicConfig)

		r.Get("/items", s.listItems)
		r.Get("/items/{id}", s.getItem)
		r.Patch("/items/{id}", s.patchItem)
		r.Post("/items/{id}/summarize", s.summarizeOne)
		r.Post("/items/summarize", s.summarizeMany)
		r.Get("/settings/ai", s.getAISettings)
		r.Put("/settings/ai", s.putAISettings)
		r.Get("/usage", s.usage)
		s.intelRoutes(r)

		r.Get("/feeds", s.listFeeds)
		r.Post("/feeds", s.createFeed)
		r.Post("/feeds/test", s.testFeed)
		r.Post("/feeds/seed", s.seedFeeds)
		r.Put("/feeds/{id}", s.updateFeed)
		r.Delete("/feeds/{id}", s.deleteFeed)

		r.Get("/rules", s.listRules)
		r.Post("/rules", s.createRule)
		r.Post("/rules/test", s.testRule) // test unsaved rule
		r.Put("/rules/{id}", s.updateRule)
		r.Delete("/rules/{id}", s.deleteRule)

		r.Get("/alerts", s.listAlerts)
		r.Get("/digests", s.listDigests)
		r.Get("/digests/{date}", s.getDigest)
		r.Post("/digests/run", s.runDigest)
		r.Get("/runs", s.listRuns)
		r.Post("/runs", s.runAggregate)
		r.Get("/stats", s.stats)
		s.chatRoutes(r)
	})

	r.NotFound(s.serveSPA)
	return r
}

// ---------------- middleware ----------------

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		t0 := time.Now()
		next.ServeHTTP(ww, r)
		if strings.HasPrefix(r.URL.Path, "/api") {
			// Strip CR/LF so request paths can't forge log lines.
			path := strings.NewReplacer("\n", "", "\r", "").Replace(r.URL.Path)
			slog.Debug("http", "method", r.Method, "path", path, "status", ww.Status(), "dur", time.Since(t0).Round(time.Millisecond))
		}
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' https: data:; media-src https:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// auth enforces Container Apps Easy Auth headers when AUTH_MODE=easyauth.
// The platform authenticates users before requests reach the app; this is
// defence in depth in case the app is exposed some other way.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AuthMode == "easyauth" && r.Header.Get("X-MS-CLIENT-PRINCIPAL-ID") == "" {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	name := r.Header.Get("X-MS-CLIENT-PRINCIPAL-NAME")
	if name == "" {
		name = "local"
	}
	writeJSON(w, 200, map[string]any{"name": name, "authMode": s.cfg.AuthMode})
}

func (s *Server) publicConfig(w http.ResponseWriter, _ *http.Request) {
	p := s.pipe.AIProvider()
	writeJSON(w, 200, map[string]any{
		"version": s.cfg.Version, "aiProvider": p.Name(), "aiModel": p.Model(), "slack": s.cfg.SlackWebhookURL != "" && s.cfg.SlackEnabled,
		"fetchCron": s.cfg.FetchCron, "digestCron": s.cfg.DigestCron, "timezone": s.cfg.Location.String(),
		"retentionDays": s.cfg.RetentionDays, "schedulerEnabled": s.cfg.SchedulerEnabled,
		"defaultThreshold": s.cfg.DefaultRuleThreshold,
	})
}

// ---------------- items ----------------

func (s *Server) itemsSince(ctx context.Context, days int) ([]model.Item, error) {
	s.cacheMu.Lock()
	c, ok := s.cache[days]
	s.cacheMu.Unlock()
	if ok && time.Since(c.at) < 20*time.Second {
		return c.items, nil
	}
	items, err := s.store.ListItems(ctx, time.Now().UTC().AddDate(0, 0, -days))
	if err != nil {
		return nil, err
	}
	s.cacheMu.Lock()
	s.cache[days] = cachedItems{at: time.Now(), items: items}
	s.cacheMu.Unlock()
	return items, nil
}

// InvalidateCache drops cached item lists (called after runs/updates).
func (s *Server) InvalidateCache() {
	s.cacheMu.Lock()
	s.cache = map[int]cachedItems{}
	s.cacheMu.Unlock()
}

func (s *Server) listItems(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	days := clampInt(atoi(q.Get("days"), 7), 1, max(1, s.cfg.RetentionDays))
	items, err := s.itemsSince(r.Context(), days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	f := model.ItemFilter{
		Since: time.Now().UTC().AddDate(0, 0, -days), Category: q.Get("category"), Severity: q.Get("severity"),
		FeedID: q.Get("feed"), Tag: q.Get("tag"), Query: q.Get("q"), RuleID: q.Get("rule"),
		OnlyHits: q.Get("hits") == "true", Starred: q.Get("starred") == "true", Unread: q.Get("unread") == "true",
	}
	out := store.FilterItems(items, f)
	total := len(out)
	offset := clampInt(atoi(q.Get("offset"), 0), 0, total)
	limit := clampInt(atoi(q.Get("limit"), 100), 1, 500)
	end := min(offset+limit, total)
	writeJSON(w, 200, map[string]any{"items": out[offset:end], "total": total, "offset": offset, "limit": limit})
}

func (s *Server) getItem(w http.ResponseWriter, r *http.Request) {
	it, err := s.store.GetItem(r.Context(), chi.URLParam(r, "id"), true)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, it)
}

func (s *Server) patchItem(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Read    *bool `json:"read"`
		Starred *bool `json:"starred"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	it, err := s.store.GetItem(r.Context(), chi.URLParam(r, "id"), false)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if body.Read != nil {
		it.Read = *body.Read
	}
	if body.Starred != nil {
		it.Starred = *body.Starred
	}
	if err := s.store.PutItem(r.Context(), it); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.updateCached(*it)
	writeJSON(w, 200, it)
}

func (s *Server) updateCached(it model.Item) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	for _, c := range s.cache {
		for i := range c.items {
			if c.items[i].ID == it.ID {
				c.items[i].Read, c.items[i].Starred = it.Read, it.Starred
			}
		}
	}
}

// ---------------- feeds ----------------

func (s *Server) listFeeds(w http.ResponseWriter, r *http.Request) {
	fs, err := s.store.ListFeeds(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, fs)
}

func validateFeed(f *model.Feed) string {
	f.Name = strings.TrimSpace(f.Name)
	f.URL = strings.TrimSpace(f.URL)
	if f.Name == "" {
		return "name is required"
	}
	u, err := url.Parse(f.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "url must be an http(s) URL"
	}
	if f.Kind == "" {
		f.Kind = model.FeedRSS
	}
	if f.Kind != model.FeedRSS && f.Kind != model.FeedCISAKEV && f.Kind != model.FeedOSV {
		return "kind must be rss, cisa-kev or osv-watch"
	}
	switch f.Category {
	case model.CatNews, model.CatResearch, model.CatAdvisory, model.CatPodcast, model.CatAI:
	case "":
		f.Category = model.CatNews
	default:
		return "invalid category"
	}
	if f.Weight == 0 {
		f.Weight = 3
	}
	f.Weight = clampInt(f.Weight, 1, 5)
	return ""
}

func (s *Server) createFeed(w http.ResponseWriter, r *http.Request) {
	var f model.Feed
	if !decodeBody(w, r, &f) {
		return
	}
	if msg := validateFeed(&f); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if f.ID == "" {
		f.ID = feeds.Slug(f.Name)
	}
	if _, err := s.store.GetFeed(r.Context(), f.ID); err == nil {
		writeErr(w, 409, "a feed with this id already exists")
		return
	}
	f.CreatedAt = time.Now().UTC()
	if err := s.store.UpsertFeed(r.Context(), &f); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, f)
}

func (s *Server) updateFeed(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetFeed(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var f model.Feed
	if !decodeBody(w, r, &f) {
		return
	}
	if msg := validateFeed(&f); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	// Preserve server-managed fields.
	f.ID, f.CreatedAt = existing.ID, existing.CreatedAt
	f.LastFetched, f.LastStatus, f.LastError, f.LastNewItems, f.ItemCount = existing.LastFetched, existing.LastStatus, existing.LastError, existing.LastNewItems, existing.ItemCount
	if f.URL == existing.URL {
		f.ETag, f.LastModified = existing.ETag, existing.LastModified
	}
	if err := s.store.UpsertFeed(r.Context(), &f); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, f)
}

func (s *Server) deleteFeed(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteFeed(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.WriteHeader(204)
}

func (s *Server) testFeed(w http.ResponseWriter, r *http.Request) {
	var f model.Feed
	if !decodeBody(w, r, &f) {
		return
	}
	if f.Name == "" {
		f.Name = "test"
	}
	if msg := validateFeed(&f); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := s.pipe.Fetcher().Fetch(ctx, f)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	preview := res.Items
	sort.SliceStable(preview, func(i, j int) bool { return preview[i].Published.After(preview[j].Published) })
	if len(preview) > 5 {
		preview = preview[:5]
	}
	type pv struct {
		Title     string    `json:"title"`
		Link      string    `json:"link"`
		Published time.Time `json:"published"`
		Audio     bool      `json:"audio"`
	}
	var out []pv
	for _, it := range preview {
		out = append(out, pv{it.Title, it.Link, it.Published, it.AudioURL != ""})
	}
	writeJSON(w, 200, map[string]any{"ok": true, "title": res.Title, "siteUrl": res.SiteURL, "itemCount": len(res.Items), "preview": out})
}

func (s *Server) seedFeeds(w http.ResponseWriter, r *http.Request) {
	n, err := s.pipe.Seed(r.Context(), false)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]int{"added": n})
}

// ---------------- rules ----------------

const mask = "••••"

func maskRule(r model.Rule) model.Rule {
	if r.SlackWebhook != "" {
		tail := r.SlackWebhook
		if len(tail) > 4 {
			tail = tail[len(tail)-4:]
		}
		r.SlackWebhook = mask + tail
	}
	return r
}

func (s *Server) normalizeRule(r *model.Rule) string {
	r.Name = strings.TrimSpace(r.Name)
	r.Description = strings.TrimSpace(r.Description)
	if r.Name == "" {
		return "name is required"
	}
	if r.Mode == "" {
		r.Mode = model.ModeHybrid
	}
	if r.Mode != model.ModeKeyword && r.Mode != model.ModeSemantic && r.Mode != model.ModeHybrid {
		return "mode must be keyword, semantic or hybrid"
	}
	r.Keywords = trimList(r.Keywords)
	r.Regexes = trimList(r.Regexes)
	if r.Mode == model.ModeKeyword && len(r.Keywords)+len(r.Regexes) == 0 {
		return "keyword rules need at least one keyword or regex"
	}
	if r.Semantic() && r.Description == "" {
		return "semantic/hybrid rules need a description of what you want to be alerted about"
	}
	if r.Threshold <= 0 {
		r.Threshold = s.cfg.DefaultRuleThreshold
	}
	r.Threshold = clampInt(r.Threshold, 1, 100)
	if r.MinSeverity != "" {
		r.MinSeverity = model.NormalizeSeverity(string(r.MinSeverity))
	}
	if r.SlackWebhook != "" && !strings.HasPrefix(r.SlackWebhook, mask) && !strings.HasPrefix(r.SlackWebhook, "https://hooks.slack.com/") {
		return "slackWebhook must be a https://hooks.slack.com/ URL"
	}
	if _, err := rules.Compile(*r); err != nil {
		return err.Error()
	}
	return ""
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	rs, err := s.store.ListRules(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]model.Rule, 0, len(rs))
	for _, x := range rs {
		out = append(out, maskRule(x))
	}
	writeJSON(w, 200, out)
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var rule model.Rule
	rule.Enabled = true
	if !decodeBody(w, r, &rule) {
		return
	}
	if strings.HasPrefix(rule.SlackWebhook, mask) {
		rule.SlackWebhook = ""
	}
	if msg := s.normalizeRule(&rule); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	rule.ID = feeds.Slug(rule.Name)
	if rule.ID == "" {
		rule.ID = "rule"
	}
	if _, err := s.store.GetRule(r.Context(), rule.ID); err == nil {
		rule.ID += "-" + strconv.FormatInt(time.Now().Unix()%100000, 36)
	}
	rule.CreatedAt, rule.UpdatedAt = time.Now().UTC(), time.Now().UTC()
	if err := s.store.UpsertRule(r.Context(), &rule); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, maskRule(rule))
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetRule(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var rule model.Rule
	if !decodeBody(w, r, &rule) {
		return
	}
	if strings.HasPrefix(rule.SlackWebhook, mask) {
		rule.SlackWebhook = existing.SlackWebhook // unchanged masked value
	}
	if msg := s.normalizeRule(&rule); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	rule.ID, rule.CreatedAt, rule.UpdatedAt = existing.ID, existing.CreatedAt, time.Now().UTC()
	if err := s.store.UpsertRule(r.Context(), &rule); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, maskRule(rule))
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteRule(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.WriteHeader(204)
}

func (s *Server) testRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		model.Rule
		Days   int `json:"days"`
		MaxLLM int `json:"maxLlm"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	rule := body.Rule
	rule.SlackWebhook = ""
	if msg := s.normalizeRule(&rule); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if rule.ID == "" {
		rule.ID = "test"
	}
	days := clampInt(body.Days, 1, 30)
	if body.Days == 0 {
		days = 7
	}
	maxLLM := clampInt(body.MaxLLM, 0, 400)
	if body.MaxLLM == 0 {
		maxLLM = 120
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	res, err := s.pipe.TestRule(ctx, rule, days, maxLLM)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"results": res})
}

// ---------------- alerts, digests, runs ----------------

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	days := clampInt(atoi(r.URL.Query().Get("days"), 7), 1, 90)
	as, err := s.store.ListAlerts(r.Context(), time.Now().UTC().AddDate(0, 0, -days))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if as == nil {
		as = []model.Alert{}
	}
	writeJSON(w, 200, as)
}

func (s *Server) listDigests(w http.ResponseWriter, r *http.Request) {
	ds, err := s.store.ListDigests(r.Context(), clampInt(atoi(r.URL.Query().Get("limit"), 30), 1, 365))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if ds == nil {
		ds = []model.Digest{}
	}
	writeJSON(w, 200, ds)
}

func (s *Server) getDigest(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDigest(r.Context(), chi.URLParam(r, "date"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) runDigest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Minute)
	defer cancel()
	// A manual "Generate now" is an explicit request, so it uses AI when configured.
	d, err := s.pipe.RunDigest(ctx, "manual", true)
	if errors.Is(err, store.ErrLocked) {
		writeErr(w, 409, "a digest is already being generated")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	rs, err := s.store.ListRuns(r.Context(), clampInt(atoi(r.URL.Query().Get("limit"), 30), 1, 200))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if rs == nil {
		rs = []model.Run{}
	}
	writeJSON(w, 200, map[string]any{"runs": rs, "running": s.pipe.Running()})
}

func (s *Server) runAggregate(w http.ResponseWriter, _ *http.Request) {
	if s.pipe.Running() {
		writeErr(w, 409, "an aggregation run is already in progress")
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
		defer cancel()
		if _, err := s.pipe.RunAggregate(ctx, "manual"); err != nil {
			slog.Warn("manual run", "err", err)
		}
		s.InvalidateCache()
	}()
	writeJSON(w, 202, map[string]string{"status": "started"})
}

// ---------------- stats ----------------

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	days := clampInt(atoi(r.URL.Query().Get("days"), 7), 1, 90)
	items, err := s.itemsSince(r.Context(), days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	since := time.Now().UTC().AddDate(0, 0, -days)
	items = store.FilterItems(items, model.ItemFilter{Since: since})
	bySev := map[string]int{}
	byCat := map[string]int{}
	byDay := map[string]map[string]int{}
	tagCounts := map[string]map[string]int{"cves": {}, "threatActors": {}, "malware": {}, "vendors": {}, "topics": {}}
	hits := 0
	for _, it := range items {
		bySev[string(it.Severity)]++
		byCat[string(it.Category)]++
		d := it.Published.In(s.cfg.Location).Format("2006-01-02")
		if byDay[d] == nil {
			byDay[d] = map[string]int{}
		}
		byDay[d][string(it.Severity)]++
		if len(it.RuleHits) > 0 {
			hits++
		}
		for k, l := range map[string][]string{"cves": it.Tags.CVEs, "threatActors": it.Tags.ThreatActors, "malware": it.Tags.Malware, "vendors": it.Tags.Vendors, "topics": it.Tags.Topics} {
			for _, v := range l {
				tagCounts[k][v]++
			}
		}
	}
	type kv struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	top := map[string][]kv{}
	for k, m := range tagCounts {
		var l []kv
		for n, c := range m {
			l = append(l, kv{n, c})
		}
		sort.Slice(l, func(i, j int) bool {
			return l[i].Count > l[j].Count || (l[i].Count == l[j].Count && l[i].Name < l[j].Name)
		})
		if len(l) > 12 {
			l = l[:12]
		}
		if l == nil {
			l = []kv{}
		}
		top[k] = l
	}
	type day struct {
		Date       string         `json:"date"`
		BySeverity map[string]int `json:"bySeverity"`
	}
	var series []day
	for i := days - 1; i >= 0; i-- {
		d := time.Now().In(s.cfg.Location).AddDate(0, 0, -i).Format("2006-01-02")
		m := byDay[d]
		if m == nil {
			m = map[string]int{}
		}
		series = append(series, day{d, m})
	}
	writeJSON(w, 200, map[string]any{"total": len(items), "ruleHits": hits, "bySeverity": bySev, "byCategory": byCat, "byDay": series, "top": top})
}

// ---------------- SPA ----------------

func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, 404, "not found")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p != "" {
		if st, err := fs.Stat(s.spa, p); err == nil && !st.IsDir() {
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFileFS(w, r, s.spa, p)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-cache")
	if _, err := fs.Stat(s.spa, "index.html"); err != nil {
		// Fresh clone without a frontend build: the API still works.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>CyNewsFeed</title><body style="font-family:system-ui;padding:2rem"><h1>CyNewsFeed API is running</h1><p>The web UI hasn't been built. Run <code>make build</code> (or <code>cd frontend &amp;&amp; npm ci &amp;&amp; npm run build</code>) and restart.</p></body>`))
		return
	}
	http.ServeFileFS(w, r, s.spa, "index.html")
}

// ---------------- helpers ----------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeStoreErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "not found")
		return
	}
	writeErr(w, 500, err.Error())
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func atoi(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func clampInt(n, lo, hi int) int { return max(lo, min(hi, n)) }

func trimList(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ---------------- AI settings, on-demand summaries, spend ----------------

func (s *Server) aiSettingsResponse(r *http.Request) map[string]any {
	st := s.pipe.AISettings(r.Context())
	out := map[string]any{"autoSummarize": st.AutoSummarize, "scheduledDigestAI": st.ScheduledDigestAI,
		"provider": s.cfg.AIProvider, "summaryModel": s.pipe.AIProvider().Model()}
	switch s.cfg.AIProvider {
	case "claude":
		out["digestModel"], out["chatModel"] = s.cfg.ClaudeDigestModel, s.cfg.ClaudeChatModel
	case "azureopenai":
		out["digestModel"], out["chatModel"] = s.cfg.AzureOpenAIDigestDeployment, s.cfg.AzureOpenAIChatDeployment
	case "ollama":
		out["digestModel"], out["chatModel"] = s.cfg.OllamaModel, s.cfg.OllamaModel
	}
	return out
}

func (s *Server) getAISettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.aiSettingsResponse(r))
}

func (s *Server) putAISettings(w http.ResponseWriter, r *http.Request) {
	var body model.AISettings
	if !decodeBody(w, r, &body) {
		return
	}
	if err := s.pipe.SaveAISettings(r.Context(), body); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, s.aiSettingsResponse(r))
}

func (s *Server) summarizeOne(w http.ResponseWriter, r *http.Request) {
	s.runSummarize(w, r, []string{chi.URLParam(r, "id")})
}

func (s *Server) summarizeMany(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if len(body.IDs) == 0 || len(body.IDs) > 25 {
		writeErr(w, 400, "send between 1 and 25 story ids")
		return
	}
	s.runSummarize(w, r, body.IDs)
}

func (s *Server) runSummarize(w http.ResponseWriter, r *http.Request, ids []string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 4*time.Minute)
	defer cancel()
	_, uname := user(r)
	items, usage, err := s.pipe.SummarizeItems(ctx, ids, uname)
	s.InvalidateCache()
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "usage": model.TokenUsage{Model: usage.Model, Input: usage.Input,
		Output: usage.Output, Cached: usage.Cached, CostUSD: usage.Cost}})
}

func (s *Server) usage(w http.ResponseWriter, r *http.Request) {
	days := clampInt(atoi(r.URL.Query().Get("days"), 30), 1, 90)
	loc := s.cfg.Location
	recs, err := s.store.ListUsage(r.Context(), time.Now().UTC().AddDate(0, 0, -days))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	type agg struct {
		CostUSD float64 `json:"costUsd"`
		Input   int64   `json:"input"`
		Output  int64   `json:"output"`
		Calls   int     `json:"calls"`
	}
	byKind := map[string]*agg{}
	byDay := map[string]*agg{}
	total := &agg{}
	today := time.Now().In(loc).Format("2006-01-02")
	todayAgg := &agg{}
	for _, u := range recs {
		for _, a := range []*agg{total, get(byKind, u.Kind), get(byDay, u.At.In(loc).Format("2006-01-02"))} {
			a.CostUSD += u.CostUSD
			a.Input += u.Input
			a.Output += u.Output
			a.Calls++
		}
		if u.At.In(loc).Format("2006-01-02") == today {
			todayAgg.CostUSD += u.CostUSD
			todayAgg.Calls++
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].At.After(recs[j].At) })
	if len(recs) > 50 {
		recs = recs[:50]
	}
	writeJSON(w, 200, map[string]any{"days": days, "total": total, "today": todayAgg, "byKind": byKind, "byDay": byDay, "recent": recs})
}

func get[T any](m map[string]*T, k string) *T {
	if v, ok := m[k]; ok {
		return v
	}
	v := new(T)
	m[k] = v
	return v
}
