package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/analysis"
	"cynewsfeed/internal/feeds"
	"cynewsfeed/internal/frameworks"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/pipeline"
	"cynewsfeed/internal/sharing"
)

type exposureCache struct {
	at   time.Time
	key  string
	data []feeds.Exposure
}

func (s *Server) intelRoutes(r chi.Router) {
	r.Post("/items/{id}/detections", s.detections)
	r.Get("/iocs", s.listIOCs)
	r.Get("/iocs/export", s.exportIOCs)
	r.Post("/iocs/misp", s.pushMISP)
	r.Get("/events", s.events)
	r.Get("/trends", s.trends)
	r.Get("/frameworks", s.frameworks)
	r.Get("/ai/inventory", s.getInventory)
	r.Put("/ai/inventory", s.putInventory)
	r.Get("/ai/exposure", s.exposureCheck)
	r.Get("/reports", s.listReports)
	r.Post("/reports/weekly", s.generateWeekly)
	r.Get("/reports/{id}", s.getReport)
	r.Get("/reports/{id}/markdown", s.reportMarkdown)
	r.Get("/integrations", s.integrations)
}

func usageJSON(u ai.Usage) model.TokenUsage {
	return model.TokenUsage{Model: u.Model, Input: u.Input, Output: u.Output, Cached: u.Cached, CostUSD: u.Cost}
}

// ---- detections ----

func (s *Server) detections(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Formats []string `json:"formats"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	for _, f := range body.Formats {
		if f != "kql" && f != "spl" && f != "sigma" && f != "yara" {
			writeErr(w, 400, "formats must be kql, spl, sigma or yara")
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 4*time.Minute)
	defer cancel()
	ds, usage, err := s.pipe.GenerateDetections(ctx, chi.URLParam(r, "id"), body.Formats)
	s.InvalidateCache()
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"detections": ds, "usage": usageJSON(usage)})
}

// ---- IOCs ----

func (s *Server) iocFilter(r *http.Request) (int, sharing.Filter) {
	q := r.URL.Query()
	days := clampInt(atoi(q.Get("days"), 30), 1, max(1, s.cfg.RetentionDays))
	f := sharing.Filter{Type: q.Get("type"), MinSeverity: q.Get("min_severity"), Query: q.Get("q")}
	if ids := q.Get("items"); ids != "" {
		f.ItemIDs = map[string]bool{}
		for _, id := range strings.Split(ids, ",") {
			f.ItemIDs[strings.TrimSpace(id)] = true
		}
	}
	return days, f
}

func (s *Server) indicators(r *http.Request) ([]sharing.Indicator, error) {
	days, f := s.iocFilter(r)
	items, err := s.itemsSince(r.Context(), days)
	if err != nil {
		return nil, err
	}
	items = filterSince(items, days)
	return sharing.Aggregate(items, f), nil
}

func filterSince(items []model.Item, days int) []model.Item {
	cut := time.Now().UTC().AddDate(0, 0, -days)
	out := items[:0:0]
	for _, it := range items {
		if !it.Published.Before(cut) {
			out = append(out, it)
		}
	}
	return out
}

func (s *Server) listIOCs(w http.ResponseWriter, r *http.Request) {
	inds, err := s.indicators(r)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	counts := map[string]int{}
	for _, i := range inds {
		counts[i.Type]++
	}
	if inds == nil {
		inds = []sharing.Indicator{}
	}
	writeJSON(w, 200, map[string]any{"indicators": inds, "counts": counts, "total": len(inds)})
}

func (s *Server) exportIOCs(w http.ResponseWriter, r *http.Request) {
	inds, err := s.indicators(r)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	stamp := time.Now().UTC().Format("20060102-1504")
	switch r.URL.Query().Get("format") {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cynews-iocs-%s.csv"`, stamp))
		_ = sharing.CSV(w, inds)
	case "txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cynews-iocs-%s.txt"`, stamp))
		sharing.Text(w, inds, r.URL.Query().Get("defang") == "true")
	default:
		w.Header().Set("Content-Type", "application/stix+json;version=2.1")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cynews-iocs-%s.stix.json"`, stamp))
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(sharing.StixBundle(inds))
	}
}

func (s *Server) pushMISP(w http.ResponseWriter, r *http.Request) {
	if !s.misp.Configured() {
		writeErr(w, 400, "MISP is not configured (set MISP_URL and MISP_KEY)")
		return
	}
	var body struct {
		Days        int      `json:"days"`
		MinSeverity string   `json:"minSeverity"`
		Type        string   `json:"type"`
		ItemIDs     []string `json:"itemIds"`
		Info        string   `json:"info"`
		TLP         string   `json:"tlp"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	days := clampInt(body.Days, 1, max(1, s.cfg.RetentionDays))
	if body.Days == 0 {
		days = 7
	}
	items, err := s.itemsSince(r.Context(), days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	f := sharing.Filter{MinSeverity: body.MinSeverity, Type: body.Type}
	if len(body.ItemIDs) > 0 {
		f.ItemIDs = map[string]bool{}
		for _, id := range body.ItemIDs {
			f.ItemIDs[id] = true
		}
	}
	inds := sharing.Aggregate(filterSince(items, days), f)
	info := body.Info
	if info == "" {
		info = fmt.Sprintf("CyNewsFeed IOCs — %s (last %d days)", time.Now().UTC().Format("2006-01-02"), days)
	}
	id, err := s.misp.PushEvent(r.Context(), info, inds, body.TLP)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"eventId": id, "attributes": len(inds), "url": strings.TrimRight(s.cfg.MISPURL, "/") + "/events/view/" + id})
}

// ---- events, trends, frameworks ----

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	days := clampInt(atoi(r.URL.Query().Get("days"), 7), 1, 30)
	items, err := s.itemsSince(r.Context(), days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	evs := analysis.Cluster(filterSince(items, days), 4*24*time.Hour)
	if evs == nil {
		evs = []analysis.Event{}
	}
	writeJSON(w, 200, map[string]any{"days": days, "events": evs})
}

func (s *Server) trends(w http.ResponseWriter, r *http.Request) {
	recent := clampInt(atoi(r.URL.Query().Get("days"), 7), 1, 30)
	baseline := recent * 3
	items, err := s.itemsSince(r.Context(), min(recent+baseline, max(1, s.cfg.RetentionDays)))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	tr := analysis.Trends(items, time.Now().UTC(), recent, baseline, 2)
	if len(tr) > 40 {
		tr = tr[:40]
	}
	// How much baseline data exists, so the UI can explain early "new" results.
	var oldest time.Time
	for _, it := range items {
		if oldest.IsZero() || it.Published.Before(oldest) {
			oldest = it.Published
		}
	}
	if tr == nil {
		tr = []analysis.Trend{}
	}
	writeJSON(w, 200, map[string]any{"recentDays": recent, "baselineDays": baseline, "oldest": oldest, "rising": tr})
}

func (s *Server) frameworks(w http.ResponseWriter, r *http.Request) {
	days := clampInt(atoi(r.URL.Query().Get("days"), 30), 1, 90)
	items, err := s.itemsSince(r.Context(), days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	items = filterSince(items, days)
	cov := analysis.Frameworks(items)
	summarised := 0
	for _, it := range items {
		if it.AIStatus == model.AIDone {
			summarised++
		}
	}
	writeJSON(w, 200, map[string]any{"days": days, "coverage": cov, "owaspNames": frameworks.OWASPLLM,
		"attackTactics": ai.AttackTactics(), "atlasTactics": ai.AtlasTactics(), "stories": len(items), "summarised": summarised})
}

// ---- AI supply-chain inventory ----

var ecosystems = map[string]bool{"PyPI": true, "npm": true, "Go": true, "crates.io": true, "Maven": true, "NuGet": true, "RubyGems": true, "Packagist": true}

func (s *Server) getInventory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"packages": s.pipe.Inventory(r.Context()), "ecosystems": []string{"PyPI", "npm", "Go", "crates.io", "Maven", "NuGet", "RubyGems", "Packagist"}})
}

func (s *Server) putInventory(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Packages []model.InventoryPackage `json:"packages"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if len(body.Packages) > 300 {
		writeErr(w, 400, "at most 300 packages")
		return
	}
	clean := []model.InventoryPackage{}
	seen := map[string]bool{}
	for _, p := range body.Packages {
		p.Name, p.Version = strings.TrimSpace(p.Name), strings.TrimSpace(p.Version)
		if p.Name == "" {
			continue
		}
		if !ecosystems[p.Ecosystem] {
			writeErr(w, 400, "unknown ecosystem "+p.Ecosystem)
			return
		}
		k := p.Ecosystem + "|" + strings.ToLower(p.Name) + "|" + p.Version
		if !seen[k] {
			seen[k] = true
			clean = append(clean, p)
		}
	}
	if err := s.pipe.SaveInventory(r.Context(), clean); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.exposureMu.Lock()
	s.exposure = nil
	s.exposureMu.Unlock()
	writeJSON(w, 200, map[string]any{"packages": clean})
}

func (s *Server) exposureCheck(w http.ResponseWriter, r *http.Request) {
	inv := s.pipe.Inventory(r.Context())
	key, _ := json.Marshal(inv)
	s.exposureMu.Lock()
	c := s.exposure
	s.exposureMu.Unlock()
	if c != nil && c.key == string(key) && time.Since(c.at) < 15*time.Minute && r.URL.Query().Get("refresh") != "true" {
		writeJSON(w, 200, map[string]any{"checkedAt": c.at, "results": c.data})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	data := s.pipe.Fetcher().CheckExposure(ctx, s.cfg.OSVURL, inv)
	now := time.Now().UTC()
	s.exposureMu.Lock()
	s.exposure = &exposureCache{at: now, key: string(key), data: data}
	s.exposureMu.Unlock()
	writeJSON(w, 200, map[string]any{"checkedAt": now, "results": data})
}

// ---- reports ----

func (s *Server) listReports(w http.ResponseWriter, r *http.Request) {
	rs, err := s.store.ListReports(r.Context(), 52)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if rs == nil {
		rs = []model.Report{}
	}
	writeJSON(w, 200, rs)
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.GetReport(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) generateWeekly(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 8*time.Minute)
	defer cancel()
	rep, err := s.pipe.WeeklyBrief(ctx)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) reportMarkdown(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.GetReport(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cynews-brief-%s.md"`, rep.ID))
	_, _ = w.Write([]byte(pipeline.ReportMarkdown(rep, s.cfg.PublicBaseURL)))
}

// ---- integrations ----

func (s *Server) integrations(w http.ResponseWriter, _ *http.Request) {
	base := s.cfg.PublicBaseURL
	open := s.cfg.AuthMode == "none"
	writeJSON(w, 200, map[string]any{
		"taxii": map[string]any{"enabled": s.cfg.TAXIIToken != "" || open, "auth": authLabel(s.cfg.TAXIIToken, open),
			"discovery": base + "/taxii2/", "apiRoot": base + "/taxii2/api/", "collections": sharing.CollectionInfo(base)},
		"mcp":  map[string]any{"enabled": s.cfg.MCPToken != "" || open, "auth": authLabel(s.cfg.MCPToken, open), "url": base + "/mcp"},
		"misp": map[string]any{"configured": s.misp.Configured(), "url": s.cfg.MISPURL},
	})
}

func authLabel(token string, open bool) string {
	switch {
	case token != "":
		return "token"
	case open:
		return "none (local mode)"
	}
	return "disabled"
}
