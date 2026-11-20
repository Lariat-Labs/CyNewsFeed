package pipeline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/analysis"
	"cynewsfeed/internal/detect"
	"cynewsfeed/internal/model"
)

var AllDetectionFormats = []string{"kql", "spl", "sigma", "yara"}

// GenerateDetections writes hunting queries for a story with the AI and stores them on the item.
func (p *Pipeline) GenerateDetections(ctx context.Context, id string, formats []string) ([]model.Detection, ai.Usage, error) {
	if p.ai.Name() == "none" {
		return nil, ai.Usage{}, errors.New("detections need an AI provider")
	}
	if len(formats) == 0 {
		formats = AllDetectionFormats
	}
	it, err := p.store.GetItem(ctx, id, true)
	if err != nil {
		return nil, ai.Usage{}, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Title: %s\nSource: %s (%s)\nPublished: %s\nURL: %s\nSeverity: %s\n", it.Title, it.FeedName, it.Category,
		it.Published.Format(time.RFC3339), it.Link, it.Severity)
	if it.TLDR != "" {
		fmt.Fprintf(&b, "Summary: %s\n", it.TLDR)
	}
	for _, x := range it.Bullets {
		fmt.Fprintf(&b, "- %s\n", x)
	}
	t := it.Tags
	line := func(label string, v []string) {
		if len(v) > 0 {
			fmt.Fprintf(&b, "%s: %s\n", label, strings.Join(v, ", "))
		}
	}
	line("CVEs", t.CVEs)
	line("Threat actors", t.ThreatActors)
	line("Malware", t.Malware)
	line("Products", t.Products)
	var iocs, techs []string
	for _, i := range t.IOCs {
		iocs = append(iocs, i.Type+" "+i.Value)
	}
	for _, x := range append(append([]model.Technique{}, t.Attack...), t.Atlas...) {
		techs = append(techs, strings.TrimSpace(x.ID+" "+x.Name))
	}
	line("IOCs", iocs)
	line("Techniques", techs)
	content := it.Content
	if len(content) > 8000 {
		content = content[:8000] + "…"
	}
	fmt.Fprintf(&b, "\nArticle text:\n%s", content)

	ds, usage, err := p.ai.Detections(ctx, b.String(), formats)
	var acc ai.Usage
	acc.Add(usage)
	p.recordUsage(ctx, "detections", id, 1, acc)
	if err != nil {
		return nil, acc, err
	}
	ds = detect.Normalize(ds)
	if len(ds) == 0 {
		return nil, acc, errors.New("the story doesn't contain enough technical detail to write detections")
	}
	it.Detections = ds
	it.Content = ""
	if err := p.store.PutItem(ctx, it); err != nil {
		return ds, acc, err
	}
	return ds, acc, nil
}

// isoWeek returns an id like 2026-W47 for the week containing t.
func isoWeek(t time.Time) string {
	y, w := t.ISOWeek()
	return fmt.Sprintf("%d-W%02d", y, w)
}

// WeeklyBrief generates (or regenerates) the executive brief for the last 7 days.
func (p *Pipeline) WeeklyBrief(ctx context.Context) (*model.Report, error) {
	if p.ai.Name() == "none" {
		return nil, errors.New("the weekly brief needs an AI provider")
	}
	now := time.Now().UTC()
	start := now.AddDate(0, 0, -7)
	items, err := p.store.ListItems(ctx, now.AddDate(0, 0, -28))
	if err != nil {
		return nil, err
	}
	var week []model.Item
	for _, it := range items {
		if it.Published.After(start) {
			week = append(week, it)
		}
	}
	if len(week) == 0 {
		return nil, errors.New("no stories in the last 7 days")
	}
	metrics := map[string]int{"stories": len(week)}
	var b strings.Builder
	fmt.Fprintf(&b, "Period: %s to %s\n\n", start.Format("2 Jan 2006"), now.Format("2 Jan 2006"))
	for _, it := range week {
		metrics["severity_"+string(it.Severity)]++
		metrics["category_"+string(it.Category)]++
		if len(it.RuleHits) > 0 {
			metrics["rule_matches"]++
		}
		if it.FeedID == "cisa-kev" {
			metrics["kev_added"]++
		}
	}
	alerts, _ := p.store.ListAlerts(ctx, start)
	metrics["alerts"] = len(alerts)

	b.WriteString("## Top events (multi-source clusters)\n")
	events := analysis.Cluster(week, 4*24*time.Hour)
	for i, e := range events {
		if i >= 15 {
			break
		}
		var ids []string
		for _, x := range e.Items {
			ids = append(ids, x.ID)
		}
		fmt.Fprintf(&b, "- [%s] %s — %d stories from %d sources; ids: %s; CVEs: %s; actors: %s\n  %s\n", e.Severity, e.Title, e.Stories, e.Sources,
			strings.Join(ids, ","), strings.Join(e.CVEs, ","), strings.Join(e.Actors, ","), e.Items[len(e.Items)-1].TLDR)
	}
	b.WriteString("\n## Highest-severity individual stories\n")
	sorted := append([]model.Item(nil), week...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Severity.Rank() > sorted[j].Severity.Rank() })
	for i, it := range sorted {
		if i >= 25 || it.Severity.Rank() < model.SevHigh.Rank() {
			break
		}
		tl := it.TLDR
		if tl == "" {
			tl = it.Snippet
		}
		fmt.Fprintf(&b, "- id %s [%s] %s (%s): %s\n", it.ID, it.Severity, it.Title, it.FeedName, truncate(tl, 300))
	}
	b.WriteString("\n## Rising topics (vs prior 3 weeks)\n")
	for i, t := range analysis.Trends(items, now, 7, 21, 3) {
		if i >= 12 {
			break
		}
		fmt.Fprintf(&b, "- %s %s: %d stories this week vs %d in prior 3 weeks\n", t.Kind, t.Name, t.Recent, t.Baseline)
	}
	cov := analysis.Frameworks(week)
	b.WriteString("\n## Framework coverage\n")
	for tac, ts := range cov.Attack {
		for _, x := range ts[:min(3, len(ts))] {
			fmt.Fprintf(&b, "- ATT&CK %s %s (%s): %d stories\n", x.ID, x.Name, tac, x.Count)
		}
	}
	for k, v := range cov.OWASP {
		fmt.Fprintf(&b, "- OWASP %s: %d stories\n", k, v)
	}
	byRule := map[string]int{}
	for _, a := range alerts {
		byRule[a.RuleName]++
	}
	b.WriteString("\n## Alerts by watch rule\n")
	for k, v := range byRule {
		fmt.Fprintf(&b, "- %s: %d\n", k, v)
	}
	fmt.Fprintf(&b, "\n## Metrics\n%v\n", metrics)

	out, usage, err := p.ai.WeeklyBrief(ctx, b.String())
	var acc ai.Usage
	acc.Add(usage)
	p.recordUsage(ctx, "brief", isoWeek(now), 0, acc)
	if err != nil {
		return nil, err
	}
	valid := map[string]bool{}
	for _, it := range week {
		valid[it.ID] = true
	}
	r := &model.Report{ID: isoWeek(now), Title: out.Title, PeriodStart: start, PeriodEnd: now, ExecutiveSummary: out.ExecutiveSummary,
		KeyRisks: out.KeyRisks, Metrics: metrics, MetricsNote: out.MetricsNote, Recommendations: out.Recommendations,
		Model: usage.Model, CreatedAt: now}
	for _, e := range out.TopEvents {
		ev := model.ReportEvent{Title: e.Title, Why: e.Why}
		for _, id := range e.ItemIDs {
			if valid[id] {
				ev.ItemIDs = append(ev.ItemIDs, id)
			}
		}
		r.TopEvents = append(r.TopEvents, ev)
	}
	return r, p.store.PutReport(ctx, r)
}

// ReportMarkdown renders a report for export (email, wiki, PDF conversion).
func ReportMarkdown(r *model.Report, baseURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n_Weekly security brief · %s – %s_\n\n", r.Title, r.PeriodStart.Format("2 Jan"), r.PeriodEnd.Format("2 Jan 2006"))
	fmt.Fprintf(&b, "## Executive summary\n\n%s\n\n## Key risks\n\n", r.ExecutiveSummary)
	for i, k := range r.KeyRisks {
		fmt.Fprintf(&b, "%d. **%s** — %s\n   - *Recommendation:* %s\n", i+1, k.Title, k.Detail, k.Recommendation)
	}
	b.WriteString("\n## Top events\n\n")
	for _, e := range r.TopEvents {
		fmt.Fprintf(&b, "- **%s** — %s", e.Title, e.Why)
		for i, id := range e.ItemIDs {
			fmt.Fprintf(&b, " [[%d]](%s/?item=%s)", i+1, baseURL, id)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "\n## This week in numbers\n\n%s\n\n", r.MetricsNote)
	keys := make([]string, 0, len(r.Metrics))
	for k := range r.Metrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b.WriteString("| Metric | Value |\n|---|---|\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "| %s | %d |\n", strings.ReplaceAll(k, "_", " "), r.Metrics[k])
	}
	b.WriteString("\n## Recommendations for next week\n\n")
	for i, x := range r.Recommendations {
		fmt.Fprintf(&b, "%d. %s\n", i+1, x)
	}
	fmt.Fprintf(&b, "\n---\n_Generated by CyNewsFeed%s on %s. AI-written; verify against linked sources._\n", modelSuffix(r.Model), r.CreatedAt.Format("2 Jan 2006 15:04 MST"))
	return b.String()
}

func modelSuffix(m string) string {
	if m == "" {
		return ""
	}
	return " (" + m + ")"
}
