package ai

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"cynewsfeed/internal/model"
)

// Heuristic is the AI_PROVIDER=none fallback: no LLM, so it extracts a lead
// sentence as the TL;DR and leaves semantic scoring to keyword rules.
type Heuristic struct{}

func (Heuristic) Name() string  { return "none" }
func (Heuristic) Model() string { return "heuristic" }

var sentenceEnd = regexp.MustCompile(`([.!?])\s+`)

func (Heuristic) Enrich(_ context.Context, in EnrichInput) (*Enrichment, Usage, error) {
	text := strings.TrimSpace(in.Text)
	tldr := text
	if locs := sentenceEnd.FindAllStringIndex(text, 2); len(locs) > 0 {
		end := locs[len(locs)-1][0] + 1
		if end > 320 {
			end = locs[0][0] + 1
		}
		tldr = text[:end]
	}
	if len(tldr) > 320 {
		tldr = tldr[:320] + "…"
	}
	sev := "info"
	lt := strings.ToLower(in.Title + " " + text)
	switch {
	case strings.Contains(lt, "actively exploited") || strings.Contains(lt, "zero-day") || strings.Contains(lt, "0-day"):
		sev = "high"
	case strings.Contains(lt, "vulnerab") || strings.Contains(lt, "ransomware") || strings.Contains(lt, "breach"):
		sev = "medium"
	}
	return &Enrichment{TLDR: tldr, Severity: sev}, Usage{Model: "heuristic"}, nil
}

func (Heuristic) ScoreBatch(context.Context, RuleBrief, []ItemBrief) ([]ItemScore, Usage, error) {
	return nil, Usage{}, nil
}

func (Heuristic) Digest(_ context.Context, in DigestInput) (*DigestOutput, Usage, error) {
	out := &DigestOutput{Headline: "Daily cybersecurity roundup", Overview: "AI summaries are disabled (AI_PROVIDER=none); showing top-ranked items."}
	sec := struct {
		Title string `json:"title"`
		Items []struct {
			ItemID string `json:"item_id"`
			Line   string `json:"line"`
		} `json:"items"`
	}{Title: "Top stories"}
	for i, it := range in.Items {
		if i >= 25 {
			break
		}
		sec.Items = append(sec.Items, struct {
			ItemID string `json:"item_id"`
			Line   string `json:"line"`
		}{it.ID, it.Title})
	}
	out.Sections = append(out.Sections, sec)
	return out, Usage{Model: "heuristic"}, nil
}

func (Heuristic) Detections(context.Context, string, []string) ([]model.Detection, Usage, error) {
	return nil, Usage{}, errors.New("detections need an AI provider (AI_PROVIDER=none)")
}

func (Heuristic) WeeklyBrief(context.Context, string) (*BriefOutput, Usage, error) {
	return nil, Usage{}, errors.New("the weekly brief needs an AI provider (AI_PROVIDER=none)")
}
