// Package rules compiles watch rules and evaluates them against items using
// keyword/regex matching combined with LLM relevance scores.
package rules

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"cynewsfeed/internal/model"
)

// KeywordBoost is added to the LLM score in hybrid mode when a keyword matches.
const KeywordBoost = 15

type Compiled struct {
	Rule     model.Rule
	keywords []kw
	regexes  []*regexp.Regexp
}

type kw struct {
	raw string
	re  *regexp.Regexp
}

// Compile prepares a rule for matching. Regexes use RE2 (linear time), so
// user-supplied patterns cannot cause catastrophic backtracking.
func Compile(r model.Rule) (*Compiled, error) {
	c := &Compiled{Rule: r}
	for _, k := range r.Keywords {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		words := strings.Fields(k)
		for i, w := range words {
			words[i] = regexp.QuoteMeta(w)
		}
		pat := strings.Join(words, `\s+`) // tolerate any whitespace between words
		if isWord(rune(k[0])) {
			pat = `\b` + pat
		}
		if isWord(rune(k[len(k)-1])) {
			pat += `\b`
		}
		re, err := regexp.Compile(`(?i)` + pat)
		if err != nil {
			return nil, fmt.Errorf("keyword %q: %w", k, err)
		}
		c.keywords = append(c.keywords, kw{raw: k, re: re})
	}
	for _, p := range r.Regexes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "(?") {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("regex %q: %w", p, err)
		}
		c.regexes = append(c.regexes, re)
	}
	if r.Threshold <= 0 {
		c.Rule.Threshold = 70
	}
	if c.Rule.Mode == "" {
		c.Rule.Mode = model.ModeHybrid
	}
	return c, nil
}

func isWord(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }

// KeywordHits returns matched keywords and regex matches in text.
func (c *Compiled) KeywordHits(text string) []string {
	var hits []string
	seen := map[string]bool{}
	for _, k := range c.keywords {
		if k.re.MatchString(text) && !seen[k.raw] {
			seen[k.raw] = true
			hits = append(hits, k.raw)
		}
	}
	for _, re := range c.regexes {
		if m := re.FindString(text); m != "" && !seen[m] {
			seen[m] = true
			hits = append(hits, m)
		}
	}
	return hits
}

// HasMatchers reports whether the rule has any keyword/regex.
func (c *Compiled) HasMatchers() bool { return len(c.keywords)+len(c.regexes) > 0 }

// Evaluate decides whether an item triggers the rule.
// llmScore < 0 means no LLM score is available (AI disabled or failed).
func (c *Compiled) Evaluate(kwHits []string, llmScore int, reason string, sev model.Severity) (model.RuleHit, bool) {
	r := c.Rule
	hit := model.RuleHit{RuleID: r.ID, RuleName: r.Name, Reason: reason, MatchedKeywords: kwHits}
	if r.MinSeverity != "" && sev.Rank() < r.MinSeverity.Rank() {
		return hit, false
	}
	kwMatch := len(kwHits) > 0
	mode := r.Mode
	if llmScore < 0 && mode != model.ModeKeyword {
		mode = model.ModeKeyword // degrade gracefully without an LLM score
	}
	switch mode {
	case model.ModeKeyword:
		hit.Score = 100
		if reason == "" && kwMatch {
			hit.Reason = "Keyword match: " + strings.Join(kwHits, ", ")
		}
		return hit, kwMatch
	case model.ModeSemantic:
		hit.Score = llmScore
		return hit, llmScore >= r.Threshold
	default: // hybrid
		score := llmScore
		if kwMatch {
			score = min(100, score+KeywordBoost)
		}
		hit.Score = score
		return hit, kwMatch || llmScore >= r.Threshold
	}
}
