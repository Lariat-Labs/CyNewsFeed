// Package frameworks validates and extracts MITRE ATT&CK, MITRE ATLAS and
// OWASP LLM Top 10 references.
package frameworks

import (
	"regexp"
	"sort"
	"strings"

	"cynewsfeed/internal/model"
)

var (
	attackID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	atlasID  = regexp.MustCompile(`^AML\.T\d{4}(\.\d{3})?$`)
	owaspID  = regexp.MustCompile(`^LLM(0[1-9]|10)$`)

	attackInText = regexp.MustCompile(`\bT1\d{3}(?:\.\d{3})?\b`)
	atlasInText  = regexp.MustCompile(`\bAML\.T\d{4}(?:\.\d{3})?\b`)
	owaspInText  = regexp.MustCompile(`\bLLM(0[1-9]|10)(?::2025)?\b`)
)

// OWASPLLM maps OWASP Top 10 for LLM Applications (2025) IDs to names.
var OWASPLLM = map[string]string{
	"LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure", "LLM03": "Supply Chain",
	"LLM04": "Data and Model Poisoning", "LLM05": "Improper Output Handling", "LLM06": "Excessive Agency",
	"LLM07": "System Prompt Leakage", "LLM08": "Vector and Embedding Weaknesses", "LLM09": "Misinformation",
	"LLM10": "Unbounded Consumption",
}

// Clean validates IDs, upper-cases them and dedupes (keeping the first name/tactic seen).
func Clean(in []model.Technique, atlas bool) []model.Technique {
	re := attackID
	if atlas {
		re = atlasID
	}
	seen := map[string]bool{}
	var out []model.Technique
	for _, t := range in {
		t.ID = strings.ToUpper(strings.TrimSpace(t.ID))
		if atlas && strings.HasPrefix(t.ID, "AML.T") {
			t.ID = "AML.T" + strings.TrimPrefix(t.ID, "AML.T")
		}
		if !re.MatchString(t.ID) || seen[t.ID] {
			continue
		}
		seen[t.ID] = true
		t.Name, t.Tactic = strings.TrimSpace(t.Name), strings.TrimSpace(t.Tactic)
		out = append(out, t)
	}
	return out
}

func CleanOWASP(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.ToUpper(strings.TrimSpace(v))
		if owaspID.MatchString(v) && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Merge combines technique lists, preferring entries that carry a name/tactic.
func Merge(a, b []model.Technique) []model.Technique {
	idx := map[string]int{}
	var out []model.Technique
	for _, l := range [][]model.Technique{a, b} {
		for _, t := range l {
			if i, ok := idx[t.ID]; ok {
				if out[i].Name == "" {
					out[i].Name = t.Name
				}
				if out[i].Tactic == "" {
					out[i].Tactic = t.Tactic
				}
				continue
			}
			idx[t.ID] = len(out)
			out = append(out, t)
		}
	}
	return out
}

// ExtractExplicit finds technique / category IDs written literally in text
// (e.g. vendor reports that list "T1190" or "AML.T0051"). Free, no AI needed.
func ExtractExplicit(text string) (attack, atlas []model.Technique, owasp []string) {
	for _, m := range atlasInText.FindAllString(text, -1) {
		atlas = append(atlas, model.Technique{ID: m})
	}
	stripped := atlasInText.ReplaceAllString(text, " ")
	for _, m := range attackInText.FindAllString(stripped, -1) {
		attack = append(attack, model.Technique{ID: m})
	}
	for _, m := range owaspInText.FindAllStringSubmatch(text, -1) {
		owasp = append(owasp, "LLM"+m[1])
	}
	return Clean(attack, false), Clean(atlas, true), CleanOWASP(owasp)
}
