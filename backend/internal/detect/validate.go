// Package detect performs structural validation of generated detection content.
package detect

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"cynewsfeed/internal/model"
)

var fence = regexp.MustCompile("(?s)^\\s*```[a-zA-Z]*\\s*\\n(.*?)\\n?```\\s*$")

// Normalize strips markdown fences and validates each detection in place.
func Normalize(ds []model.Detection) []model.Detection {
	out := make([]model.Detection, 0, len(ds))
	for _, d := range ds {
		d.Format = strings.ToLower(strings.TrimSpace(d.Format))
		if m := fence.FindStringSubmatch(d.Query); m != nil {
			d.Query = m[1]
		}
		d.Query = strings.TrimSpace(d.Query)
		if d.Query == "" {
			continue
		}
		if err := Validate(d.Format, d.Query); err != nil {
			d.Valid, d.Issue = false, err.Error()
		} else {
			d.Valid, d.Issue = true, ""
		}
		out = append(out, d)
	}
	return out
}

// Validate checks structure (not semantics) of a query in the given format.
func Validate(format, q string) error {
	switch format {
	case "sigma":
		var r map[string]any
		if err := yaml.Unmarshal([]byte(q), &r); err != nil {
			return fmt.Errorf("invalid YAML: %v", err)
		}
		for _, k := range []string{"title", "logsource", "detection"} {
			if _, ok := r[k]; !ok {
				return fmt.Errorf("missing required field %q", k)
			}
		}
		det, ok := r["detection"].(map[string]any)
		if !ok {
			return fmt.Errorf("detection must be a mapping")
		}
		if _, ok := det["condition"]; !ok {
			return fmt.Errorf("detection has no condition")
		}
		if _, ok := r["logsource"].(map[string]any); !ok {
			return fmt.Errorf("logsource must be a mapping")
		}
	case "yara":
		if !regexp.MustCompile(`(?m)^\s*(private\s+|global\s+)*rule\s+\w+`).MatchString(q) || !strings.Contains(q, "condition:") {
			return fmt.Errorf("expected 'rule <name>' with a condition section")
		}
		if err := balanced(q, '{', '}'); err != nil {
			return err
		}
	case "kql", "spl":
		if err := balanced(q, '(', ')'); err != nil {
			return err
		}
		if strings.Count(q, `"`)%2 != 0 {
			return fmt.Errorf("unbalanced double quotes")
		}
		if format == "kql" && !regexp.MustCompile(`(?i)\b(where|summarize|project|let|union|join|extend|search)\b|\|`).MatchString(q) {
			return fmt.Errorf("does not look like KQL")
		}
	default:
		return fmt.Errorf("unknown format %q", format)
	}
	return nil
}

func balanced(s string, open, close rune) error {
	depth := 0
	inStr := false
	var prev rune
	for _, r := range s {
		if r == '"' && prev != '\\' {
			inStr = !inStr
		}
		if !inStr {
			if r == open {
				depth++
			} else if r == close {
				depth--
				if depth < 0 {
					return fmt.Errorf("unbalanced %c%c", open, close)
				}
			}
		}
		prev = r
	}
	if depth != 0 {
		return fmt.Errorf("unbalanced %c%c", open, close)
	}
	return nil
}
