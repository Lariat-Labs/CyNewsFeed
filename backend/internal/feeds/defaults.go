package feeds

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"

	"cynewsfeed/internal/model"
)

//go:embed defaults.yaml
var defaultsYAML []byte

// Defaults returns the built-in starter source list.
func Defaults() ([]model.Feed, error) {
	var out []model.Feed
	if err := yaml.Unmarshal(defaultsYAML, &out); err != nil {
		return nil, fmt.Errorf("defaults.yaml: %w", err)
	}
	for i := range out {
		if out[i].Kind == "" {
			out[i].Kind = model.FeedRSS
		}
		if out[i].Weight == 0 {
			out[i].Weight = 3
		}
	}
	return out, nil
}
