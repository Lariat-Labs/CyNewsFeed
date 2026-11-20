package ai

import "strings"

// Approximate list prices in USD per million tokens (input, output), used to
// show estimated spend in the UI. Cache reads bill at ~10% of input and cache
// writes at 1.25x input. Unknown models (Azure OpenAI deployments, Ollama)
// report zero cost.
var prices = map[string][2]float64{
	"claude-fable-5-2":  {8, 40},
	"claude-opus-5-5":   {4, 20},
	"claude-opus-5":     {5, 25},
	"claude-opus-4-8":   {5, 25},
	"claude-sonnet-5-5": {2, 10},
	"claude-sonnet-5":   {2, 10},
	"claude-haiku-5-5":  {0.10, 0.50},
	"claude-haiku-4-5":  {1, 5},
}

// EstimateCost returns the approximate USD cost of a usage record.
func EstimateCost(u Usage) float64 {
	p, ok := prices[u.Model]
	if !ok {
		// Responses may carry a dated or suffixed model id; match by prefix.
		for k, v := range prices {
			if strings.HasPrefix(u.Model, k) {
				p, ok = v, true
				break
			}
		}
	}
	if !ok {
		return 0
	}
	uncached := u.Input - u.Cached - u.CacheWrite
	if uncached < 0 {
		uncached = 0
	}
	in := float64(uncached)*p[0] + float64(u.CacheWrite)*p[0]*1.25 + float64(u.Cached)*p[0]*0.1
	return (in + float64(u.Output)*p[1]) / 1e6
}

// Add accumulates usage (model is kept from the first non-empty value).
func (u *Usage) Add(o Usage) {
	if u.Model == "" {
		u.Model = o.Model
	}
	u.Input += o.Input
	u.Output += o.Output
	u.Cached += o.Cached
	u.CacheWrite += o.CacheWrite
	u.Cost += EstimateCost(o)
}
