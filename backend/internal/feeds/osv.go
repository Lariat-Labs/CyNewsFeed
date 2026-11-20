package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cynewsfeed/internal/model"
)

// DefaultInventory is the starter AI/ML package list for the supply-chain watch.
var DefaultInventory = []model.InventoryPackage{
	{Ecosystem: "PyPI", Name: "langchain"}, {Ecosystem: "PyPI", Name: "langchain-core"}, {Ecosystem: "PyPI", Name: "langchain-community"},
	{Ecosystem: "PyPI", Name: "llama-index"}, {Ecosystem: "PyPI", Name: "transformers"}, {Ecosystem: "PyPI", Name: "torch"},
	{Ecosystem: "PyPI", Name: "vllm"}, {Ecosystem: "PyPI", Name: "llama-cpp-python"}, {Ecosystem: "PyPI", Name: "huggingface-hub"},
	{Ecosystem: "PyPI", Name: "mlflow"}, {Ecosystem: "PyPI", Name: "gradio"}, {Ecosystem: "PyPI", Name: "ray"},
	{Ecosystem: "PyPI", Name: "keras"}, {Ecosystem: "PyPI", Name: "onnx"}, {Ecosystem: "PyPI", Name: "openai"},
	{Ecosystem: "PyPI", Name: "anthropic"}, {Ecosystem: "PyPI", Name: "litellm"}, {Ecosystem: "npm", Name: "langchain"},
	{Ecosystem: "npm", Name: "@langchain/core"}, {Ecosystem: "Go", Name: "github.com/ollama/ollama"},
}

type osvVuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func (f *Fetcher) osvQuery(ctx context.Context, endpoint string, p model.InventoryPackage) ([]osvVuln, error) {
	body := map[string]any{"package": map[string]string{"name": p.Name, "ecosystem": p.Ecosystem}}
	if p.Version != "" {
		body["version"] = p.Version
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", f.ua)
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("OSV %s/%s: HTTP %d", p.Ecosystem, p.Name, resp.StatusCode)
	}
	var out struct {
		Vulns []osvVuln `json:"vulns"`
	}
	return out.Vulns, json.Unmarshal(data, &out)
}

func osvSeverity(v osvVuln) model.Severity {
	if strings.HasPrefix(v.ID, "MAL-") {
		return model.SevCritical // malicious package
	}
	switch strings.ToUpper(v.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return model.SevCritical
	case "HIGH":
		return model.SevHigh
	case "MODERATE", "MEDIUM":
		return model.SevMedium
	case "LOW":
		return model.SevLow
	}
	return model.SevMedium
}

func fixedVersions(v osvVuln, pkg string) []string {
	var out []string
	for _, a := range v.Affected {
		if a.Package.Name != pkg {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if fx := e["fixed"]; fx != "" {
					out = append(out, fx)
				}
			}
		}
	}
	return out
}

// FetchOSV turns OSV advisories for the inventory into feed items (one per
// advisory, merged across packages).
func (f *Fetcher) FetchOSV(ctx context.Context, feed model.Feed, pkgs []model.InventoryPackage) (*Result, error) {
	endpoint := feed.URL
	if endpoint == "" {
		endpoint = "https://api.osv.dev/v1/query"
	}
	type hit struct {
		v    osvVuln
		pkgs []model.InventoryPackage
	}
	var mu sync.Mutex
	hits := map[string]*hit{}
	var errs []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, p := range pkgs {
		wg.Add(1)
		go func(p model.InventoryPackage) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			vulns, err := f.osvQuery(ctx, endpoint, p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err.Error())
				return
			}
			for _, v := range vulns {
				h := hits[v.ID]
				if h == nil {
					h = &hit{v: v}
					hits[v.ID] = h
				}
				h.pkgs = append(h.pkgs, p)
			}
		}(p)
	}
	wg.Wait()
	if len(errs) == len(pkgs) && len(pkgs) > 0 {
		return nil, fmt.Errorf("all OSV queries failed: %s", errs[0])
	}
	now := time.Now().UTC()
	res := &Result{Title: "OSV AI supply-chain watch"}
	for _, h := range hits {
		v := h.v
		pub, err := time.Parse(time.RFC3339, v.Published)
		if err != nil {
			pub = now
		}
		var names, lines []string
		for _, p := range h.pkgs {
			names = append(names, p.Name)
			line := fmt.Sprintf("Package: %s (%s)", p.Name, p.Ecosystem)
			if fx := fixedVersions(v, p.Name); len(fx) > 0 {
				line += "; fixed in " + strings.Join(fx, ", ")
			}
			if p.Version != "" {
				line += fmt.Sprintf("; YOUR PINNED VERSION %s IS AFFECTED", p.Version)
			}
			lines = append(lines, line)
		}
		sort.Strings(names)
		summary := v.Summary
		if summary == "" {
			summary = Truncate(StripHTML(v.Details), 140)
		}
		var cves []string
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				cves = append(cves, a)
			}
		}
		sev := ""
		for _, s := range v.Severity {
			sev = s.Type + " " + s.Score
		}
		kind := "Vulnerability"
		if strings.HasPrefix(v.ID, "MAL-") {
			kind = "MALICIOUS PACKAGE"
		}
		content := fmt.Sprintf("%s advisory %s (aliases: %s)\n%s\n\n%s\n\nSeverity: %s %s\nPublished %s, modified %s",
			kind, v.ID, strings.Join(v.Aliases, ", "), strings.Join(lines, "\n"), v.Details, v.DatabaseSpecific.Severity, sev, v.Published, v.Modified)
		res.Items = append(res.Items, model.Item{
			ID: ItemID("osv|" + v.ID), FeedID: feed.ID, FeedName: feed.Name, Category: feed.Category,
			Title:     fmt.Sprintf("%s: %s", strings.Join(names, ", "), summary),
			Link:      "https://osv.dev/vulnerability/" + v.ID,
			Published: pub, Fetched: now,
			Snippet:  Truncate(StripHTML(v.Details), 600),
			Content:  content,
			Severity: osvSeverity(v),
			Tags: model.Tags{CVEs: cves, Products: names, Topics: []string{"ai-supply-chain"},
				OwaspLLM: []string{"LLM03"}},
			AIStatus: model.AIPending,
		})
	}
	return res, nil
}

// Exposure is the live result of checking one inventory package.
type Exposure struct {
	Package    model.InventoryPackage `json:"package"`
	Advisories []ExposureAdvisory     `json:"advisories"`
	Error      string                 `json:"error,omitempty"`
}

type ExposureAdvisory struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Severity  string   `json:"severity"`
	Fixed     []string `json:"fixed,omitempty"`
	Published string   `json:"published"`
	Aliases   []string `json:"aliases,omitempty"`
	Malicious bool     `json:"malicious,omitempty"`
}

// CheckExposure queries OSV live for each package. With a pinned version the
// result lists advisories affecting that version; without, all advisories.
func (f *Fetcher) CheckExposure(ctx context.Context, endpoint string, pkgs []model.InventoryPackage) []Exposure {
	if endpoint == "" {
		endpoint = "https://api.osv.dev/v1/query"
	}
	out := make([]Exposure, len(pkgs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, p := range pkgs {
		wg.Add(1)
		go func(i int, p model.InventoryPackage) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ex := Exposure{Package: p, Advisories: []ExposureAdvisory{}}
			vulns, err := f.osvQuery(ctx, endpoint, p)
			if err != nil {
				ex.Error = err.Error()
			}
			for _, v := range vulns {
				ex.Advisories = append(ex.Advisories, ExposureAdvisory{ID: v.ID, Summary: v.Summary, Severity: string(osvSeverity(v)),
					Fixed: fixedVersions(v, p.Name), Published: v.Published, Aliases: v.Aliases, Malicious: strings.HasPrefix(v.ID, "MAL-")})
			}
			sort.Slice(ex.Advisories, func(a, b int) bool { return ex.Advisories[a].Published > ex.Advisories[b].Published })
			out[i] = ex
		}(i, p)
	}
	wg.Wait()
	return out
}
