// Package feeds fetches and normalises RSS/Atom/JSON feeds and special sources.
package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	readability "github.com/go-shiori/go-readability"
	"github.com/mmcdole/gofeed"

	"cynewsfeed/internal/model"
)

const maxBody = 40 << 20 // 40 MiB: some podcast feeds (e.g. CyberWire) exceed 20 MiB

type Fetcher struct {
	client *http.Client
	ua     string
}

// NewFetcher returns a client that refuses connections to private, loopback,
// link-local (incl. cloud metadata) and other internal addresses.
func NewFetcher(timeout time.Duration, userAgent string) *Fetcher {
	return newFetcher(timeout, userAgent, false)
}

// NewFetcherAllowPrivate disables the internal-address guard (FETCH_ALLOW_PRIVATE=true,
// e.g. feeds on an internal network, and tests).
func NewFetcherAllowPrivate(timeout time.Duration, userAgent string) *Fetcher {
	return newFetcher(timeout, userAgent, true)
}

func newFetcher(timeout time.Duration, userAgent string, allowPrivate bool) *Fetcher {
	client := &http.Client{
		Timeout:   timeout,
		Transport: safeTransport(allowPrivate),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q", req.URL.Scheme)
			}
			return nil
		},
	}
	return &Fetcher{client: client, ua: userAgent}
}

func checkScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	return nil
}

type Result struct {
	Items        []model.Item
	ETag         string
	LastModified string
	NotModified  bool
	Title        string
	SiteURL      string
}

// Fetch retrieves a feed using conditional GET and returns normalised items
// (without AI fields). Callers handle dedupe.
func (f *Fetcher) Fetch(ctx context.Context, feed model.Feed) (*Result, error) {
	if err := checkScheme(feed.URL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.ua)
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/feed+json, application/json, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.5")
	if feed.ETag != "" {
		req.Header.Set("If-None-Match", feed.ETag)
	}
	if feed.LastModified != "" {
		req.Header.Set("If-Modified-Since", feed.LastModified)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	res := &Result{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	if resp.StatusCode == http.StatusNotModified {
		res.NotModified = true
		res.ETag, res.LastModified = feed.ETag, feed.LastModified
		return res, nil
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	switch feed.Kind {
	case model.FeedCISAKEV:
		res.Items, err = parseKEV(body, feed)
	default:
		err = parseRSS(body, feed, res)
	}
	return res, err
}

func parseRSS(body []byte, feed model.Feed, res *Result) error {
	pf, err := gofeed.NewParser().Parse(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	res.Title, res.SiteURL = pf.Title, pf.Link
	now := time.Now().UTC()
	for _, gi := range pf.Items {
		link := strings.TrimSpace(gi.Link)
		if link == "" && gi.GUID != "" && strings.HasPrefix(gi.GUID, "http") {
			link = gi.GUID
		}
		if link != "" {
			link = absURL(feed.URL, link)
		}
		key := CanonicalURL(link)
		if key == "" {
			key = feed.ID + "|" + firstNonEmpty(gi.GUID, gi.Title)
		}
		published := now
		if gi.PublishedParsed != nil {
			published = gi.PublishedParsed.UTC()
		} else if gi.UpdatedParsed != nil {
			published = gi.UpdatedParsed.UTC()
		}
		if published.After(now.Add(time.Hour)) { // clamp bogus future dates
			published = now
		}
		desc := firstNonEmpty(gi.Description, gi.Content)
		content := StripHTML(firstNonEmpty(gi.Content, gi.Description))
		it := model.Item{
			ID: ItemID(key), FeedID: feed.ID, FeedName: feed.Name, Category: feed.Category,
			Title:     strings.TrimSpace(StripHTML(gi.Title)),
			Link:      link,
			Published: published, Fetched: now,
			Snippet:  Truncate(StripHTML(desc), 600),
			Content:  content,
			Severity: model.SevInfo, AIStatus: model.AIPending,
		}
		if gi.Author != nil {
			it.Author = gi.Author.Name
		} else if len(gi.Authors) > 0 && gi.Authors[0] != nil {
			it.Author = gi.Authors[0].Name
		}
		for _, enc := range gi.Enclosures {
			if enc != nil && (strings.HasPrefix(enc.Type, "audio/") || strings.HasSuffix(strings.ToLower(enc.URL), ".mp3")) {
				it.AudioURL = enc.URL
				break
			}
		}
		if gi.ITunesExt != nil {
			it.Duration = gi.ITunesExt.Duration
			it.ImageURL = gi.ITunesExt.Image
			if s := StripHTML(gi.ITunesExt.Summary); len(s) > len(it.Content) {
				it.Content = s
			}
		}
		if it.ImageURL == "" && gi.Image != nil {
			it.ImageURL = gi.Image.URL
		}
		if it.Title == "" {
			it.Title = Truncate(it.Snippet, 120)
		}
		res.Items = append(res.Items, it)
	}
	return nil
}

type kevCatalog struct {
	Vulnerabilities []struct {
		CveID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		ShortDescription  string `json:"shortDescription"`
		RequiredAction    string `json:"requiredAction"`
		DueDate           string `json:"dueDate"`
		Ransomware        string `json:"knownRansomwareCampaignUse"`
		Notes             string `json:"notes"`
	} `json:"vulnerabilities"`
}

func parseKEV(body []byte, feed model.Feed) ([]model.Item, error) {
	var cat kevCatalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, fmt.Errorf("parse KEV: %w", err)
	}
	now := time.Now().UTC()
	var out []model.Item
	for _, v := range cat.Vulnerabilities {
		added, err := time.Parse("2006-01-02", v.DateAdded)
		if err != nil {
			continue
		}
		// Use noon UTC on the added date so items sort sensibly within the day.
		added = added.Add(12 * time.Hour)
		link := "https://nvd.nist.gov/vuln/detail/" + v.CveID
		content := fmt.Sprintf("%s\n\nVendor/Product: %s %s\nDate added to KEV: %s\nRemediation due (US federal): %s\nRequired action: %s\nKnown ransomware campaign use: %s\nNotes: %s",
			v.ShortDescription, v.VendorProject, v.Product, v.DateAdded, v.DueDate, v.RequiredAction, v.Ransomware, v.Notes)
		out = append(out, model.Item{
			ID: ItemID("kev|" + v.CveID), FeedID: feed.ID, FeedName: feed.Name, Category: feed.Category,
			Title:     fmt.Sprintf("KEV: %s — %s", v.CveID, v.VulnerabilityName),
			Link:      link,
			Published: added, Fetched: now,
			Snippet:  Truncate(v.ShortDescription, 600),
			Content:  content,
			Severity: model.SevHigh,
			Tags:     model.Tags{CVEs: []string{v.CveID}, Vendors: nonEmpty(v.VendorProject), Products: nonEmpty(v.Product)},
			AIStatus: model.AIPending,
		})
	}
	return out, nil
}

// FullText downloads an article and extracts its main readable text.
func (f *Fetcher) FullText(ctx context.Context, link string) (string, error) {
	if err := checkScheme(link); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", f.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := f.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "html") {
		return "", fmt.Errorf("not html: %s", ct)
	}
	u, _ := url.Parse(link)
	art, err := readability.FromReader(io.LimitReader(resp.Body, 5<<20), u)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(art.TextContent), nil
}

func absURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func nonEmpty(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []string{s}
}
