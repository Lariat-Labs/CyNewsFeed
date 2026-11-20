package feeds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cynewsfeed/internal/model"
)

func TestCanonicalURL(t *testing.T) {
	cases := map[string]string{
		"http://www.Example.com/a/b/?utm_source=x&id=3#frag": "https://example.com/a/b?id=3",
		"https://example.com/post/":                          "https://example.com/post",
		"https://example.com/?fbclid=abc":                    "https://example.com/",
	}
	for in, want := range cases {
		if got := CanonicalURL(in); got != want {
			t.Errorf("%s => %s, want %s", in, got, want)
		}
	}
	if ItemID(CanonicalURL("http://www.example.com/x?utm_medium=rss")) != ItemID(CanonicalURL("https://example.com/x")) {
		t.Error("tracking variants should dedupe to the same ID")
	}
}

func TestExtractCVEsAndStrip(t *testing.T) {
	got := ExtractCVEs("Fixes cve-2026-1234 and CVE-2025-99999; also CVE-2026-1234 again")
	if strings.Join(got, ",") != "CVE-2025-99999,CVE-2026-1234" {
		t.Fatalf("got %v", got)
	}
	s := StripHTML(`<p>Hello &amp; <b>world</b></p><script>alert(1)</script><p>Two</p>`)
	if s != "Hello & world\n\nTwo" {
		t.Fatalf("strip = %q", s)
	}
}

const rssDoc = `<?xml version="1.0"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
<channel><title>Test Feed</title><link>https://example.com</link>
<item><title>Episode 1: &lt;b&gt;ransomware&lt;/b&gt;</title><link>/ep1?utm_source=rss</link>
<description>&lt;p&gt;Show notes about LockBit.&lt;/p&gt;</description>
<pubDate>%s</pubDate>
<enclosure url="https://cdn.example.com/ep1.mp3" type="audio/mpeg" length="1"/>
<itunes:duration>42:00</itunes:duration></item>
</channel></rss>`

func TestFetchRSSConditional(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprintf(w, rssDoc, time.Now().UTC().Format(time.RFC1123Z))
	}))
	defer srv.Close()

	f := NewFetcher(5*time.Second, "test")
	feed := model.Feed{ID: "t", Name: "Test", URL: srv.URL + "/feed", Kind: model.FeedRSS, Category: model.CatPodcast}
	res, err := f.Fetch(context.Background(), feed)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.ETag != `"v1"` {
		t.Fatalf("items=%d etag=%q", len(res.Items), res.ETag)
	}
	it := res.Items[0]
	if it.Title != "Episode 1: ransomware" || it.AudioURL == "" || it.Duration != "42:00" {
		t.Fatalf("bad item %+v", it)
	}
	if !strings.HasPrefix(it.Link, srv.URL+"/ep1") {
		t.Fatalf("relative link not resolved: %s", it.Link)
	}
	feed.ETag = res.ETag
	res, err = f.Fetch(context.Background(), feed)
	if err != nil || !res.NotModified {
		t.Fatalf("want 304 not-modified, got %+v err %v", res, err)
	}
}

func TestParseKEV(t *testing.T) {
	body := []byte(`{"vulnerabilities":[{"cveID":"CVE-2026-0001","vendorProject":"Acme","product":"Gateway",
	"vulnerabilityName":"Acme Gateway RCE","dateAdded":"2026-11-18","shortDescription":"RCE in Acme.",
	"requiredAction":"Patch.","dueDate":"2026-12-09","knownRansomwareCampaignUse":"Known","notes":""}]}`)
	items, err := parseKEV(body, model.Feed{ID: "cisa-kev", Name: "KEV", Category: model.CatAdvisory})
	if err != nil || len(items) != 1 {
		t.Fatalf("items %v err %v", items, err)
	}
	it := items[0]
	if it.Tags.CVEs[0] != "CVE-2026-0001" || it.Severity != model.SevHigh || !strings.Contains(it.Content, "ransomware campaign use: Known") {
		t.Fatalf("bad KEV item %+v", it)
	}
}

func TestDefaultsValid(t *testing.T) {
	fs, err := Defaults()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range fs {
		if f.ID == "" || f.URL == "" || f.Name == "" || seen[f.ID] {
			t.Errorf("invalid/duplicate feed %+v", f)
		}
		seen[f.ID] = true
	}
	if len(fs) < 30 {
		t.Errorf("expected 30+ default feeds, got %d", len(fs))
	}
}
