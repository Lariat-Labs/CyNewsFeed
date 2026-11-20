package feeds

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

	f := NewFetcherAllowPrivate(5*time.Second, "test")
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

func TestSSRFGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<rss><channel><title>x</title></channel></rss>`)
	}))
	defer srv.Close()
	safe := NewFetcher(3*time.Second, "test")
	for _, u := range []string{srv.URL, "http://169.254.169.254/metadata/identity/oauth2/token", "http://[::1]:1/", "http://10.0.0.1/", "file:///etc/passwd"} {
		if _, err := safe.Fetch(context.Background(), model.Feed{URL: u, Kind: model.FeedRSS}); err == nil {
			t.Errorf("expected %s to be refused", u)
		}
	}
	if _, err := safe.FullText(context.Background(), "http://127.0.0.1:9/"); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Errorf("full text should refuse loopback: %v", err)
	}
	allow := NewFetcherAllowPrivate(3*time.Second, "test")
	if _, err := allow.Fetch(context.Background(), model.Feed{URL: srv.URL, Kind: model.FeedRSS}); err != nil {
		t.Errorf("allow-private fetcher should reach local server: %v", err)
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700::1111"} {
		if blockedAddr(netip.MustParseAddr(ip)) {
			t.Errorf("public %s must be allowed", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "168.63.129.16", "100.64.0.1", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "0.0.0.0"} {
		if !blockedAddr(netip.MustParseAddr(ip)) {
			t.Errorf("internal %s must be blocked", ip)
		}
	}
}
