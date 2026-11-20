package sharing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"cynewsfeed/internal/model"
)

func sample() []model.Item {
	now := time.Now().UTC()
	return []model.Item{
		{ID: "s1", Title: "QuietCrab C2 found", Link: "https://x/1", FeedName: "Talos", Published: now.Add(-2 * time.Hour), Severity: model.SevHigh,
			Tags: model.Tags{Malware: []string{"QuietCrab"}, IOCs: []model.IOC{{Type: "ip", Value: "203.0.113.7"}, {Type: "domain", Value: "bad.example.xyz"},
				{Type: "sha256", Value: strings.Repeat("ab", 32)}, {Type: "url", Value: "https://bad.example.xyz/a'b"}}}},
		{ID: "s2", Title: "More QuietCrab", Link: "https://x/2", FeedName: "Unit42", Published: now.Add(-1 * time.Hour), Severity: model.SevCritical,
			Tags: model.Tags{IOCs: []model.IOC{{Type: "ip", Value: "203.0.113.7"}}}},
		{ID: "s3", Title: "Low story", Published: now.Add(-3 * time.Hour), Severity: model.SevLow, Tags: model.Tags{IOCs: []model.IOC{{Type: "email", Value: "a@b.xyz"}}}},
	}
}

func TestAggregateAndStix(t *testing.T) {
	inds := Aggregate(sample(), Filter{})
	if len(inds) != 5 {
		t.Fatalf("want 5 indicators, got %d", len(inds))
	}
	var ip Indicator
	for _, i := range inds {
		if i.Type == "ip" {
			ip = i
		}
	}
	if len(ip.Stories) != 2 || ip.Severity != model.SevCritical || ip.Defanged != "203.0.113[.]7" || ip.Malware[0] != "QuietCrab" {
		t.Fatalf("ip %+v", ip)
	}
	if n := len(Aggregate(sample(), Filter{MinSeverity: "high"})); n != 4 {
		t.Fatalf("min severity filter: %d", n)
	}
	if n := len(Aggregate(sample(), Filter{Type: "hash"})); n != 1 {
		t.Fatalf("hash filter: %d", n)
	}
	b := StixBundle(inds)
	objs := b["objects"].([]map[string]any)
	pats := map[string]bool{}
	reports := 0
	for _, o := range objs {
		if o["type"] == "indicator" {
			pats[o["pattern"].(string)] = true
			if !strings.HasPrefix(o["id"].(string), "indicator--") || o["spec_version"] != "2.1" {
				t.Fatalf("bad indicator %v", o)
			}
		}
		if o["type"] == "report" {
			reports++
		}
	}
	for _, want := range []string{"[ipv4-addr:value = '203.0.113.7']", "[domain-name:value = 'bad.example.xyz']",
		"[file:hashes.'SHA-256' = '" + strings.Repeat("ab", 32) + "']", `[url:value = 'https://bad.example.xyz/a\'b']`, "[email-addr:value = 'a@b.xyz']"} {
		if !pats[want] {
			t.Errorf("missing pattern %s", want)
		}
	}
	if reports != 3 {
		t.Fatalf("reports %d", reports)
	}
	// Deterministic ids across exports.
	if StixObjects(inds)[1]["id"] != StixObjects(inds)[1]["id"] {
		t.Fatal("ids not deterministic")
	}
	var sb strings.Builder
	if err := CSV(&sb, inds); err != nil || !strings.Contains(sb.String(), "203.0.113[.]7") {
		t.Fatalf("csv %v %s", err, sb.String())
	}
}

func TestTAXII(t *testing.T) {
	tx := &TAXII{BaseURL: "https://app", Token: "tok", Items: func(context.Context) ([]model.Item, error) { return sample(), nil }}
	r := chi.NewRouter()
	r.Route("/taxii2", tx.Routes)
	srv := httptest.NewServer(r)
	defer srv.Close()
	get := func(path, auth string) (*http.Response, map[string]any) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return resp, m
	}
	if resp, _ := get("/taxii2/", ""); resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	resp, disc := get("/taxii2/", "Bearer tok")
	if resp.Header.Get("Content-Type") != taxiiType || disc["default"] != "https://app/taxii2/api/" {
		t.Fatalf("discovery %v %v", resp.Header, disc)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/taxii2/api/collections/", nil)
	req.SetBasicAuth("anyuser", "tok")
	if r2, _ := http.DefaultClient.Do(req); r2.StatusCode != 200 {
		t.Fatalf("basic auth %d", r2.StatusCode)
	}
	all := collections[0].ID
	_, env := get("/taxii2/api/collections/"+all+"/objects/?limit=3", "Bearer tok")
	if env["more"] != true || len(env["objects"].([]any)) != 3 || env["next"] != "3" {
		t.Fatalf("page 1 %v", env)
	}
	_, env2 := get("/taxii2/api/collections/"+all+"/objects/?limit=100&next=3&match[type]=indicator", "Bearer tok")
	for _, o := range env2["objects"].([]any) {
		if o.(map[string]any)["type"] != "indicator" {
			t.Fatal("match[type] not applied")
		}
	}
	_, hi := get("/taxii2/api/collections/"+collections[1].ID+"/objects/?match[type]=indicator", "Bearer tok")
	if len(hi["objects"].([]any)) != 4 {
		t.Fatalf("high collection should exclude the low-severity email: %d", len(hi["objects"].([]any)))
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	_, none := get("/taxii2/api/collections/"+all+"/objects/?added_after="+future, "Bearer tok")
	if len(none["objects"].([]any)) != 0 {
		t.Fatal("added_after not applied")
	}
	if r3, _ := get("/taxii2/api/collections/nope/objects/", "Bearer tok"); r3.StatusCode != 404 {
		t.Fatal("unknown collection")
	}
}

func TestMISPPush(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events/add" || r.Header.Get("Authorization") != "k" {
			w.WriteHeader(403)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"Event":{"id":"42"}}`))
	}))
	defer srv.Close()
	m := NewMISP(srv.URL, "k", true)
	id, err := m.PushEvent(context.Background(), "test", Aggregate(sample(), Filter{}), "")
	if err != nil || id != "42" {
		t.Fatalf("push %v %v", id, err)
	}
	ev := got["Event"].(map[string]any)
	attrs := ev["Attribute"].([]any)
	if len(attrs) != 5 || ev["threat_level_id"] != "1" {
		t.Fatalf("event %v", ev)
	}
	types := map[string]bool{}
	for _, a := range attrs {
		types[a.(map[string]any)["type"].(string)] = true
	}
	for _, want := range []string{"ip-dst", "domain", "sha256", "url", "email-src"} {
		if !types[want] {
			t.Errorf("missing MISP type %s", want)
		}
	}
	if NewMISP("", "", true).Configured() {
		t.Fatal("unconfigured MISP reported configured")
	}
}
