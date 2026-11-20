// Package sharing aggregates IOCs across stories and exports them as STIX 2.1,
// CSV or plain text, serves them over TAXII 2.1, and pushes them to MISP.
package sharing

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"cynewsfeed/internal/ioc"
	"cynewsfeed/internal/model"
)

// Indicator is one IOC aggregated across every story that mentions it.
type Indicator struct {
	Type      string         `json:"type"`
	Value     string         `json:"value"`
	Defanged  string         `json:"defanged"`
	FirstSeen time.Time      `json:"firstSeen"`
	LastSeen  time.Time      `json:"lastSeen"`
	Severity  model.Severity `json:"severity"` // max severity of the stories
	Stories   []StoryRef     `json:"stories"`
	Malware   []string       `json:"malware,omitempty"`
	Actors    []string       `json:"actors,omitempty"`
	CVEs      []string       `json:"cves,omitempty"`
}

type StoryRef struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Link      string    `json:"link"`
	Source    string    `json:"source"`
	Published time.Time `json:"published"`
}

type Filter struct {
	Type        string
	MinSeverity string
	Query       string
	ItemIDs     map[string]bool
}

// Aggregate builds the indicator list from items (newest-first order kept).
func Aggregate(items []model.Item, f Filter) []Indicator {
	minRank := -1
	if f.MinSeverity != "" {
		minRank = model.NormalizeSeverity(f.MinSeverity).Rank()
	}
	q := strings.ToLower(f.Query)
	idx := map[string]*Indicator{}
	var order []string
	for _, it := range items {
		if len(f.ItemIDs) > 0 && !f.ItemIDs[it.ID] {
			continue
		}
		if minRank >= 0 && it.Severity.Rank() < minRank {
			continue
		}
		for _, i := range it.Tags.IOCs {
			if f.Type != "" && i.Type != f.Type && !(f.Type == "hash" && isHash(i.Type)) {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(i.Value), q) {
				continue
			}
			k := i.Type + "|" + strings.ToLower(i.Value)
			ind := idx[k]
			if ind == nil {
				ind = &Indicator{Type: i.Type, Value: i.Value, Defanged: ioc.Defang(i.Type, i.Value), FirstSeen: it.Published, LastSeen: it.Published, Severity: it.Severity}
				idx[k] = ind
				order = append(order, k)
			}
			if it.Published.Before(ind.FirstSeen) {
				ind.FirstSeen = it.Published
			}
			if it.Published.After(ind.LastSeen) {
				ind.LastSeen = it.Published
			}
			if it.Severity.Rank() > ind.Severity.Rank() {
				ind.Severity = it.Severity
			}
			ind.Stories = append(ind.Stories, StoryRef{ID: it.ID, Title: it.Title, Link: it.Link, Source: it.FeedName, Published: it.Published})
			ind.Malware = union(ind.Malware, it.Tags.Malware)
			ind.Actors = union(ind.Actors, it.Tags.ThreatActors)
			ind.CVEs = union(ind.CVEs, it.Tags.CVEs)
		}
	}
	out := make([]Indicator, 0, len(order))
	for _, k := range order {
		out = append(out, *idx[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

func isHash(t string) bool { return t == "md5" || t == "sha1" || t == "sha256" }

func union(a, b []string) []string {
	seen := map[string]bool{}
	for _, v := range a {
		seen[strings.ToLower(v)] = true
	}
	for _, v := range b {
		if !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			a = append(a, v)
		}
	}
	return a
}

// ---------------- STIX 2.1 ----------------

// stixNamespace is a fixed UUID namespace so object ids are deterministic:
// the same IOC always gets the same indicator id across exports and TAXII polls.
var stixNamespace = [16]byte{0x7c, 0x1e, 0x4a, 0x2b, 0x9d, 0x3f, 0x4e, 0x11, 0x8a, 0x55, 0x2c, 0x6b, 0x0d, 0x9e, 0x31, 0x47}

func uuid5(name string) string {
	h := sha1.New()
	h.Write(stixNamespace[:])
	h.Write([]byte(name))
	s := h.Sum(nil)
	s[6] = (s[6] & 0x0f) | 0x50
	s[8] = (s[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

const identityName = "CyNewsFeed"

var IdentityID = "identity--" + uuid5("identity|cynewsfeed")

func stixTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func patternFor(t, v string) string {
	esc := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v)
	switch t {
	case "ip":
		if strings.Contains(v, ":") {
			return fmt.Sprintf("[ipv6-addr:value = '%s']", esc)
		}
		return fmt.Sprintf("[ipv4-addr:value = '%s']", esc)
	case "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", esc)
	case "url":
		return fmt.Sprintf("[url:value = '%s']", esc)
	case "email":
		return fmt.Sprintf("[email-addr:value = '%s']", esc)
	case "md5":
		return fmt.Sprintf("[file:hashes.MD5 = '%s']", esc)
	case "sha1":
		return fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", esc)
	case "sha256":
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", esc)
	}
	return ""
}

var sevConfidence = map[model.Severity]int{model.SevCritical: 85, model.SevHigh: 75, model.SevMedium: 60, model.SevLow: 45, model.SevInfo: 30}

// StixObjects returns the identity, one indicator per IOC, and one report per
// referenced story (linking its indicators).
func StixObjects(inds []Indicator) []map[string]any {
	objs := []map[string]any{{
		"type": "identity", "spec_version": "2.1", "id": IdentityID, "created": "2026-01-01T00:00:00.000Z",
		"modified": "2026-01-01T00:00:00.000Z", "name": identityName, "identity_class": "system",
	}}
	reports := map[string]map[string]any{}
	var reportOrder []string
	for _, in := range inds {
		pat := patternFor(in.Type, in.Value)
		if pat == "" {
			continue
		}
		id := "indicator--" + uuid5(in.Type+"|"+strings.ToLower(in.Value))
		var refs []map[string]any
		for i, s := range in.Stories {
			if i >= 10 {
				break
			}
			refs = append(refs, map[string]any{"source_name": s.Source, "description": s.Title, "url": s.Link})
		}
		for _, c := range in.CVEs {
			refs = append(refs, map[string]any{"source_name": "cve", "external_id": c})
		}
		labels := []string{"severity:" + string(in.Severity)}
		for _, m := range in.Malware {
			labels = append(labels, "malware:"+m)
		}
		for _, a := range in.Actors {
			labels = append(labels, "actor:"+a)
		}
		ind := map[string]any{
			"type": "indicator", "spec_version": "2.1", "id": id, "created_by_ref": IdentityID,
			"created": stixTime(in.FirstSeen), "modified": stixTime(in.LastSeen),
			"name":            fmt.Sprintf("%s %s", in.Type, in.Defanged),
			"description":     "Reported in: " + in.Stories[0].Title,
			"indicator_types": []string{"malicious-activity"},
			"pattern":         pat, "pattern_type": "stix", "valid_from": stixTime(in.FirstSeen),
			"confidence": sevConfidence[in.Severity], "labels": labels, "external_references": refs,
		}
		objs = append(objs, ind)
		for _, s := range in.Stories {
			r := reports[s.ID]
			if r == nil {
				r = map[string]any{
					"type": "report", "spec_version": "2.1", "id": "report--" + uuid5("report|"+s.ID), "created_by_ref": IdentityID,
					"created": stixTime(s.Published), "modified": stixTime(s.Published), "published": stixTime(s.Published),
					"name": s.Title, "report_types": []string{"threat-report"},
					"external_references": []map[string]any{{"source_name": s.Source, "url": s.Link}},
					"object_refs":         []string{},
				}
				reports[s.ID] = r
				reportOrder = append(reportOrder, s.ID)
			}
			r["object_refs"] = append(r["object_refs"].([]string), id)
		}
	}
	for _, k := range reportOrder {
		objs = append(objs, reports[k])
	}
	return objs
}

// StixBundle wraps objects in a STIX 2.1 bundle.
func StixBundle(inds []Indicator) map[string]any {
	ids := make([]string, 0, len(inds))
	for _, i := range inds {
		ids = append(ids, i.Type+i.Value)
	}
	return map[string]any{"type": "bundle", "id": "bundle--" + uuid5(strings.Join(ids, ",")+time.Now().UTC().Format(time.RFC3339)), "objects": StixObjects(inds)}
}

// ---------------- CSV / text ----------------

func CSV(w io.Writer, inds []Indicator) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"type", "value", "defanged", "first_seen", "last_seen", "severity", "story_count", "malware", "actors", "cves", "story_titles", "story_links"})
	for _, in := range inds {
		var titles, links []string
		for _, s := range in.Stories {
			titles = append(titles, s.Title)
			links = append(links, s.Link)
		}
		_ = cw.Write([]string{in.Type, in.Value, in.Defanged, in.FirstSeen.UTC().Format(time.RFC3339), in.LastSeen.UTC().Format(time.RFC3339),
			string(in.Severity), fmt.Sprint(len(in.Stories)), strings.Join(in.Malware, "; "), strings.Join(in.Actors, "; "),
			strings.Join(in.CVEs, "; "), strings.Join(titles, " | "), strings.Join(links, " ")})
	}
	cw.Flush()
	return cw.Error()
}

// Text writes one indicator per line (refanged for blocklists, or defanged for sharing).
func Text(w io.Writer, inds []Indicator, defanged bool) {
	for _, in := range inds {
		v := in.Value
		if defanged {
			v = in.Defanged
		}
		fmt.Fprintln(w, v)
	}
}

// ---------------- MISP ----------------

type MISP struct {
	URL, Key  string
	VerifyTLS bool
	client    *http.Client
}

func NewMISP(url, key string, verifyTLS bool) *MISP {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if !verifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for self-signed MISP
	}
	return &MISP{URL: strings.TrimRight(url, "/"), Key: key, VerifyTLS: verifyTLS, client: &http.Client{Timeout: 30 * time.Second, Transport: tr}}
}

func (m *MISP) Configured() bool { return m != nil && m.URL != "" && m.Key != "" }

var mispType = map[string][2]string{
	"ip": {"ip-dst", "Network activity"}, "domain": {"domain", "Network activity"}, "url": {"url", "Network activity"},
	"email": {"email-src", "Payload delivery"}, "md5": {"md5", "Payload delivery"}, "sha1": {"sha1", "Payload delivery"},
	"sha256": {"sha256", "Payload delivery"},
}

// PushEvent creates one MISP event containing the indicators. Returns the event id.
func (m *MISP) PushEvent(ctx context.Context, info string, inds []Indicator, tlp string) (string, error) {
	if !m.Configured() {
		return "", fmt.Errorf("MISP is not configured (set MISP_URL and MISP_KEY)")
	}
	var attrs []map[string]any
	maxSev := model.SevInfo
	for _, in := range inds {
		t, ok := mispType[in.Type]
		if !ok {
			continue
		}
		if in.Severity.Rank() > maxSev.Rank() {
			maxSev = in.Severity
		}
		comment := in.Stories[0].Title
		if len(comment) > 200 {
			comment = comment[:200]
		}
		attrs = append(attrs, map[string]any{"type": t[0], "category": t[1], "value": in.Value, "to_ids": true,
			"comment": comment, "first_seen": stixTime(in.FirstSeen), "last_seen": stixTime(in.LastSeen)})
	}
	if len(attrs) == 0 {
		return "", fmt.Errorf("no indicators to push")
	}
	threat := map[model.Severity]string{model.SevCritical: "1", model.SevHigh: "1", model.SevMedium: "2", model.SevLow: "3", model.SevInfo: "4"}[maxSev]
	if tlp == "" {
		tlp = "tlp:amber"
	}
	body := map[string]any{"Event": map[string]any{
		"info": info, "distribution": "0", "threat_level_id": threat, "analysis": "1",
		"Attribute": attrs, "Tag": []map[string]string{{"name": tlp}, {"name": "source:cynewsfeed"}},
	}}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.URL+"/events/add", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", m.Key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("MISP: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("MISP HTTP %d: %s", resp.StatusCode, string(data[:min(len(data), 300)]))
	}
	var out struct {
		Event struct {
			ID string `json:"id"`
		} `json:"Event"`
	}
	_ = json.Unmarshal(data, &out)
	return out.Event.ID, nil
}
