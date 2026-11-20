package sharing

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"cynewsfeed/internal/model"
)

const taxiiType = "application/taxii+json;version=2.1"

// TAXII serves a read-only TAXII 2.1 API so SIEM/TIP platforms (Microsoft
// Sentinel's TAXII connector, OpenCTI, MISP, Splunk, ...) can pull IOCs.
type TAXII struct {
	BaseURL string
	Token   string // required unless Open is set
	Open    bool   // allow unauthenticated access (local development only)
	Items   func(ctx context.Context) ([]model.Item, error)
}

type collection struct {
	ID, Title, Description string
	MinSeverity            string
}

var collections = []collection{
	{ID: "4f0b6b1e-0c4a-5d2e-9a77-000000000001", Title: "CyNewsFeed IOCs (all)", Description: "Indicators extracted from all stories in the retention window."},
	{ID: "4f0b6b1e-0c4a-5d2e-9a77-000000000002", Title: "CyNewsFeed IOCs (high & critical)", Description: "Indicators from high and critical severity stories only.", MinSeverity: "high"},
}

func (t *TAXII) Routes(r chi.Router) {
	r.Use(t.auth)
	r.Get("/", t.discovery)
	r.Get("/api/", t.apiRoot)
	r.Get("/api/collections/", t.listCollections)
	r.Get("/api/collections/{id}/", t.getCollection)
	r.Get("/api/collections/{id}/objects/", t.objects)
	r.Get("/api/collections/{id}/manifest/", t.manifest)
}

// auth accepts "Authorization: Bearer <token>" or HTTP Basic with the token as password.
func (t *TAXII) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !t.Open {
			if t.Token == "" {
				taxiiErr(w, http.StatusNotFound, "TAXII is disabled (set TAXII_TOKEN)")
				return
			}
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if _, pw, ok := r.BasicAuth(); ok {
				got = pw
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(t.Token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="taxii"`)
				taxiiErr(w, http.StatusUnauthorized, "authentication required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func taxiiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", taxiiType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func taxiiErr(w http.ResponseWriter, status int, msg string) {
	taxiiJSON(w, status, map[string]any{"title": msg, "http_status": strconv.Itoa(status)})
}

func (t *TAXII) discovery(w http.ResponseWriter, _ *http.Request) {
	taxiiJSON(w, 200, map[string]any{"title": "CyNewsFeed TAXII", "description": "Indicators from cybersecurity news",
		"default": t.BaseURL + "/taxii2/api/", "api_roots": []string{t.BaseURL + "/taxii2/api/"}})
}

func (t *TAXII) apiRoot(w http.ResponseWriter, _ *http.Request) {
	taxiiJSON(w, 200, map[string]any{"title": "CyNewsFeed", "versions": []string{taxiiType}, "max_content_length": 10485760})
}

func collJSON(c collection) map[string]any {
	return map[string]any{"id": c.ID, "title": c.Title, "description": c.Description, "can_read": true, "can_write": false,
		"media_types": []string{"application/stix+json;version=2.1"}}
}

func (t *TAXII) listCollections(w http.ResponseWriter, _ *http.Request) {
	var out []map[string]any
	for _, c := range collections {
		out = append(out, collJSON(c))
	}
	taxiiJSON(w, 200, map[string]any{"collections": out})
}

func findColl(id string) (collection, bool) {
	for _, c := range collections {
		if c.ID == id {
			return c, true
		}
	}
	return collection{}, false
}

func (t *TAXII) getCollection(w http.ResponseWriter, r *http.Request) {
	c, ok := findColl(chi.URLParam(r, "id"))
	if !ok {
		taxiiErr(w, 404, "collection not found")
		return
	}
	taxiiJSON(w, 200, collJSON(c))
}

// collectionObjects returns STIX objects with their date_added (= modified).
func (t *TAXII) collectionObjects(r *http.Request) ([]map[string]any, error) {
	c, ok := findColl(chi.URLParam(r, "id"))
	if !ok {
		return nil, nil
	}
	items, err := t.Items(r.Context())
	if err != nil {
		return nil, err
	}
	objs := StixObjects(Aggregate(items, Filter{MinSeverity: c.MinSeverity}))
	// Stable order by modified time, then id, for pagination.
	sort.SliceStable(objs, func(i, j int) bool {
		mi, mj := objs[i]["modified"].(string), objs[j]["modified"].(string)
		if mi != mj {
			return mi < mj
		}
		return objs[i]["id"].(string) < objs[j]["id"].(string)
	})
	q := r.URL.Query()
	var out []map[string]any
	var after time.Time
	if v := q.Get("added_after"); v != "" {
		after, _ = time.Parse(time.RFC3339Nano, v)
	}
	types := map[string]bool{}
	for _, v := range strings.Split(q.Get("match[type]"), ",") {
		if v != "" {
			types[v] = true
		}
	}
	ids := map[string]bool{}
	for _, v := range strings.Split(q.Get("match[id]"), ",") {
		if v != "" {
			ids[v] = true
		}
	}
	for _, o := range objs {
		if len(types) > 0 && !types[o["type"].(string)] {
			continue
		}
		if len(ids) > 0 && !ids[o["id"].(string)] {
			continue
		}
		if !after.IsZero() {
			m, _ := time.Parse(time.RFC3339Nano, o["modified"].(string))
			if !m.After(after) {
				continue
			}
		}
		out = append(out, o)
	}
	return out, nil
}

func page(r *http.Request, objs []map[string]any) ([]map[string]any, bool, string) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("next"))
	if start < 0 || start > len(objs) {
		start = 0
	}
	end := min(start+limit, len(objs))
	more := end < len(objs)
	next := ""
	if more {
		next = strconv.Itoa(end)
	}
	return objs[start:end], more, next
}

func (t *TAXII) objects(w http.ResponseWriter, r *http.Request) {
	if _, ok := findColl(chi.URLParam(r, "id")); !ok {
		taxiiErr(w, 404, "collection not found")
		return
	}
	objs, err := t.collectionObjects(r)
	if err != nil {
		taxiiErr(w, 500, err.Error())
		return
	}
	pg, more, next := page(r, objs)
	if len(pg) > 0 {
		w.Header().Set("X-TAXII-Date-Added-First", pg[0]["modified"].(string))
		w.Header().Set("X-TAXII-Date-Added-Last", pg[len(pg)-1]["modified"].(string))
	}
	env := map[string]any{"more": more, "objects": pg}
	if next != "" {
		env["next"] = next
	}
	if pg == nil {
		env["objects"] = []any{}
	}
	taxiiJSON(w, 200, env)
}

func (t *TAXII) manifest(w http.ResponseWriter, r *http.Request) {
	if _, ok := findColl(chi.URLParam(r, "id")); !ok {
		taxiiErr(w, 404, "collection not found")
		return
	}
	objs, err := t.collectionObjects(r)
	if err != nil {
		taxiiErr(w, 500, err.Error())
		return
	}
	pg, more, next := page(r, objs)
	var man []map[string]any
	for _, o := range pg {
		man = append(man, map[string]any{"id": o["id"], "date_added": o["modified"], "version": o["modified"],
			"media_type": "application/stix+json;version=2.1"})
	}
	env := map[string]any{"more": more, "objects": man}
	if next != "" {
		env["next"] = next
	}
	taxiiJSON(w, 200, env)
}

// CollectionInfo is exposed in the UI's integration panel.
func CollectionInfo(base string) []map[string]string {
	var out []map[string]string
	for _, c := range collections {
		out = append(out, map[string]string{"id": c.ID, "title": c.Title, "objectsUrl": base + "/taxii2/api/collections/" + c.ID + "/objects/"})
	}
	return out
}
