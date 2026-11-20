// Package analysis groups cross-source coverage into events, detects rising
// entities, and builds ATT&CK / ATLAS / OWASP-LLM coverage views.
package analysis

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"

	"cynewsfeed/internal/model"
)

// Event is a cluster of stories about the same incident or disclosure.
type Event struct {
	ID        string         `json:"id"`
	Title     string         `json:"title"`
	Severity  model.Severity `json:"severity"`
	Sources   int            `json:"sources"`
	Stories   int            `json:"stories"`
	FirstSeen time.Time      `json:"firstSeen"`
	LastSeen  time.Time      `json:"lastSeen"`
	CVEs      []string       `json:"cves,omitempty"`
	Actors    []string       `json:"actors,omitempty"`
	Malware   []string       `json:"malware,omitempty"`
	Products  []string       `json:"products,omitempty"`
	Items     []EventItem    `json:"items"`
	Score     float64        `json:"score"`
}

type EventItem struct {
	ID        string         `json:"id"`
	Title     string         `json:"title"`
	Source    string         `json:"source"`
	Published time.Time      `json:"published"`
	Severity  model.Severity `json:"severity"`
	TLDR      string         `json:"tldr,omitempty"`
}

var wordRe = regexp.MustCompile(`[a-z0-9][a-z0-9\-\.]*[a-z0-9]`)

var stop = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`the and for with from that this into over about after before amid new news says said report reports
	how what why who are was were has have had its it's not but you your our their they them his her than then just more most
	security cyber cybersecurity attack attacks attackers hackers hacker hacked vulnerability vulnerabilities flaw flaws bug bugs
	patch patches patched update updates fix fixes fixed exploit exploited exploits exploitation critical high severity warns warning
	week weekly daily today data breach breaches threat threats malware ransomware users user company companies firm million billion
	via using used use could may might will can now still also amp episode podcast part one two three
	remote code execution rce injection command sql cross site scripting xss improper authentication bypass privilege escalation
	path traversal arbitrary deserialization untrusted unsafe reflection denial service dos memory corruption overflow buffer heap
	kev cisa adds known catalog products software multiple systems devices active actively immediate immediately urges urged warns
	issues issued releases released fixes vendors researchers disclose disclosed details detailed analysis campaign campaigns`) {
		stop[w] = true
	}
}

func titleTokens(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range wordRe.FindAllString(strings.ToLower(s), -1) {
		if len(w) >= 3 && !stop[w] {
			out[w] = true
		}
	}
	return out
}

func jaccard(a, b map[string]bool) (float64, int) {
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0, 0
	}
	return float64(inter) / float64(union), inter
}

type uf struct{ p, size []int }

func (u *uf) find(x int) int {
	for u.p[x] != x {
		u.p[x] = u.p[u.p[x]]
		x = u.p[x]
	}
	return x
}
func (u *uf) union(a, b int) {
	ra, rb := u.find(a), u.find(b)
	if ra == rb {
		return
	}
	u.p[ra] = rb
	u.size[rb] += u.size[ra]
}

// Cluster groups items published within `window` of each other that share a
// specific CVE or malware family, or have strongly overlapping titles
// (optionally reinforced by a shared actor/product). Only clusters with at
// least two stories are returned, ranked by score.
func Cluster(items []model.Item, window time.Duration) []Event {
	n := len(items)
	u := &uf{p: make([]int, n), size: make([]int, n)}
	toks := make([]map[string]bool, n)
	for i := range items {
		u.p[i], u.size[i] = i, 1
		toks[i] = titleTokens(items[i].Title)
	}
	near := func(i, j int) bool {
		d := items[i].Published.Sub(items[j].Published)
		return d < window && d > -window
	}
	// Inverted indexes keep candidate comparisons small.
	byKey := map[string][]int{}
	for i, it := range items {
		if len(it.Tags.CVEs) <= 3 { // roundups listing many CVEs would glue unrelated stories together
			for _, c := range it.Tags.CVEs {
				byKey["cve:"+strings.ToUpper(c)] = append(byKey["cve:"+strings.ToUpper(c)], i)
			}
		}
		for _, m := range it.Tags.Malware {
			byKey["mal:"+strings.ToLower(m)] = append(byKey["mal:"+strings.ToLower(m)], i)
		}
	}
	// Multi-topic items (podcast episodes, weekly roundups) must not bridge
	// otherwise-unrelated clusters: link them only after the others, and only
	// to the single cluster they share the most keys with.
	bridge := func(i int) bool {
		it := items[i]
		return it.Category == model.CatPodcast || len(it.Tags.CVEs)+len(it.Tags.Malware) >= 2
	}
	for _, idx := range byKey {
		for a := 0; a < len(idx); a++ {
			for b := a + 1; b < len(idx); b++ {
				if near(idx[a], idx[b]) && !bridge(idx[a]) && !bridge(idx[b]) {
					u.union(idx[a], idx[b])
				}
			}
		}
	}
	for i := range items {
		if !bridge(i) {
			continue
		}
		votes := map[int]int{}
		for k, idx := range byKey {
			_ = k
			has := false
			for _, j := range idx {
				if j == i {
					has = true
					break
				}
			}
			if !has {
				continue
			}
			for _, j := range idx {
				if j != i && !bridge(j) && near(i, j) {
					votes[u.find(j)]++
				}
			}
		}
		best, bestN := -1, 0
		for root, n := range votes {
			if n > bestN || (n == bestN && root < best) {
				best, bestN = root, n
			}
		}
		if best >= 0 {
			u.union(i, best)
		}
	}
	byTok := map[string][]int{}
	for i, t := range toks {
		for w := range t {
			byTok[w] = append(byTok[w], i)
		}
	}
	checked := map[[2]int]bool{}
	for _, idx := range byTok {
		if len(idx) > 60 { // too common to be discriminative
			continue
		}
		for a := 0; a < len(idx); a++ {
			for b := a + 1; b < len(idx); b++ {
				i, j := idx[a], idx[b]
				// Same-feed pairs are rarely duplicates (e.g. many KEV entries share wording).
				if checked[[2]int{i, j}] || !near(i, j) || items[i].FeedID == items[j].FeedID || bridge(i) || bridge(j) {
					continue
				}
				checked[[2]int{i, j}] = true
				jc, inter := jaccard(toks[i], toks[j])
				if (jc >= 0.5 && inter >= 3) || (jc >= 0.3 && inter >= 2 && shareAny(items[i], items[j])) {
					// Weak (title-only) links may not chain clusters into one giant blob.
					if ri, rj := u.find(i), u.find(j); ri == rj || u.size[ri]+u.size[rj] <= 8 {
						u.union(i, j)
					}
				}
			}
		}
	}

	groups := map[int][]int{}
	for i := range items {
		groups[u.find(i)] = append(groups[u.find(i)], i)
	}
	var events []Event
	now := time.Now()
	for _, g := range groups {
		if len(g) < 2 {
			continue
		}
		sort.Slice(g, func(a, b int) bool { return items[g[a]].Published.Before(items[g[b]].Published) })
		ev := Event{FirstSeen: items[g[0]].Published, LastSeen: items[g[len(g)-1]].Published, Stories: len(g)}
		sources := map[string]bool{}
		best := g[0]
		var ids []string
		for _, i := range g {
			it := items[i]
			ids = append(ids, it.ID)
			sources[it.FeedID] = true
			if it.Severity.Rank() > ev.Severity.Rank() || ev.Severity == "" {
				ev.Severity = it.Severity
			}
			if it.Severity.Rank() > items[best].Severity.Rank() || (it.Severity == items[best].Severity && it.Category != model.CatPodcast && items[best].Category == model.CatPodcast) {
				best = i
			}
			ev.CVEs = addAll(ev.CVEs, it.Tags.CVEs, 10)
			ev.Actors = addAll(ev.Actors, it.Tags.ThreatActors, 6)
			ev.Malware = addAll(ev.Malware, it.Tags.Malware, 6)
			ev.Products = addAll(ev.Products, it.Tags.Products, 6)
			tl := it.TLDR
			if tl == "" {
				tl = it.Snippet
			}
			if len(tl) > 280 {
				tl = tl[:280] + "…"
			}
			ev.Items = append(ev.Items, EventItem{ID: it.ID, Title: it.Title, Source: it.FeedName, Published: it.Published, Severity: it.Severity, TLDR: tl})
		}
		ev.Sources = len(sources)
		ev.Title = items[best].Title
		sum := sha1.Sum([]byte(ids[0]))
		ev.ID = hex.EncodeToString(sum[:8])
		ageDays := now.Sub(ev.LastSeen).Hours() / 24
		ev.Score = float64(ev.Sources)*2 + float64(ev.Stories)*0.5 + float64(ev.Severity.Rank())*3 - ageDays*0.5
		events = append(events, ev)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Score > events[j].Score })
	return events
}

func shareAny(a, b model.Item) bool {
	set := map[string]bool{}
	for _, v := range append(append([]string{}, a.Tags.ThreatActors...), a.Tags.Products...) {
		set[strings.ToLower(v)] = true
	}
	for _, v := range append(append([]string{}, b.Tags.ThreatActors...), b.Tags.Products...) {
		if set[strings.ToLower(v)] {
			return true
		}
	}
	return false
}

func addAll(dst, src []string, max int) []string {
	seen := map[string]bool{}
	for _, v := range dst {
		seen[strings.ToLower(v)] = true
	}
	for _, v := range src {
		if len(dst) >= max {
			break
		}
		if !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			dst = append(dst, v)
		}
	}
	return dst
}

// ---------------- trends ----------------

type Trend struct {
	Kind     string  `json:"kind"` // cve | actor | malware | vendor | product | topic | attack | owasp
	Name     string  `json:"name"`
	Recent   int     `json:"recent"`   // stories in the recent window
	Baseline int     `json:"baseline"` // stories in the baseline window
	Ratio    float64 `json:"ratio"`    // recent daily rate vs baseline daily rate (smoothed)
	New      bool    `json:"new"`      // not seen in the baseline window
	Daily    []int   `json:"daily"`    // per-day counts across baseline+recent, oldest first
}

// Trends compares entity mentions in the last `recentDays` against the
// preceding `baselineDays`. Requires at least minRecent stories.
func Trends(items []model.Item, now time.Time, recentDays, baselineDays, minRecent int) []Trend {
	total := recentDays + baselineDays
	start := now.AddDate(0, 0, -total)
	recentStart := now.AddDate(0, 0, -recentDays)
	type acc struct {
		kind, name       string
		recent, baseline int
		daily            []int
	}
	m := map[string]*acc{}
	for _, it := range items {
		if it.Published.Before(start) || it.Published.After(now) {
			continue
		}
		day := int(it.Published.Sub(start).Hours() / 24)
		if day >= total {
			day = total - 1
		}
		seen := map[string]bool{}
		add := func(kind, name string) {
			k := kind + "|" + strings.ToLower(name)
			if name == "" || seen[k] {
				return
			}
			seen[k] = true
			a := m[k]
			if a == nil {
				a = &acc{kind: kind, name: name, daily: make([]int, total)}
				m[k] = a
			}
			a.daily[day]++
			if it.Published.Before(recentStart) {
				a.baseline++
			} else {
				a.recent++
			}
		}
		t := it.Tags
		for _, v := range t.CVEs {
			add("cve", v)
		}
		for _, v := range t.ThreatActors {
			add("actor", v)
		}
		for _, v := range t.Malware {
			add("malware", v)
		}
		for _, v := range t.Vendors {
			add("vendor", v)
		}
		for _, v := range t.Products {
			add("product", v)
		}
		for _, v := range t.Topics {
			add("topic", v)
		}
		for _, v := range t.Attack {
			add("attack", v.ID)
		}
		for _, v := range t.OwaspLLM {
			add("owasp", v)
		}
	}
	var out []Trend
	for _, a := range m {
		if a.recent < minRecent {
			continue
		}
		recentRate := float64(a.recent) / float64(recentDays)
		baseRate := float64(a.baseline) / float64(baselineDays)
		ratio := (recentRate + 0.1) / (baseRate + 0.1)
		if ratio < 1.5 && a.baseline > 0 {
			continue
		}
		out = append(out, Trend{Kind: a.kind, Name: a.name, Recent: a.recent, Baseline: a.baseline, Ratio: ratio, New: a.baseline == 0, Daily: a.daily})
	}
	// Broad labels (topics, big vendors) rise with overall volume; rank
	// specific entities (CVEs, actors, malware, products) ahead of them.
	weight := map[string]float64{"topic": 0.3, "vendor": 0.5}
	score := func(t Trend) float64 {
		w, ok := weight[t.Kind]
		if !ok {
			w = 1
		}
		return t.Ratio * float64(t.Recent) * w
	}
	sort.Slice(out, func(i, j int) bool { return score(out[i]) > score(out[j]) })
	return out
}

// ---------------- framework coverage ----------------

type TechniqueCount struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactic  string   `json:"tactic"`
	Count   int      `json:"count"`
	ItemIDs []string `json:"itemIds"`
}

type Coverage struct {
	Attack       map[string][]TechniqueCount `json:"attack"` // tactic -> techniques
	Atlas        map[string][]TechniqueCount `json:"atlas"`
	OWASP        map[string]int              `json:"owasp"`
	OWASPItems   map[string][]string         `json:"owaspItems"`
	TaggedAttack int                         `json:"taggedAttack"`
	TaggedAI     int                         `json:"taggedAi"`
}

// Frameworks counts ATT&CK / ATLAS techniques by tactic and OWASP LLM categories.
func Frameworks(items []model.Item) Coverage {
	cov := Coverage{Attack: map[string][]TechniqueCount{}, Atlas: map[string][]TechniqueCount{}, OWASP: map[string]int{}, OWASPItems: map[string][]string{}}
	tally := func(dst map[string][]TechniqueCount, techs []model.Technique, itemID string) {
		for _, t := range techs {
			tac := t.Tactic
			if tac == "" {
				tac = "Unspecified"
			}
			found := false
			for i := range dst[tac] {
				if dst[tac][i].ID == t.ID {
					dst[tac][i].Count++
					if len(dst[tac][i].ItemIDs) < 25 {
						dst[tac][i].ItemIDs = append(dst[tac][i].ItemIDs, itemID)
					}
					if dst[tac][i].Name == "" {
						dst[tac][i].Name = t.Name
					}
					found = true
				}
			}
			if !found {
				dst[tac] = append(dst[tac], TechniqueCount{ID: t.ID, Name: t.Name, Tactic: tac, Count: 1, ItemIDs: []string{itemID}})
			}
		}
	}
	for _, it := range items {
		if len(it.Tags.Attack) > 0 {
			cov.TaggedAttack++
		}
		if len(it.Tags.Atlas) > 0 || len(it.Tags.OwaspLLM) > 0 || it.Category == model.CatAI {
			cov.TaggedAI++
		}
		tally(cov.Attack, it.Tags.Attack, it.ID)
		tally(cov.Atlas, it.Tags.Atlas, it.ID)
		for _, o := range it.Tags.OwaspLLM {
			cov.OWASP[o]++
			if len(cov.OWASPItems[o]) < 25 {
				cov.OWASPItems[o] = append(cov.OWASPItems[o], it.ID)
			}
		}
	}
	for _, m := range []map[string][]TechniqueCount{cov.Attack, cov.Atlas} {
		for k := range m {
			sort.Slice(m[k], func(i, j int) bool { return m[k][i].Count > m[k][j].Count })
		}
	}
	return cov
}
