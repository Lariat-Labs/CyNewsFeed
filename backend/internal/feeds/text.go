package feeds

import (
	"crypto/sha256"
	"encoding/hex"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var trackingParams = map[string]bool{
	"fbclid": true, "gclid": true, "mc_cid": true, "mc_eid": true, "ref": true, "source": true,
	"cmpid": true, "_hsenc": true, "_hsmi": true, "mkt_tok": true,
}

// CanonicalURL normalises a link so the same article from different feeds or
// with tracking params dedupes to the same ID.
func CanonicalURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	u.Scheme = "https"
	u.Host = strings.TrimPrefix(strings.ToLower(u.Host), "www.")
	u.Fragment = ""
	q := u.Query()
	for k := range q {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "utm_") || trackingParams[lk] {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	if len(u.Path) > 1 {
		u.Path = strings.TrimRight(u.Path, "/")
	}
	return u.String()
}

// ItemID is a stable short hash of the canonical URL (or a fallback key).
func ItemID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:20]
}

var cveRe = regexp.MustCompile(`(?i)\bCVE-(\d{4})-(\d{4,7})\b`)

// ExtractCVEs returns unique, upper-cased CVE IDs found in text.
func ExtractCVEs(texts ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range texts {
		for _, m := range cveRe.FindAllStringSubmatch(t, -1) {
			id := "CVE-" + m[1] + "-" + m[2]
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

var (
	tagRe   = regexp.MustCompile(`(?s)<(script|style)[^>]*>.*?</(script|style)>|<[^>]+>`)
	spaceRe = regexp.MustCompile(`[ \t\r\f\v]+`)
	nlRe    = regexp.MustCompile(`\n{3,}`)
)

// StripHTML converts an HTML fragment to readable plain text.
func StripHTML(s string) string {
	s = strings.NewReplacer("<br>", "\n", "<br/>", "\n", "<br />", "\n", "</p>", "\n\n", "</li>", "\n").Replace(s)
	s = tagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = spaceRe.ReplaceAllString(s, " ")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	s = nlRe.ReplaceAllString(strings.Join(lines, "\n"), "\n\n")
	return strings.TrimSpace(s)
}

// Truncate cuts s to at most n runes on a word boundary, adding an ellipsis.
func Truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)[:n]
	cut := string(r)
	if i := strings.LastIndexAny(cut, " \n"); i > n/2 {
		cut = cut[:i]
	}
	return strings.TrimSpace(cut) + "…"
}

// Slug makes a URL-safe identifier.
func Slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	dash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
