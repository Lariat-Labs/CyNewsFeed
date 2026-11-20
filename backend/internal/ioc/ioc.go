// Package ioc extracts network and file indicators of compromise from text,
// handling common defanging (hxxp, [.], (dot), [@]).
package ioc

import (
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"cynewsfeed/internal/model"
)

var refanger = strings.NewReplacer(
	"[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".", " [.] ", ".",
	"[:]", ":", "[://]", "://", "[@]", "@", "(at)", "@", "[at]", "@",
	"hxxps", "https", "hxxp", "http", "hXXps", "https", "hXXp", "http", "fxp", "ftp",
)

// Refang converts a defanged indicator back to its usable form.
func Refang(s string) string { return refanger.Replace(s) }

// Defang makes an indicator safe to paste (non-clickable).
func Defang(t, v string) string {
	switch t {
	case "url":
		v = strings.Replace(strings.Replace(v, "https://", "hxxps://", 1), "http://", "hxxp://", 1)
		fallthrough
	case "domain", "ip", "email":
		if i := strings.LastIndex(v, "."); i > 0 {
			v = v[:i] + "[.]" + v[i+1:]
		}
	}
	return v
}

var (
	reURL    = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s<>"'()\[\]{}]+`)
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reEmail  = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b`)
	reDomain = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b`)
	reSHA256 = regexp.MustCompile(`(?i)\b[a-f0-9]{64}\b`)
	reSHA1   = regexp.MustCompile(`(?i)\b[a-f0-9]{40}\b`)
	reMD5    = regexp.MustCompile(`(?i)\b[a-f0-9]{32}\b`)
	defangRe = regexp.MustCompile(`(?i)\[\.\]|\(\.\)|\[dot\]|\(dot\)|hxxp|\[@\]|\[:\]`)
)

// TLDs accepted for un-defanged bare domains. Restricting this list avoids
// matching file names (update.exe) and code (window.location).
var commonTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "ru": true, "cn": true, "info": true, "biz": true,
	"xyz": true, "top": true, "online": true, "site": true, "club": true, "co": true, "me": true, "tk": true,
	"cc": true, "su": true, "pw": true, "ws": true, "app": true, "dev": true, "cloud": true, "live": true,
	"shop": true, "store": true, "link": true, "click": true, "icu": true, "buzz": true, "uk": true, "de": true,
	"ir": true, "kp": true, "ua": true, "br": true, "in": true, "jp": true, "kr": true, "us": true, "eu": true,
}

// Domains that appear constantly in security writing and are not IOCs.
var benignDomains = map[string]bool{
	"microsoft.com": true, "google.com": true, "github.com": true, "apple.com": true, "amazon.com": true,
	"cisa.gov": true, "nist.gov": true, "mitre.org": true, "twitter.com": true, "x.com": true,
	"linkedin.com": true, "youtube.com": true, "facebook.com": true, "virustotal.com": true,
	"example.com": true, "example.org": true, "example.net": true, "wikipedia.org": true, "w3.org": true,
	"cloudflare.com": true, "medium.com": true, "reddit.com": true, "bleepingcomputer.com": true,
	"thehackernews.com": true, "therecord.media": true, "securityweek.com": true, "darkreading.com": true,
	"apple.news": true, "gmail.com": true, "outlook.com": true, "office.com": true, "azure.com": true,
	"windows.net": true, "amazonaws.com": true, "googleapis.com": true, "gstatic.com": true,
	"feedburner.com": true, "wordpress.com": true, "substack.com": true, "t.co": true, "bit.ly": true,
	"microsoftonline.com": true, "live.com": true, "sharepoint.com": true, "office365.com": true, "microsoft.net": true,
	"github.io": true, "githubusercontent.com": true, "npmjs.com": true, "pypi.org": true, "python.org": true, "nodejs.org": true,
	"apple.com.": true, "icloud.com": true, "slack.com": true, "zoom.us": true, "dropbox.com": true, "box.com": true,
	"telegram.org": true, "discord.com": true, "openai.com": true, "anthropic.com": true, "huggingface.co": true,
}

// Defanged candidates: hostnames/URLs that contain at least one defang marker.
var (
	defangURL  = regexp.MustCompile(`(?i)\b(?:h[x]{2}ps?|fxp|https?)(?:\[:\]|:)//[^\s<>"'()]+`)
	defangHost = regexp.MustCompile(`(?i)(?:[a-z0-9._%+\-]+(?:\[@\]|\(at\)|\[at\]|@))?[a-z0-9_\-]+(?:(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\.)[a-z0-9_\-]+)*(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))[a-z0-9_\-]+(?:(?:\[\.\]|\(\.\)|\.)[a-z0-9_\-]+)*`)
	marker     = regexp.MustCompile(`(?i)\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|h[x]{2}p|\[:\]|\[@\]`)
)

// fileExt are "TLDs" that are really file extensions (cmd.exe, tasks.json, ...).
var fileExt = map[string]bool{}

func init() {
	for _, e := range strings.Fields(`exe dll js mjs cjs json dat cmd plist ashx aspx asp php jsp py pyc ps1 psm1 bat vbs vbe sh bash zsh zip rar 7z gz tgz tar
	txt log xml html htm jar war lnk iso img msi msix docx doc docm xlsx xls xlsm pptx ppt pdf rtf so dylib bin tmp sys ini cfg conf yaml yml md ts tsx jsx
	go rs java class apk ipa dmg pkg deb rpm vhd vhdx hta wsf scr cpl ocx drv efi mui db sqlite csv png jpg jpeg gif svg ico css map lock toml env key pem
	crt cer pfx p12 asc gpg dmp bak old swp out o a lib pdb manifest config properties gradle mod sum node vue rb pl lua cs vb cpp hpp h c sln csproj`) {
		fileExt[e] = true
	}
}

// Extract returns unique IOCs found in the texts. Only explicitly defanged
// hostnames/URLs/emails are taken as network indicators (plus public IPs, URLs
// on raw IPs, and bare domains on TLDs rarely used by legitimate sites), so
// file names and reference links aren't reported. sourceHosts are excluded.
func Extract(sourceHosts []string, texts ...string) []model.IOC {
	skip := map[string]bool{}
	for _, h := range sourceHosts {
		skip[baseDomain(strings.ToLower(strings.TrimPrefix(h, "www.")))] = true
	}
	seen := map[string]bool{}
	var out []model.IOC
	add := func(t, v string) {
		k := t + "|" + strings.ToLower(v)
		if v == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, model.IOC{Type: t, Value: v})
	}
	okHost := func(host string) bool {
		host = strings.ToLower(strings.Trim(host, "."))
		if isIP(host) {
			return true
		}
		i := strings.LastIndex(host, ".")
		if i <= 0 {
			return false
		}
		tld := host[i+1:]
		if fileExt[tld] || len(tld) < 2 || strings.ContainsAny(tld, "0123456789_-") {
			return false
		}
		bd := baseDomain(host)
		return !skip[bd] && !benignDomains[bd] && !reverseDNS(host)
	}
	addHost := func(h string) {
		h = strings.ToLower(strings.Trim(h, ".,;:"))
		if strings.Contains(h, "@") {
			parts := strings.SplitN(h, "@", 2)
			if parts[0] != "" && okHost(parts[1]) && !isIP(parts[1]) {
				add("email", h)
			}
			return
		}
		if a, err := netip.ParseAddr(h); err == nil {
			if a.IsGlobalUnicast() && !a.IsPrivate() {
				add("ip", h)
			}
			return
		}
		if okHost(h) {
			add("domain", h)
		}
	}

	for _, raw := range texts {
		if raw == "" {
			continue
		}
		// 1. Explicitly defanged URLs and hostnames.
		urlSpans := defangURL.FindAllStringIndex(raw, -1)
		for _, sp := range urlSpans {
			tok := raw[sp[0]:sp[1]]
			if !marker.MatchString(tok) {
				continue
			}
			u := strings.TrimRight(Refang(tok), ".,;:!?")
			if pu, err := url.Parse(u); err == nil && pu.Host != "" && okHost(pu.Hostname()) {
				add("url", u)
			}
		}
		inURL := func(i int) bool {
			for _, sp := range urlSpans {
				if i >= sp[0] && i < sp[1] {
					return true
				}
			}
			return false
		}
		for _, sp := range defangHost.FindAllStringIndex(raw, -1) {
			if inURL(sp[0]) {
				continue
			}
			addHost(Refang(raw[sp[0]:sp[1]]))
		}

		// 2. Plain text: public IPs, URLs on raw IPs, hashes, and bare domains on unusual TLDs.
		text := Refang(raw)
		for _, m := range reURL.FindAllString(text, -1) {
			u := strings.TrimRight(m, ".,;:!?")
			if pu, err := url.Parse(u); err == nil && isIP(pu.Hostname()) {
				if a, _ := netip.ParseAddr(pu.Hostname()); a.IsGlobalUnicast() && !a.IsPrivate() {
					add("url", u)
				}
			}
		}
		for _, sp := range reIPv4.FindAllStringIndex(text, -1) {
			ip := text[sp[0]:sp[1]]
			if sp[0] > 0 && (text[sp[0]-1] == 'v' || text[sp[0]-1] == 'V' || text[sp[0]-1] == '.') {
				continue // version strings
			}
			if sp[1] < len(text) && text[sp[1]] == '.' && sp[1]+1 < len(text) && text[sp[1]+1] >= '0' && text[sp[1]+1] <= '9' {
				continue // 1.2.3.4.5 style version
			}
			if a, err := netip.ParseAddr(ip); err == nil && a.IsGlobalUnicast() && !a.IsPrivate() {
				add("ip", ip)
			}
		}
		for _, m := range reSHA256.FindAllString(text, -1) {
			add("sha256", strings.ToLower(m))
		}
		for _, m := range reSHA1.FindAllString(text, -1) {
			add("sha1", strings.ToLower(m))
		}
		for _, m := range reMD5.FindAllString(text, -1) {
			add("md5", strings.ToLower(m))
		}
		plainURLs := reURL.FindAllStringIndex(text, -1)
		for _, sp := range reDomain.FindAllStringSubmatchIndex(text, -1) {
			in := false
			for _, u := range plainURLs {
				if sp[0] >= u[0] && sp[0] < u[1] {
					in = true
				}
			}
			if in || (sp[0] > 0 && (text[sp[0]-1] == '@' || text[sp[0]-1] == '/')) {
				continue
			}
			d := strings.ToLower(text[sp[0]:sp[1]])
			tld := strings.ToLower(text[sp[2]:sp[3]])
			if commonTLDs[tld] && !proseTLD[tld] && okHost(d) {
				add("domain", d)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

// TLDs common in ordinary prose (company sites) that are only kept when defanged.
var proseTLD = map[string]bool{"com": true, "net": true, "org": true, "io": true, "co": true, "uk": true,
	"de": true, "us": true, "eu": true, "in": true, "jp": true, "me": true, "dev": true, "app": true}

func isIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func baseDomain(h string) string {
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	// Handle two-level public suffixes like co.uk / com.au.
	if len(parts[len(parts)-2]) <= 3 && len(parts[len(parts)-1]) == 2 && len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// Merge combines IOC lists, deduping case-insensitively.
func Merge(a, b []model.IOC) []model.IOC {
	seen := map[string]bool{}
	var out []model.IOC
	for _, l := range [][]model.IOC{a, b} {
		for _, i := range l {
			i.Type = strings.ToLower(strings.TrimSpace(i.Type))
			i.Value = Refang(strings.TrimSpace(i.Value))
			k := i.Type + "|" + strings.ToLower(i.Value)
			if i.Value == "" || seen[k] || !validType[i.Type] || !plausible(i) {
				continue
			}
			seen[k] = true
			out = append(out, i)
		}
	}
	return out
}

var validType = map[string]bool{"ip": true, "domain": true, "url": true, "md5": true, "sha1": true, "sha256": true, "email": true}

// plausible rejects indicators that are really file names or well-known benign infrastructure.
func plausible(i model.IOC) bool {
	host := ""
	switch i.Type {
	case "domain":
		host = i.Value
	case "email":
		if at := strings.LastIndex(i.Value, "@"); at > 0 {
			host = i.Value[at+1:]
		}
	case "url":
		if u, err := url.Parse(i.Value); err == nil {
			host = u.Hostname()
		}
	default:
		return true
	}
	host = strings.ToLower(strings.Trim(host, "."))
	if host == "" {
		return false
	}
	if isIP(host) {
		return true
	}
	dot := strings.LastIndex(host, ".")
	if dot <= 0 {
		return false
	}
	tld := host[dot+1:]
	return !fileExt[tld] && !strings.ContainsAny(tld, "0123456789_-") && !benignDomains[baseDomain(host)] && !reverseDNS(host)
}

// reverseDNS spots bundle/package identifiers like com.zoom or org.mozilla.firefox.
func reverseDNS(host string) bool {
	first := host[:strings.Index(host, ".")]
	switch first {
	case "com", "org", "net", "io", "co", "edu", "gov":
		return true
	}
	return false
}

// Sanitize filters an existing IOC list (used to clean data stored by older versions).
func Sanitize(in []model.IOC) []model.IOC { return Merge(in, nil) }
