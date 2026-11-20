package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/ioc"
)

// Intel performs on-demand external lookups: NVD + CISA KEV for CVEs, and
// VirusTotal / AbuseIPDB for IOC reputation when API keys are configured.
type Intel struct {
	client    *http.Client
	ua        string
	nvdKey    string
	vtKey     string
	abuseKey  string
	kevMu     sync.Mutex
	kev       map[string]map[string]any
	kevLoaded time.Time

	// Overridable for tests.
	NVDBase, KEVURL, VTBase, AbuseBase string
}

func NewIntel(ua, nvdKey, vtKey, abuseKey string) *Intel {
	return &Intel{client: &http.Client{Timeout: 20 * time.Second}, ua: ua, nvdKey: nvdKey, vtKey: vtKey, abuseKey: abuseKey,
		NVDBase:   "https://services.nvd.nist.gov/rest/json/cves/2.0",
		KEVURL:    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		VTBase:    "https://www.virustotal.com/api/v3",
		AbuseBase: "https://api.abuseipdb.com/api/v2"}
}

func (in *Intel) getJSON(ctx context.Context, u string, headers map[string]string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", in.ua)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := in.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if resp.StatusCode == 404 {
		return 404, nil
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	return resp.StatusCode, json.Unmarshal(data, out)
}

func (in *Intel) kevEntry(ctx context.Context, cve string) (map[string]any, error) {
	in.kevMu.Lock()
	defer in.kevMu.Unlock()
	if in.kev == nil || time.Since(in.kevLoaded) > 6*time.Hour {
		var cat struct {
			Vulnerabilities []map[string]any `json:"vulnerabilities"`
		}
		if _, err := in.getJSON(ctx, in.KEVURL, nil, &cat); err != nil {
			return nil, err
		}
		in.kev = map[string]map[string]any{}
		for _, v := range cat.Vulnerabilities {
			if id, _ := v["cveID"].(string); id != "" {
				in.kev[strings.ToUpper(id)] = v
			}
		}
		in.kevLoaded = time.Now()
	}
	return in.kev[strings.ToUpper(cve)], nil
}

func (in *Intel) LookupCVE(ctx context.Context, cve string) (map[string]any, error) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	if !strings.HasPrefix(cve, "CVE-") {
		return nil, fmt.Errorf("not a CVE id: %q", cve)
	}
	out := map[string]any{"cve": cve}
	if kev, err := in.kevEntry(ctx, cve); err != nil {
		out["kev_error"] = err.Error()
	} else if kev != nil {
		out["cisa_kev"] = kev
	} else {
		out["cisa_kev"] = "not in the CISA Known Exploited Vulnerabilities catalog"
	}
	var nvd struct {
		Vulnerabilities []struct {
			CVE struct {
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				VulnStatus   string `json:"vulnStatus"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
						VectorString string  `json:"vectorString"`
					} `json:"cvssData"`
					Source string `json:"source"`
				} `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Criteria            string `json:"criteria"`
							VersionEndExcluding string `json:"versionEndExcluding"`
							VersionEndIncluding string `json:"versionEndIncluding"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
				References []struct {
					URL  string   `json:"url"`
					Tags []string `json:"tags"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	headers := map[string]string{}
	if in.nvdKey != "" {
		headers["apiKey"] = in.nvdKey
	}
	if _, err := in.getJSON(ctx, in.NVDBase+"?cveId="+url.QueryEscape(cve), headers, &nvd); err != nil {
		out["nvd_error"] = err.Error()
		return out, nil
	}
	if len(nvd.Vulnerabilities) == 0 {
		out["nvd"] = "not found in NVD (may be reserved or not yet published)"
		return out, nil
	}
	c := nvd.Vulnerabilities[0].CVE
	n := map[string]any{"published": c.Published, "last_modified": c.LastModified, "status": c.VulnStatus}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			n["description"] = d.Value
		}
	}
	var scores []map[string]any
	for k, ms := range c.Metrics {
		for _, m := range ms {
			scores = append(scores, map[string]any{"version": k, "score": m.CVSSData.BaseScore, "severity": m.CVSSData.BaseSeverity, "vector": m.CVSSData.VectorString, "source": m.Source})
		}
	}
	n["cvss"] = scores
	var cwes []string
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			cwes = append(cwes, d.Value)
		}
	}
	n["cwe"] = cwes
	var cpes []string
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				s := m.Criteria
				if m.VersionEndExcluding != "" {
					s += " (< " + m.VersionEndExcluding + ")"
				} else if m.VersionEndIncluding != "" {
					s += " (<= " + m.VersionEndIncluding + ")"
				}
				if len(cpes) < 25 {
					cpes = append(cpes, s)
				}
			}
		}
	}
	n["affected_cpes"] = cpes
	var refs []string
	for _, r := range c.References {
		if len(refs) < 12 {
			refs = append(refs, r.URL+" "+strings.Join(r.Tags, ","))
		}
	}
	n["references"] = refs
	out["nvd"] = n
	return out, nil
}

func (in *Intel) Reputation(ctx context.Context, typ, value string) (map[string]any, error) {
	value = ioc.Refang(strings.TrimSpace(value))
	typ = strings.ToLower(typ)
	out := map[string]any{"type": typ, "value": value}
	if in.vtKey != "" {
		var path string
		switch typ {
		case "ip":
			path = "/ip_addresses/" + url.PathEscape(value)
		case "domain":
			path = "/domains/" + url.PathEscape(value)
		case "url":
			path = "/urls/" + base64.RawURLEncoding.EncodeToString([]byte(value))
		case "md5", "sha1", "sha256", "hash":
			path = "/files/" + url.PathEscape(value)
		}
		if path != "" {
			var vt struct {
				Data struct {
					Attributes map[string]any `json:"attributes"`
				} `json:"data"`
			}
			status, err := in.getJSON(ctx, in.VTBase+path, map[string]string{"x-apikey": in.vtKey}, &vt)
			switch {
			case err != nil:
				out["virustotal_error"] = err.Error()
			case status == 404:
				out["virustotal"] = "not found in VirusTotal"
			default:
				a := vt.Data.Attributes
				keep := map[string]any{}
				for _, k := range []string{"last_analysis_stats", "reputation", "tags", "type_description", "meaningful_name",
					"popular_threat_classification", "first_submission_date", "last_analysis_date", "country", "as_owner",
					"asn", "categories", "registrar", "creation_date", "times_submitted", "names"} {
					if v, ok := a[k]; ok {
						keep[k] = v
					}
				}
				if names, ok := keep["names"].([]any); ok && len(names) > 10 {
					keep["names"] = names[:10]
				}
				out["virustotal"] = keep
			}
		}
	}
	if in.abuseKey != "" && typ == "ip" {
		var ab struct {
			Data map[string]any `json:"data"`
		}
		if _, err := in.getJSON(ctx, in.AbuseBase+"/check?maxAgeInDays=90&ipAddress="+url.QueryEscape(value),
			map[string]string{"Key": in.abuseKey}, &ab); err != nil {
			out["abuseipdb_error"] = err.Error()
		} else {
			out["abuseipdb"] = ab.Data
		}
	}
	if len(out) == 2 {
		out["note"] = "no reputation source supports this indicator type"
	}
	return out, nil
}

func (tb *Toolbox) registerIntel() {
	if tb.intel == nil {
		return
	}
	in := tb.intel
	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "lookup_cve",
			Description: "Look up a CVE in NVD (description, CVSS, CWE, affected CPEs/versions, references) and the CISA KEV catalog (exploited-in-the-wild status, due date, ransomware use).",
			Properties:  map[string]any{"cve": map[string]any{"type": "string", "description": "e.g. CVE-2026-1234"}},
			Required:    []string{"cve"},
		},
		Run: func(ctx context.Context, raw json.RawMessage) (any, string, error) {
			var a struct {
				CVE string `json:"cve"`
			}
			if err := decodeStrict(raw, &a); err != nil {
				return nil, "", err
			}
			res, err := in.LookupCVE(ctx, a.CVE)
			if err != nil {
				return nil, "", err
			}
			s := "Looked up " + strings.ToUpper(a.CVE) + " in NVD"
			if _, ok := res["cisa_kev"].(map[string]any); ok {
				s += " (in CISA KEV)"
			}
			return res, s, nil
		},
	})
	if in.vtKey == "" && in.abuseKey == "" {
		return
	}
	var sources []string
	if in.vtKey != "" {
		sources = append(sources, "VirusTotal (ip, domain, url, file hashes)")
	}
	if in.abuseKey != "" {
		sources = append(sources, "AbuseIPDB (ip)")
	}
	tb.add(Tool{
		Def: ai.ToolDef{
			Name:        "ioc_reputation",
			Description: "Check an indicator's reputation with " + strings.Join(sources, " and ") + ". Free API quotas are small: look up each indicator at most once.",
			Properties: map[string]any{
				"type":  map[string]any{"type": "string", "enum": []string{"ip", "domain", "url", "md5", "sha1", "sha256"}},
				"value": map[string]any{"type": "string", "description": "the indicator (defanged input is accepted)"},
			},
			Required: []string{"type", "value"},
		},
		Run: func(ctx context.Context, raw json.RawMessage) (any, string, error) {
			var a struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			}
			if err := decodeStrict(raw, &a); err != nil {
				return nil, "", err
			}
			res, err := in.Reputation(ctx, a.Type, a.Value)
			if err != nil {
				return nil, "", err
			}
			s := "Checked reputation of " + ioc.Defang(a.Type, ioc.Refang(a.Value))
			if vt, ok := res["virustotal"].(map[string]any); ok {
				if st, ok := vt["last_analysis_stats"].(map[string]any); ok {
					s += fmt.Sprintf(" — VT malicious: %v", st["malicious"])
				}
			}
			return res, s, nil
		},
	})
}
