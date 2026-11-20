package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"cynewsfeed/internal/ai"
	"cynewsfeed/internal/model"
	"cynewsfeed/internal/store"
)

// Event is streamed to the UI while the agent works.
type Event struct {
	Type    string             `json:"type"` // text | step_start | step_end | done | error
	Delta   string             `json:"delta,omitempty"`
	Step    *model.ToolStep    `json:"step,omitempty"`
	Message *model.ChatMessage `json:"message,omitempty"`
	Error   string             `json:"error,omitempty"`
}

type Agent struct {
	chatter       ai.Chatter
	tools         *Toolbox
	store         store.Store
	maxSteps      int
	retentionDays int
}

func New(p ai.Provider, tb *Toolbox, st store.Store, maxSteps, retentionDays int) (*Agent, error) {
	c, ok := ai.AsChatter(p)
	if !ok {
		return nil, ai.ErrChatUnsupported
	}
	if maxSteps <= 0 {
		maxSteps = 12
	}
	return &Agent{chatter: c, tools: tb, store: st, maxSteps: maxSteps, retentionDays: retentionDays}, nil
}

func (a *Agent) Provider() string { return a.chatter.ChatProvider() }
func (a *Agent) Model() string    { return a.chatter.ChatModel() }
func (a *Agent) Tools() []string  { return a.tools.Names() }

func (a *Agent) systemPrompt() string {
	return fmt.Sprintf(`You are the CyNewsFeed analyst assistant, helping a security team research threats using their own news dataset.

The dataset contains cybersecurity stories (news, vendor research, government advisories, the CISA KEV catalog, podcasts) collected over the last %d days, each with an AI summary, severity, and tags: CVEs, threat actors, malware, vendors, products, topics and IOCs. You also see the team's alert rules and the alerts they produced.

How to work:
- Ground every factual claim in tool results. Search before answering; use entity_timeline to track something over time and get_story for detail. Run independent lookups in parallel.
- Cite stories inline as [[story:ID]] using ids returned by the tools, right after the claim they support. Never invent ids.
- If the dataset has nothing relevant, say so plainly. You may add general background knowledge, but label it as such and keep it separate from what the sources say.
- External lookups (lookup_cve, ioc_reputation) have small quotas: call them only for the specific CVEs or indicators the question is about.
- You are read-only: you cannot change rules, sources or data. If the user would benefit from an alert rule, suggest its wording.

Answer format:
- Markdown. Lead with the direct answer in 1-3 sentences, then supporting detail under short headings or bullets. Use tables for timelines or comparisons when helpful.
- Write indicators defanged (example[.]com, hxxps://, 1.2.3[.]4) so they are not clickable.
- Be concise and specific: dates, versions, counts, sources. Finish with concrete recommended actions when relevant.

Today is %s.`, a.retentionDays, time.Now().UTC().Format("Monday, 2 January 2006"))
}

// Reply runs one user turn: persists the user message, drives the tool loop
// (streaming events through emit) and persists the assistant message.
// It should be called with a context detached from the HTTP request so the
// answer completes and is saved even if the browser disconnects.
func (a *Agent) Reply(ctx context.Context, chat *model.Chat, userText, display string, cctx *model.ChatContext, emit func(Event)) (*model.ChatMessage, error) {
	if emit == nil {
		emit = func(Event) {}
	}
	history, err := a.store.ListChatMessages(ctx, chat.ID)
	if err != nil {
		return nil, err
	}

	// Resume from the provider-native transcript when the chat was produced by
	// the same provider and every turn has one; otherwise replay plain text.
	var native []json.RawMessage
	var plain []ai.PlainMsg
	useNative := chat.Provider == "" || chat.Provider == a.chatter.ChatProvider()
	for _, m := range history {
		if len(m.Native) == 0 {
			useNative = false
		}
	}
	for _, m := range history {
		if useNative {
			var entries []json.RawMessage
			if err := json.Unmarshal(m.Native, &entries); err != nil {
				useNative = false
				break
			}
			native = append(native, entries...)
		}
		if m.Text != "" {
			plain = append(plain, ai.PlainMsg{Role: m.Role, Text: m.Text})
		}
	}
	if !useNative {
		native = nil
	}
	sess, err := a.chatter.NewSession(a.systemPrompt(), a.tools.Defs(), native, plain)
	if err != nil {
		return nil, err
	}

	seq := len(history)
	sess.AddUser(userText)
	userMsg := &model.ChatMessage{Seq: seq, Role: "user", Text: display, Context: cctx, CreatedAt: time.Now().UTC()}
	userMsg.Native = marshalEntries(sess.Drain())
	if err := a.store.AppendChatMessage(ctx, chat.ID, userMsg); err != nil {
		return nil, err
	}

	asst := &model.ChatMessage{Seq: seq + 1, Role: "assistant", Model: a.chatter.ChatModel(), CreatedAt: time.Now().UTC()}
	var texts []string
	var runErr error
	var usage ai.Usage
	for step := 0; ; step++ {
		if step >= a.maxSteps {
			runErr = fmt.Errorf("stopped after %d tool rounds; ask a narrower question", a.maxSteps)
			break
		}
		res, err := sess.Step(ctx, func(d string) { emit(Event{Type: "text", Delta: d}) })
		if err != nil {
			runErr = err
			break
		}
		usage.Add(res.Usage)
		if res.Usage.Model != "" {
			asst.Model = res.Usage.Model
		}
		if t := strings.TrimSpace(res.Text); t != "" {
			texts = append(texts, t)
		}
		if len(res.ToolCalls) == 0 {
			break
		}
		emit(Event{Type: "text", Delta: "\n\n"})
		results := make([]ai.ToolResult, len(res.ToolCalls))
		type done struct {
			i    int
			step model.ToolStep
			res  ai.ToolResult
		}
		ch := make(chan done, len(res.ToolCalls))
		for i, tc := range res.ToolCalls {
			st := model.ToolStep{ID: tc.ID, Name: tc.Name, Input: compactJSON(tc.Input)}
			emit(Event{Type: "step_start", Step: &st})
			go func(i int, tc ai.ToolCall, st model.ToolStep) {
				out, summary, err := a.tools.Call(ctx, tc.Name, tc.Input)
				r := ai.ToolResult{CallID: tc.ID, Name: tc.Name, Content: out}
				if err != nil {
					r.Content, r.IsError = "Error: "+err.Error(), true
					st.IsError, st.Summary = true, err.Error()
				} else {
					st.Summary = summary
				}
				st.Result = truncate(r.Content, 4000)
				ch <- done{i, st, r}
			}(i, tc, st)
		}
		for range res.ToolCalls {
			d := <-ch
			results[d.i] = d.res
			asst.Steps = append(asst.Steps, d.step)
			emit(Event{Type: "step_end", Step: &d.step})
		}
		sess.AddToolResults(results)
	}

	asst.Text = strings.Join(texts, "\n\n")
	if usage.Input > 0 || usage.Output > 0 {
		asst.Usage = &model.TokenUsage{Model: asst.Model, Input: usage.Input, Output: usage.Output, Cached: usage.Cached, CostUSD: usage.Cost}
		_ = a.store.PutUsage(context.WithoutCancel(ctx), &model.UsageRecord{ID: "chat-" + store.InvTS(time.Now()), Kind: "chat", Ref: chat.ID,
			User: chat.UserName, At: time.Now().UTC(), TokenUsage: *asst.Usage})
	}
	asst.Native = marshalEntries(sess.Drain())
	if runErr != nil {
		asst.Error = runErr.Error()
		slog.Warn("agent turn failed", "chat", chat.ID, "err", runErr)
	}
	// Persist even on error so the transcript stays append-only and consistent.
	saveCtx := context.WithoutCancel(ctx)
	if err := a.store.AppendChatMessage(saveCtx, chat.ID, asst); err != nil {
		return nil, err
	}
	chat.Messages = asst.Seq + 1
	chat.UpdatedAt = time.Now().UTC()
	chat.Provider = a.chatter.ChatProvider()
	if err := a.store.PutChat(saveCtx, chat); err != nil {
		return nil, err
	}
	out := *asst
	out.Native = nil
	emit(Event{Type: "done", Message: &out})
	if runErr != nil && asst.Text == "" {
		return &out, runErr
	}
	return &out, nil
}

func marshalEntries(e []json.RawMessage) json.RawMessage {
	if len(e) == 0 {
		return nil
	}
	b, _ := json.Marshal(e)
	return b
}

func compactJSON(b json.RawMessage) string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

// ---------------- standard prompts ----------------

// DefaultPrompts are the one-click "Ask about this" templates per entity type.
// Placeholders: {{type}}, {{value}}, {{story}}, {{reason}}.
var DefaultPrompts = map[string]string{
	"default": `Give me an analyst brief on the {{type}} "{{value}}":
1. What it is, in two sentences.
2. Every mention across our sources: a dated timeline with citations.
3. Related CVEs, threat actors, malware, products and IOCs that co-occur with it.
4. Exploitation status and who is affected.
5. Recommended actions for our defenders.`,
	"cve": `Give me an analyst brief on {{value}}:
1. What the vulnerability is: affected products/versions, CVSS and weakness (look it up in NVD and CISA KEV).
2. Exploitation status: is it in KEV, exploited in the wild, public PoC, ransomware use?
3. Every mention across our sources: a dated timeline with citations.
4. Related threat actors, malware and IOCs.
5. Patch/mitigation guidance and the deadline we should hold ourselves to.`,
	"actor": `Give me an analyst brief on the threat actor "{{value}}":
1. Who they are (aliases, suspected origin, motivation), labelled as background knowledge where not from our sources.
2. Their activity in our sources: a dated timeline with citations.
3. Targets (sectors, regions), CVEs exploited, malware/tools and IOCs observed.
4. What we should hunt for and how to reduce exposure.`,
	"malware": `Give me an analyst brief on the malware/tool "{{value}}":
1. What it is and what it does.
2. Its appearances in our sources: a dated timeline with citations.
3. Associated threat actors, delivery vectors, exploited CVEs and IOCs.
4. Detection and hunting ideas plus mitigations.`,
	"ioc": `Investigate the {{type}} indicator "{{value}}":
1. Every story in our dataset that mentions it, with context and citations.
2. Its reputation (check the configured reputation sources once).
3. Related infrastructure, malware, threat actors and campaigns.
4. Verdict (malicious / suspicious / benign / unknown), confidence, and recommended actions (block, hunt, ignore).`,
	"vendor": `Give me a brief on recent security news about {{value}}:
1. Vulnerabilities, incidents and advisories in our sources over the last 30 days: a dated timeline with citations.
2. Which issues are exploited or critical.
3. What customers of {{value}} should do now.`,
	"detail": `Follow up on this detail from the story "{{story}}": "{{value}}" (flagged because: {{reason}}).
Verify it against our other sources, explain what it means for defenders, and list concrete next steps. Cite stories.`,
}

// PromptKind maps an entity type to its template key.
func PromptKind(entityType string) string {
	switch entityType {
	case "cve":
		return "cve"
	case "actor":
		return "actor"
	case "malware":
		return "malware"
	case "vendor", "product":
		return "vendor"
	case "ip", "domain", "url", "md5", "sha1", "sha256", "email", "ioc":
		return "ioc"
	case "detail":
		return "detail"
	}
	return "default"
}

// Prompts returns the effective templates (stored overrides on top of defaults).
func Prompts(ctx context.Context, st store.Store) map[string]string {
	out := map[string]string{}
	for k, v := range DefaultPrompts {
		out[k] = v
	}
	if raw, err := st.GetSetting(ctx, "prompts"); err == nil {
		var over map[string]string
		if json.Unmarshal([]byte(raw), &over) == nil {
			for k, v := range over {
				if _, known := DefaultPrompts[k]; known && strings.TrimSpace(v) != "" {
					out[k] = v
				}
			}
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		slog.Warn("load prompt settings", "err", err)
	}
	return out
}

var typeLabels = map[string]string{"cve": "vulnerability", "actor": "threat actor", "malware": "malware", "vendor": "vendor",
	"product": "product", "topic": "topic", "ip": "IP address", "domain": "domain", "url": "URL", "md5": "MD5 hash",
	"sha1": "SHA-1 hash", "sha256": "SHA-256 hash", "email": "email address", "detail": "detail",
	"attack": "MITRE ATT&CK technique", "atlas": "MITRE ATLAS technique", "owasp": "OWASP LLM Top 10 category"}

// RenderPrompt fills a template for a highlight click.
func RenderPrompt(tpl string, c model.ChatContext, reason string) string {
	label := typeLabels[c.EntityType]
	if label == "" {
		label = "entity"
	}
	r := strings.NewReplacer("{{type}}", label, "{{value}}", c.EntityValue, "{{story}}", c.ItemTitle, "{{reason}}", reason)
	return r.Replace(tpl)
}
