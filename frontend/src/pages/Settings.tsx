import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RotateCcw } from "lucide-react";
import { api, chatApi, intelApi } from "../api";
import { ErrorBox, PageHeader, Spinner, Toggle } from "../components/ui";
import { fmtNum, fmtUSD, timeAgo } from "../util";

const PROMPT_INFO: Record<string, string> = {
  default: "Any other entity (topics, unknown types)",
  cve: "Vulnerabilities (CVE IDs)",
  actor: "Threat actors",
  malware: "Malware & tools",
  ioc: "Indicators: IPs, domains, URLs, hashes, emails",
  vendor: "Vendors & products",
  detail: "AI-flagged key details in summaries",
};
const ORDER = ["cve", "actor", "malware", "ioc", "vendor", "detail", "default"];

export default function Settings() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["agent"], queryFn: chatApi.status });
  const cfg = useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: Infinity });
  const prompts = useQuery({ queryKey: ["prompts"], queryFn: chatApi.prompts });
  const [draft, setDraft] = useState<Record<string, string>>({});
  useEffect(() => {
    if (prompts.data) setDraft(prompts.data.prompts);
  }, [prompts.data]);
  const save = useMutation({
    mutationFn: () => chatApi.savePrompts(draft),
    onSuccess: (d) => qc.setQueryData(["prompts"], d),
  });
  const dirty = prompts.data && ORDER.some((k) => draft[k] !== prompts.data.prompts[k]);

  return (
    <div className="mx-auto max-w-4xl p-4 md:p-6">
      <PageHeader title="Settings" subtitle="AI usage, the research agent, and the one-click prompts used when you click a highlight" />

      <AIUsage />

      <Integrations />

      <section className="card mb-6 p-4 text-sm">
        <h2 className="mb-2 font-semibold">Agent</h2>
        {status.data?.enabled ? (
          <dl className="grid grid-cols-[140px_1fr] gap-y-1 text-ink-2">
            <dt className="text-muted">Provider / model</dt>
            <dd>
              {status.data.provider} · {status.data.model}
            </dd>
            <dt className="text-muted">Tools</dt>
            <dd className="font-mono text-xs">{status.data.tools?.join(", ")}</dd>
            <dt className="text-muted">Summaries</dt>
            <dd>
              {cfg.data?.aiProvider} · {cfg.data?.aiModel}
            </dd>
          </dl>
        ) : (
          <p className="text-muted">{status.data?.reason ?? "Loading…"}</p>
        )}
        <p className="mt-3 text-xs text-muted">
          IOC reputation appears when <code className="font-mono">VIRUSTOTAL_API_KEY</code> or <code className="font-mono">ABUSEIPDB_API_KEY</code> is set. The same tools are
          available from the terminal: <code className="font-mono">cynews query --list</code> and <code className="font-mono">cynews ask "…"</code>.
        </p>
      </section>

      <section>
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h2 className="font-semibold">“Ask about this” prompts</h2>
            <p className="text-xs text-muted">
              Placeholders: <code className="font-mono">{"{{value}}"}</code> the clicked text, <code className="font-mono">{"{{type}}"}</code> its type,{" "}
              <code className="font-mono">{"{{story}}"}</code> the story title, <code className="font-mono">{"{{reason}}"}</code> why a detail was flagged.
            </p>
          </div>
          <button className="btn-primary" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save prompts"}
          </button>
        </div>
        <ErrorBox error={prompts.error || save.error} />
        {!prompts.data ? (
          <Spinner />
        ) : (
          <div className="space-y-4">
            {ORDER.map((k) => (
              <div key={k} className="card p-4">
                <div className="mb-2 flex items-center justify-between">
                  <label className="text-sm font-medium" htmlFor={`p-${k}`}>
                    {PROMPT_INFO[k]}
                  </label>
                  {draft[k] !== prompts.data.defaults[k] && (
                    <button className="inline-flex items-center gap-1 text-xs text-muted hover:text-ink" onClick={() => setDraft({ ...draft, [k]: prompts.data.defaults[k] })}>
                      <RotateCcw className="size-3" /> Reset to default
                    </button>
                  )}
                </div>
                <textarea id={`p-${k}`} className="input min-h-32 font-mono text-xs leading-relaxed" value={draft[k] ?? ""} onChange={(e) => setDraft({ ...draft, [k]: e.target.value })} />
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

const KIND_LABEL: Record<string, string> = { aggregate: "Scheduled summaries", summarize: "On-demand summaries", digest: "Digests", chat: "Agent chats" };

function AIUsage() {
  const qc = useQueryClient();
  const settings = useQuery({ queryKey: ["ai-settings"], queryFn: api.aiSettings });
  const usage = useQuery({ queryKey: ["usage", 30], queryFn: () => api.usage(30) });
  const save = useMutation({
    mutationFn: api.saveAISettings,
    onSuccess: (d) => qc.setQueryData(["ai-settings"], d),
  });
  const s = settings.data;
  const set = (patch: Partial<{ autoSummarize: boolean; scheduledDigestAI: boolean }>) =>
    s && save.mutate({ autoSummarize: s.autoSummarize, scheduledDigestAI: s.scheduledDigestAI, ...patch });
  const u = usage.data;

  return (
    <section className="card mb-6 p-4 text-sm">
      <h2 className="font-semibold">AI usage</h2>
      <p className="mt-0.5 text-xs text-muted">
        By default nothing calls the AI on a schedule. New stories get a free excerpt, regex-extracted CVEs and IOCs, and keyword rule matching. Use
        <span className="text-ink-2"> Summarise with AI</span> on any story, or ask the agent, when you want AI.
      </p>
      <ErrorBox error={settings.error || save.error} />
      {s && (
        <div className="mt-4 space-y-3">
          <label className="flex items-start gap-3">
            <Toggle checked={s.autoSummarize} onChange={(v) => set({ autoSummarize: v })} label="Auto-summarise new stories" />
            <span>
              <span className="font-medium text-ink">Auto-summarise every new story on each scheduled run</span>
              <span className="block text-xs text-muted">
                Uses {s.summaryModel}. Also enables semantic (AI-scored) alert rules on ingest. With default feeds that's roughly 300–800 stories a day.
              </span>
            </span>
          </label>
          <label className="flex items-start gap-3">
            <Toggle checked={s.scheduledDigestAI} onChange={(v) => set({ scheduledDigestAI: v })} label="AI-written scheduled digest" />
            <span>
              <span className="font-medium text-ink">AI-written scheduled daily digest</span>
              <span className="block text-xs text-muted">
                One call a day with {s.digestModel}. When off, the scheduled digest is a ranked headline list. “Generate now” on the Digests page always uses AI.
              </span>
            </span>
          </label>
        </div>
      )}

      <div className="mt-5 border-t border-line pt-4">
        <div className="mb-2 flex items-baseline justify-between">
          <h3 className="font-medium">Estimated spend</h3>
          <span className="text-xs text-muted">list prices; check your provider bill for exact figures</span>
        </div>
        {!u ? (
          <Spinner />
        ) : (
          <>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div>
                <div className="text-xs text-muted">Today</div>
                <div className="text-lg font-semibold tabular-nums">{fmtUSD(u.today.costUsd)}</div>
              </div>
              <div>
                <div className="text-xs text-muted">Last 30 days</div>
                <div className="text-lg font-semibold tabular-nums">{fmtUSD(u.total.costUsd)}</div>
              </div>
              {Object.entries(u.byKind).map(([k, v]) => (
                <div key={k}>
                  <div className="text-xs text-muted">{KIND_LABEL[k] ?? k}</div>
                  <div className="tabular-nums">
                    {fmtUSD(v.costUsd)} <span className="text-xs text-muted">· {v.calls} runs</span>
                  </div>
                </div>
              ))}
            </div>
            {u.recent.length > 0 && (
              <table className="mt-4 w-full text-xs tabular-nums">
                <thead className="text-left text-muted">
                  <tr>
                    <th className="py-1 font-medium">When</th>
                    <th className="py-1 font-medium">What</th>
                    <th className="py-1 font-medium">Model</th>
                    <th className="py-1 text-right font-medium">Tokens in / out</th>
                    <th className="py-1 text-right font-medium">Cost</th>
                  </tr>
                </thead>
                <tbody>
                  {u.recent.slice(0, 12).map((r) => (
                    <tr key={r.id} className="border-t border-line text-ink-2">
                      <td className="py-1">{timeAgo(r.at)}</td>
                      <td className="py-1">
                        {KIND_LABEL[r.kind] ?? r.kind}
                        {r.items ? ` (${r.items})` : ""}
                      </td>
                      <td className="py-1">{r.model}</td>
                      <td className="py-1 text-right">
                        {fmtNum(r.input)} / {fmtNum(r.output)}
                      </td>
                      <td className="py-1 text-right">{fmtUSD(r.costUsd)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {u.recent.length === 0 && <p className="mt-2 text-xs text-muted">No AI usage recorded yet. Spend from before this version isn't included.</p>}
          </>
        )}
      </div>
    </section>
  );
}

function Snippet({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="group relative mt-1">
      <pre className="scroll-thin overflow-x-auto rounded-md border border-line bg-bg px-3 py-2 font-mono text-[11px] leading-relaxed text-ink-2">{children}</pre>
      <button
        className="absolute right-1.5 top-1.5 rounded bg-panel px-1.5 py-0.5 text-[10px] text-muted opacity-0 transition group-hover:opacity-100 hover:text-ink"
        onClick={() => navigator.clipboard?.writeText(children).then(() => setCopied(true))}
      >
        {copied ? "copied" : "copy"}
      </button>
    </div>
  );
}

function Status({ on, label }: { on: boolean; label: string }) {
  return (
    <span className={on ? "rounded bg-ok/15 px-1.5 py-0.5 text-[11px] font-medium text-ok" : "rounded bg-panel-2 px-1.5 py-0.5 text-[11px] text-muted"}>{label}</span>
  );
}

function Integrations() {
  const q = useQuery({ queryKey: ["integrations"], queryFn: intelApi.integrations });
  const d = q.data;
  if (!d) return <Spinner />;
  return (
    <section className="card mb-6 p-4 text-sm">
      <h2 className="font-semibold">Integrations</h2>
      <p className="mt-0.5 text-xs text-muted">Share intel with your SIEM/TIP and let other agents query this dataset. All endpoints are read-only.</p>

      <div className="mt-4 space-y-5">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="font-medium">TAXII 2.1 feed</h3>
            <Status on={d.taxii.enabled} label={d.taxii.enabled ? `enabled · auth: ${d.taxii.auth}` : "disabled: set TAXII_TOKEN"} />
          </div>
          <p className="mt-1 text-xs text-muted">
            Pull IOCs as STIX 2.1 into Microsoft Sentinel (Threat Intelligence – TAXII connector), OpenCTI, MISP or Splunk. Use the API root and a collection ID;
            authenticate with the token as the password (any username) or as a Bearer token.
          </p>
          <Snippet>{`API root:    ${d.taxii.apiRoot}\n${d.taxii.collections.map((c) => `Collection:  ${c.id}  (${c.title})`).join("\n")}`}</Snippet>
          <Snippet>{`curl -u taxii:$TAXII_TOKEN -H "Accept: application/taxii+json;version=2.1" \\\n  "${d.taxii.collections[0]?.objectsUrl}?limit=50"`}</Snippet>
        </div>

        <div>
          <div className="flex items-center gap-2">
            <h3 className="font-medium">MCP server</h3>
            <Status on={d.mcp.enabled} label={d.mcp.enabled ? `enabled · auth: ${d.mcp.auth}` : "disabled: set MCP_TOKEN"} />
          </div>
          <p className="mt-1 text-xs text-muted">
            Give Claude Code, Claude Desktop, Cursor or your own agents the same read-only research tools the built-in agent uses (search, timelines, events, trends,
            IOCs, framework coverage, CVE lookups).
          </p>
          <Snippet>{`# Remote (Streamable HTTP)\nclaude mcp add --transport http cynewsfeed ${d.mcp.url} \\\n  --header "Authorization: Bearer $MCP_TOKEN"`}</Snippet>
          <Snippet>{`# Local (stdio), using the same storage settings as the app\nclaude mcp add cynewsfeed -- /path/to/cynews mcp`}</Snippet>
        </div>

        <div>
          <div className="flex items-center gap-2">
            <h3 className="font-medium">MISP push</h3>
            <Status on={d.misp.configured} label={d.misp.configured ? `configured · ${d.misp.url}` : "not configured: set MISP_URL and MISP_KEY"} />
          </div>
          <p className="mt-1 text-xs text-muted">Creates a MISP event (TLP:AMBER, distribution: your organisation only) from the indicators on the IOCs page.</p>
        </div>
      </div>
    </section>
  );
}
