import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellRing, FlaskConical, Pencil, Plus, Trash2 } from "lucide-react";
import { api, SEVERITIES, type Rule, type RuleMode, type TestResult } from "../api";
import { Chip, Empty, ErrorBox, Modal, PageHeader, Segmented, SeverityBadge, Spinner, Toggle } from "../components/ui";
import { cn, timeAgo } from "../util";

const MODE_HELP: Record<RuleMode, string> = {
  hybrid: "Alert on a keyword/regex match OR when the AI judges the story relevant to your description (score ≥ threshold). Recommended.",
  semantic: "Alert only when the AI judges the story relevant to your description. Catches related stories that don't use your exact words.",
  keyword: "Alert only on exact keyword/regex matches. Deterministic, works without AI.",
};

const EXAMPLES: Partial<Rule>[] = [
  {
    name: "Our edge stack",
    description: "Vulnerabilities, exploitation or advisories affecting Fortinet FortiGate, Palo Alto GlobalProtect, or Citrix NetScaler appliances.",
    keywords: ["FortiGate", "FortiOS", "GlobalProtect", "PAN-OS", "NetScaler", "Citrix ADC"],
    mode: "hybrid",
  },
  {
    name: "Identity provider compromise",
    description: "Breaches, session hijacking or attacks against identity providers and SSO such as Okta, Entra ID / Azure AD, or Ping.",
    keywords: ["Okta", "Entra ID", "Azure AD"],
    mode: "hybrid",
  },
  {
    name: "Healthcare ransomware",
    description: "Ransomware attacks or data extortion targeting hospitals, healthcare providers or health insurers.",
    keywords: [],
    mode: "semantic",
  },
];

const blank: Rule = { id: "", name: "", description: "", keywords: [], regexes: [], mode: "hybrid", threshold: 70, minSeverity: "", slackWebhook: "", enabled: true };

export default function Rules() {
  const qc = useQueryClient();
  const rules = useQuery({ queryKey: ["rules"], queryFn: api.rules });
  const cfg = useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: Infinity });
  const [editing, setEditing] = useState<Rule | null>(null);

  const toggle = useMutation({
    mutationFn: (r: Rule) => api.updateRule({ ...r, enabled: !r.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });
  const del = useMutation({
    mutationFn: (id: string) => api.deleteRule(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  return (
    <div className="mx-auto max-w-5xl p-4 md:p-6">
      <PageHeader
        title="Alert rules"
        subtitle="Get notified in Slack when stories mention — or are related to — what you care about."
        actions={
          <button className="btn-primary" onClick={() => setEditing({ ...blank, threshold: cfg.data?.defaultThreshold ?? 70 })}>
            <Plus className="size-4" /> New rule
          </button>
        }
      />
      {cfg.data?.aiProvider === "none" && (
        <div className="mb-4 rounded-md border border-line bg-panel-2 px-3 py-2 text-sm text-ink-2">
          AI is disabled, so semantic and hybrid rules fall back to keyword matching. Set <code className="font-mono text-xs">AI_PROVIDER</code> to enable relevance scoring.
        </div>
      )}
      <ErrorBox error={rules.error || toggle.error || del.error} />
      {rules.isLoading ? (
        <div className="flex justify-center p-10">
          <Spinner />
        </div>
      ) : !rules.data?.length ? (
        <div className="card">
          <Empty icon={<BellRing className="size-8" />} title="No alert rules yet">
            <p>Describe what you want to hear about in plain English, add optional keywords, and CyNewsFeed will score every new story against it.</p>
            <div className="mt-4 flex flex-wrap justify-center gap-2">
              {EXAMPLES.map((e) => (
                <button key={e.name} className="btn-ghost text-xs" onClick={() => setEditing({ ...blank, ...e } as Rule)}>
                  Start from “{e.name}”
                </button>
              ))}
            </div>
          </Empty>
        </div>
      ) : (
        <div className="grid gap-3">
          {rules.data.map((r) => (
            <div key={r.id} className={cn("card p-4", !r.enabled && "opacity-60")}>
              <div className="flex items-start gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="font-semibold">{r.name}</h3>
                    <span className="rounded bg-panel-2 px-1.5 py-0.5 text-[11px] font-medium capitalize text-ink-2">{r.mode}</span>
                    {r.mode !== "keyword" && <span className="text-xs text-muted">threshold {r.threshold}</span>}
                    {r.minSeverity && (
                      <span className="inline-flex items-center gap-1 text-xs text-muted">
                        min <SeverityBadge severity={r.minSeverity} compact />
                      </span>
                    )}
                    {r.slackWebhook && <span className="text-xs text-muted">custom Slack channel</span>}
                  </div>
                  {r.description && <p className="mt-1 text-sm text-ink-2">{r.description}</p>}
                  {(r.keywords.length > 0 || r.regexes.length > 0) && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {r.keywords.map((k) => (
                        <Chip key={k}>{k}</Chip>
                      ))}
                      {r.regexes.map((k) => (
                        <Chip key={k} kind="cve">
                          /{k}/
                        </Chip>
                      ))}
                    </div>
                  )}
                  <div className="mt-2 text-xs text-muted">
                    <Link className="hover:text-accent" to={`/?rule=${r.id}&days=30`}>
                      View matches →
                    </Link>
                    {r.updatedAt && <span className="ml-3">updated {timeAgo(r.updatedAt)}</span>}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <Toggle checked={r.enabled} onChange={() => toggle.mutate(r)} label={r.enabled ? "Disable rule" : "Enable rule"} />
                  <button className="ml-2 rounded p-1.5 text-muted hover:bg-hover hover:text-ink" onClick={() => setEditing(r)} aria-label="Edit rule">
                    <Pencil className="size-4" />
                  </button>
                  <button
                    className="rounded p-1.5 text-muted hover:bg-hover hover:text-danger"
                    onClick={() => confirm(`Delete rule “${r.name}”?`) && del.mutate(r.id)}
                    aria-label="Delete rule"
                  >
                    <Trash2 className="size-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      {editing && <RuleEditor rule={editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

const splitList = (s: string) =>
  s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);

function RuleEditor({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const qc = useQueryClient();
  const [r, setR] = useState<Rule>(rule);
  const [kw, setKw] = useState(rule.keywords.join(", "));
  const [rx, setRx] = useState(rule.regexes.join("\n"));
  const [testDays, setTestDays] = useState(7);
  const [results, setResults] = useState<TestResult[] | null>(null);
  const draft = (): Rule => ({ ...r, keywords: splitList(kw), regexes: rx.split("\n").map((x) => x.trim()).filter(Boolean) });

  const save = useMutation({
    mutationFn: () => (r.id ? api.updateRule(draft()) : api.createRule(draft())),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      onClose();
    },
  });
  const test = useMutation({
    mutationFn: () => api.testRule({ ...draft(), days: testDays }),
    onSuccess: (d) => setResults(d.results),
  });
  const alerting = results?.filter((x) => x.wouldAlert).length ?? 0;

  return (
    <Modal open onClose={onClose} title={r.id ? `Edit “${rule.name}”` : "New alert rule"} wide>
      <form
        className="grid gap-5 md:grid-cols-[1fr_1fr]"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <div className="space-y-4">
          <div>
            <label className="label" htmlFor="rname">Name</label>
            <input id="rname" className="input" value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} placeholder="e.g. Our VPN appliances" required />
          </div>
          <div>
            <label className="label" htmlFor="rdesc">What should trigger this? (plain English)</label>
            <textarea
              id="rdesc"
              className="input min-h-24"
              value={r.description}
              onChange={(e) => setR({ ...r, description: e.target.value })}
              placeholder="e.g. Vulnerabilities or active exploitation affecting Ivanti Connect Secure or Pulse Secure VPNs"
            />
            <p className="mt-1 text-xs text-muted">The AI scores every new story against this description (0–100).</p>
          </div>
          <div>
            <label className="label" htmlFor="rkw">Keywords (comma or newline separated)</label>
            <textarea id="rkw" className="input min-h-16" value={kw} onChange={(e) => setKw(e.target.value)} placeholder="Ivanti, Connect Secure, Pulse Secure" />
          </div>
          <div>
            <label className="label" htmlFor="rrx">Regex patterns (one per line, optional)</label>
            <textarea id="rrx" className="input min-h-12 font-mono text-xs" value={rx} onChange={(e) => setRx(e.target.value)} placeholder={"CVE-2026-\\d+"} />
          </div>
        </div>

        <div className="space-y-4">
          <div>
            <span className="label">Match mode</span>
            <Segmented
              value={r.mode}
              onChange={(m) => setR({ ...r, mode: m })}
              options={[
                { value: "hybrid", label: "Hybrid" },
                { value: "semantic", label: "Semantic" },
                { value: "keyword", label: "Keyword" },
              ]}
            />
            <p className="mt-1.5 text-xs text-muted">{MODE_HELP[r.mode]}</p>
          </div>
          {r.mode !== "keyword" && (
            <div>
              <label className="label" htmlFor="rth">
                Relevance threshold: <span className="tabular-nums text-ink">{r.threshold}</span>
              </label>
              <input id="rth" type="range" min={40} max={95} step={5} value={r.threshold} onChange={(e) => setR({ ...r, threshold: Number(e.target.value) })} className="w-full accent-[var(--accent)]" />
              <div className="flex justify-between text-[11px] text-muted">
                <span>broader</span>
                <span>stricter</span>
              </div>
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label" htmlFor="rsev">Minimum severity</label>
              <select id="rsev" className="input" value={r.minSeverity ?? ""} onChange={(e) => setR({ ...r, minSeverity: e.target.value as Rule["minSeverity"] })}>
                <option value="">Any</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-end gap-2 pb-2">
              <Toggle checked={r.enabled} onChange={(v) => setR({ ...r, enabled: v })} label="Enabled" />
              <span className="text-sm text-ink-2">Enabled</span>
            </div>
          </div>
          <div>
            <label className="label" htmlFor="rhook">Slack webhook override (optional)</label>
            <input
              id="rhook"
              className="input font-mono text-xs"
              value={r.slackWebhook ?? ""}
              onChange={(e) => setR({ ...r, slackWebhook: e.target.value })}
              placeholder="https://hooks.slack.com/services/… (defaults to the global webhook)"
            />
          </div>

          <div className="rounded-lg border border-line bg-panel-2 p-3">
            <div className="flex items-center gap-2">
              <FlaskConical className="size-4 text-muted" />
              <span className="text-sm font-medium">Back-test</span>
              <select className="input ml-auto w-auto py-1 text-xs" value={testDays} onChange={(e) => setTestDays(Number(e.target.value))} aria-label="Back-test window">
                <option value={3}>last 3 days</option>
                <option value={7}>last 7 days</option>
                <option value={14}>last 14 days</option>
                <option value={30}>last 30 days</option>
              </select>
              <button type="button" className="btn-ghost py-1 text-xs" disabled={test.isPending || !r.name} onClick={() => test.mutate()}>
                {test.isPending ? <Spinner className="size-3" /> : "Run"}
              </button>
            </div>
            <ErrorBox error={test.error} />
            {results && (
              <div className="mt-2">
                <p className="mb-1.5 text-xs text-muted">
                  Would have alerted on <span className="font-medium text-ink">{alerting}</span> stor{alerting === 1 ? "y" : "ies"}
                  {results.length > alerting && ` · ${results.length - alerting} near misses`}
                </p>
                <ul className="scroll-thin max-h-56 space-y-1.5 overflow-y-auto pr-1">
                  {results.slice(0, 40).map((x) => (
                    <li key={x.item.id} className="flex items-start gap-2 text-xs">
                      <span className={cn("mt-0.5 w-8 shrink-0 rounded px-1 text-center font-medium tabular-nums", x.wouldAlert ? "bg-accent/15 text-accent" : "bg-panel text-muted")}>{x.score}</span>
                      <span className="min-w-0">
                        <a href={x.item.link} target="_blank" rel="noreferrer" className="line-clamp-1 text-ink hover:text-accent">
                          {x.item.title}
                        </a>
                        <span className="line-clamp-1 text-muted">{x.reason || (x.keywords?.length ? `keywords: ${x.keywords.join(", ")}` : x.item.feedName)}</span>
                      </span>
                    </li>
                  ))}
                  {results.length === 0 && <li className="text-xs text-muted">No matching stories in this window.</li>}
                </ul>
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-line pt-4 md:col-span-2">
          <div className="mr-auto">
            <ErrorBox error={save.error} />
          </div>
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={save.isPending}>
            {save.isPending ? "Saving…" : r.id ? "Save rule" : "Create rule"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
