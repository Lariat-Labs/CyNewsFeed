import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BellRing, CheckCircle2, ChevronRight, CircleAlert, Loader2 } from "lucide-react";
import { api, type Run } from "../api";
import { Empty, ErrorBox, PageHeader, Segmented, SeverityBadge, Spinner } from "../components/ui";
import { cn, fmtDateTime, fmtDuration, fmtNum, fmtUSD, timeAgo } from "../util";

export default function Activity() {
  const [tab, setTab] = useState<"alerts" | "runs">("alerts");
  return (
    <div className="mx-auto max-w-6xl p-4 md:p-6">
      <PageHeader
        title="Activity"
        subtitle="Alerts sent and aggregation history"
        actions={
          <Segmented
            value={tab}
            onChange={setTab}
            options={[
              { value: "alerts", label: "Alerts" },
              { value: "runs", label: "Runs" },
            ]}
          />
        }
      />
      {tab === "alerts" ? <Alerts /> : <Runs />}
    </div>
  );
}

function Alerts() {
  const alerts = useQuery({ queryKey: ["alerts", 30], queryFn: () => api.alerts(30) });
  if (alerts.isLoading) return <Spinner />;
  if (alerts.error) return <ErrorBox error={alerts.error} />;
  if (!alerts.data?.length)
    return (
      <div className="card">
        <Empty icon={<BellRing className="size-8" />} title="No alerts in the last 30 days">
          <Link to="/rules" className="text-accent">
            Create an alert rule
          </Link>{" "}
          to be notified about the topics you care about.
        </Empty>
      </div>
    );
  return (
    <div className="card divide-y divide-line">
      {alerts.data.map((a) => (
        <div key={a.id} className="flex items-start gap-3 px-4 py-3">
          <BellRing className="mt-0.5 size-4 shrink-0 text-accent" />
          <div className="min-w-0 flex-1">
            <Link to={`/?item=${a.itemId}`} className="font-medium leading-snug hover:text-accent">
              {a.title}
            </Link>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
              <span className="font-medium text-ink-2">{a.ruleName}</span>
              <span>relevance {a.score}</span>
              <SeverityBadge severity={a.severity} compact />
              <span>{a.feedName}</span>
              <span>{timeAgo(a.createdAt)}</span>
              {a.notified ? (
                <span className="text-ok">sent to Slack</span>
              ) : a.notifyError ? (
                <span className="text-danger" title={a.notifyError}>
                  Slack failed
                </span>
              ) : (
                <span>not sent (Slack not configured)</span>
              )}
            </div>
            {a.reason && <p className="mt-1 text-xs text-ink-2">{a.reason}</p>}
          </div>
        </div>
      ))}
    </div>
  );
}

function Runs() {
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const [open, setOpen] = useState<string | null>(null);
  if (runs.isLoading) return <Spinner />;
  if (runs.error) return <ErrorBox error={runs.error} />;
  if (!runs.data?.runs.length) return <div className="card p-6 text-sm text-muted">No runs yet. Use “Refresh now” in the sidebar.</div>;
  return (
    <div className="card overflow-x-auto">
      <table className="w-full min-w-[760px] text-sm">
        <thead className="border-b border-line text-left text-xs text-muted">
          <tr>
            <th className="w-6 px-3 py-2.5" />
            <th className="px-2 py-2.5 font-medium">Started</th>
            <th className="px-2 py-2.5 font-medium">Type</th>
            <th className="px-2 py-2.5 font-medium">Status</th>
            <th className="px-2 py-2.5 text-right font-medium">New</th>
            <th className="px-2 py-2.5 text-right font-medium">Alerts</th>
            <th className="px-2 py-2.5 text-right font-medium">Errors</th>
            <th className="px-2 py-2.5 text-right font-medium">Tokens in/out</th>
            <th className="px-3 py-2.5 text-right font-medium">Duration</th>
          </tr>
        </thead>
        <tbody>
          {runs.data.runs.map((r) => (
            <Fragment key={r.id}>
              <tr className="cursor-pointer border-b border-line hover:bg-hover/50" onClick={() => setOpen(open === r.id ? null : r.id)}>
                <td className="px-3 py-2.5 text-muted">
                  <ChevronRight className={cn("size-4 transition", open === r.id && "rotate-90")} />
                </td>
                <td className="px-2 py-2.5 text-ink-2" title={fmtDateTime(r.started)}>
                  {timeAgo(r.started)}
                </td>
                <td className="px-2 py-2.5 capitalize">
                  {r.kind} <span className="text-xs text-muted">· {r.trigger}</span>
                </td>
                <td className="px-2 py-2.5">
                  <RunStatus run={r} />
                </td>
                <td className="px-2 py-2.5 text-right tabular-nums">{r.stats.newItems}</td>
                <td className="px-2 py-2.5 text-right tabular-nums">{r.stats.alerts}</td>
                <td className="px-2 py-2.5 text-right tabular-nums">{r.stats.feedErrors + r.stats.aiErrors || ""}</td>
                <td className="px-2 py-2.5 text-right tabular-nums text-ink-2">
                  {r.stats.inputTokens ? `${fmtNum(r.stats.inputTokens)} / ${fmtNum(r.stats.outputTokens)} · ${fmtUSD(r.stats.costUsd)}` : "—"}
                </td>
                <td className="px-3 py-2.5 text-right tabular-nums text-ink-2">{fmtDuration(r.started, r.finished)}</td>
              </tr>
              {open === r.id && (
                <tr className="border-b border-line bg-panel-2/50">
                  <td colSpan={9} className="px-6 py-3">
                    <RunDetail run={r} />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RunStatus({ run }: { run: Run }) {
  if (run.status === "running")
    return (
      <span className="inline-flex items-center gap-1 text-xs text-accent">
        <Loader2 className="size-3.5 animate-spin" /> running
      </span>
    );
  if (run.status === "error")
    return (
      <span className="inline-flex items-center gap-1 text-xs text-danger" title={run.error}>
        <CircleAlert className="size-3.5" /> error
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1 text-xs text-ok">
      <CheckCircle2 className="size-3.5" /> ok
    </span>
  );
}

function RunDetail({ run }: { run: Run }) {
  const s = run.stats;
  const failing = s.perFeed?.filter((f) => f.status === "error") ?? [];
  const productive = (s.perFeed ?? []).filter((f) => f.new > 0).sort((a, b) => b.new - a.new);
  return (
    <div className="space-y-2 text-xs text-ink-2">
      {run.error && <p className="text-danger">{run.error}</p>}
      <p>
        {s.feeds} feeds · {s.newItems} new · {s.enriched} summarised · {s.retried} retried · {s.aiErrors} AI errors · {s.purged} purged
        {s.cachedTokens > 0 && ` · ${fmtNum(s.cachedTokens)} cached input tokens`}
      </p>
      {productive.length > 0 && <p>New items: {productive.map((f) => `${f.feedId} (${f.new})`).join(", ")}</p>}
      {failing.length > 0 && (
        <div>
          <p className="font-medium text-danger">Failing feeds</p>
          <ul className="mt-1 space-y-0.5">
            {failing.map((f) => (
              <li key={f.feedId}>
                <span className="font-mono">{f.feedId}</span>: {f.error}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
