import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BellRing, Table2, BarChart3 } from "lucide-react";
import { api, intelApi, SEVERITIES, type Severity, type Stats } from "../api";
import { Heatmap, TrendList } from "../components/Viz";
import { ErrorBox, PageHeader, Segmented, Spinner, Stat } from "../components/ui";
import { cn, sevVar, timeAgo } from "../util";

export default function Dashboard() {
  const [days, setDays] = useState(7);
  const stats = useQuery({ queryKey: ["stats", days], queryFn: () => api.stats(days) });
  const alerts = useQuery({ queryKey: ["alerts", days], queryFn: () => api.alerts(days) });
  const s = stats.data;
  const urgent = (s?.bySeverity.critical ?? 0) + (s?.bySeverity.high ?? 0);

  return (
    <div className="mx-auto max-w-6xl p-4 md:p-6">
      <PageHeader
        title="Dashboard"
        subtitle="What the threat landscape looked like across your sources"
        actions={
          <Segmented
            value={days}
            onChange={setDays}
            options={[
              { value: 1, label: "24h" },
              { value: 7, label: "7d" },
              { value: 30, label: "30d" },
              { value: 90, label: "90d" },
            ]}
          />
        }
      />
      <ErrorBox error={stats.error} />
      {!s ? (
        <div className="flex justify-center p-10">
          <Spinner />
        </div>
      ) : (
        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Stories" value={s.total.toLocaleString()} hint={`last ${days === 1 ? "24 hours" : `${days} days`}`} />
            <Stat label="Critical + high" value={urgent.toLocaleString()} hint={s.total ? `${Math.round((urgent / s.total) * 100)}% of stories` : undefined} />
            <Stat label="Rule matches" value={s.ruleHits.toLocaleString()} hint={`${alerts.data?.length ?? 0} alerts sent`} />
            <Stat label="Advisories" value={(s.byCategory.advisory ?? 0).toLocaleString()} hint={`${s.byCategory.podcast ?? 0} podcast episodes`} />
          </div>

          <SeverityChart stats={s} />

          <AttackAndTrends days={Math.max(days, 7)} />

          <div className="grid gap-5 lg:grid-cols-3">
            <TopList title="Most-mentioned CVEs" items={s.top.cves} mono />
            <TopList title="Threat actors" items={s.top.threatActors} />
            <TopList title="Malware & tools" items={s.top.malware} />
            <TopList title="Vendors" items={s.top.vendors} />
            <TopList title="Topics" items={s.top.topics} />
            <div className="card p-4">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-sm font-semibold">Recent alerts</h2>
                <Link to="/activity" className="text-xs text-muted hover:text-accent">
                  View all
                </Link>
              </div>
              {alerts.data?.length ? (
                <ul className="space-y-2.5">
                  {alerts.data.slice(0, 6).map((a) => (
                    <li key={a.id} className="text-sm">
                      <Link to={`/?item=${a.itemId}`} className="line-clamp-2 leading-snug hover:text-accent">
                        {a.title}
                      </Link>
                      <div className="mt-0.5 flex items-center gap-1.5 text-xs text-muted">
                        <BellRing className="size-3 text-accent" />
                        {a.ruleName} · {timeAgo(a.createdAt)}
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted">
                  No alerts yet. <Link className="text-accent" to="/rules">Create a rule</Link> to get notified.
                </p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Severity is ordinal, so it uses one sequential warm ramp (see index.css).
// Stack order is most severe at the bottom (the baseline).
const STACK: Severity[] = ["critical", "high", "medium", "low", "info"];

function SeverityChart({ stats }: { stats: Stats }) {
  const [view, setView] = useState<"chart" | "table">("chart");
  const [hover, setHover] = useState<number | null>(null);
  const navigate = useNavigate();
  const data = stats.byDay;
  const totals = data.map((d) => STACK.reduce((n, s) => n + (d.bySeverity[s] ?? 0), 0));
  const maxV = Math.max(1, ...totals);
  const niceMax = niceCeil(maxV);
  const ticks = [0, niceMax / 2, niceMax];
  const fmtDay = (d: string) => new Date(d + "T12:00:00").toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const labelEvery = Math.ceil(data.length / 10);

  return (
    <div className="card p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">Stories per day by severity</h2>
        <div className="flex items-center gap-3">
          <div className="flex flex-wrap items-center gap-3 text-xs text-ink-2">
            {SEVERITIES.map((s) => (
              <span key={s} className="inline-flex items-center gap-1.5 capitalize">
                <span className="size-2.5 rounded-sm" style={{ background: sevVar[s] }} />
                {s}
              </span>
            ))}
          </div>
          <button
            className="rounded p-1 text-muted hover:bg-hover hover:text-ink"
            onClick={() => setView(view === "chart" ? "table" : "chart")}
            aria-label={view === "chart" ? "Show as table" : "Show as chart"}
            title={view === "chart" ? "Table view" : "Chart view"}
          >
            {view === "chart" ? <Table2 className="size-4" /> : <BarChart3 className="size-4" />}
          </button>
        </div>
      </div>

      {view === "table" ? (
        <div className="scroll-thin max-h-72 overflow-auto">
          <table className="w-full text-sm tabular-nums">
            <thead className="text-xs text-muted">
              <tr>
                <th className="py-1 text-left font-medium">Date</th>
                {STACK.map((s) => (
                  <th key={s} className="py-1 text-right font-medium capitalize">
                    {s}
                  </th>
                ))}
                <th className="py-1 text-right font-medium">Total</th>
              </tr>
            </thead>
            <tbody>
              {data.map((d, i) => (
                <tr key={d.date} className="border-t border-line">
                  <td className="py-1 text-ink-2">{fmtDay(d.date)}</td>
                  {STACK.map((s) => (
                    <td key={s} className="py-1 text-right text-ink-2">
                      {d.bySeverity[s] ?? 0}
                    </td>
                  ))}
                  <td className="py-1 text-right font-medium">{totals[i]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="flex gap-2">
          <div className="relative flex h-56 w-8 flex-col justify-between pb-5 text-right text-[11px] tabular-nums text-muted">
            {[...ticks].reverse().map((t) => (
              <span key={t} className="-translate-y-1/2 first:translate-y-0 last:translate-y-1/2">
                {t}
              </span>
            ))}
          </div>
          <div className="relative min-w-0 flex-1">
            <div className="pointer-events-none absolute inset-x-0 top-0 h-[calc(100%-20px)]">
              {ticks.map((t) => (
                <div key={t} className="absolute inset-x-0 border-t border-line/70" style={{ bottom: `${(t / niceMax) * 100}%` }} />
              ))}
            </div>
            <div className="relative flex h-56 items-stretch" onMouseLeave={() => setHover(null)}>
              {data.map((d, i) => (
                <div
                  key={d.date}
                  className="group relative flex flex-1 cursor-pointer flex-col items-center"
                  onMouseEnter={() => setHover(i)}
                  onClick={() => navigate(`/?days=${Math.max(1, data.length - i)}`)}
                >
                  <div className="flex h-[calc(100%-20px)] w-full items-end justify-center px-[18%]">
                    <div className={cn("flex w-full max-w-10 flex-col-reverse gap-[2px] transition-opacity", hover !== null && hover !== i && "opacity-55")} style={{ height: `${(totals[i] / niceMax) * 100}%` }}>
                      {STACK.map((s, si) => {
                        const v = d.bySeverity[s] ?? 0;
                        if (!v) return null;
                        const isTop = STACK.slice(si + 1).every((x) => !(d.bySeverity[x] ?? 0));
                        return <div key={s} style={{ flexGrow: v, flexBasis: 0, background: sevVar[s], minHeight: 2 }} className={cn(isTop && "rounded-t")} />;
                      })}
                    </div>
                  </div>
                  <div className="h-5 pt-1 text-[11px] text-muted">{i % labelEvery === 0 || i === data.length - 1 ? fmtDay(d.date) : ""}</div>
                  {hover === i && (
                    <div className="pointer-events-none absolute bottom-full z-10 mb-1 w-40 rounded-lg border border-line bg-panel px-3 py-2 text-xs shadow-xl">
                      <div className="mb-1 font-medium text-ink">{fmtDay(d.date)}</div>
                      {STACK.map((s) => (
                        <div key={s} className="flex items-center justify-between gap-2 text-ink-2">
                          <span className="inline-flex items-center gap-1.5 capitalize">
                            <span className="size-2 rounded-sm" style={{ background: sevVar[s] }} />
                            {s}
                          </span>
                          <span className="tabular-nums">{d.bySeverity[s] ?? 0}</span>
                        </div>
                      ))}
                      <div className="mt-1 flex justify-between border-t border-line pt-1 font-medium text-ink">
                        <span>Total</span>
                        <span className="tabular-nums">{totals[i]}</span>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function niceCeil(v: number): number {
  const mag = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * mag >= v) return Math.max(2, m * mag);
  return v;
}

function TopList({ title, items, mono }: { title: string; items: { name: string; count: number }[]; mono?: boolean }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div className="card p-4">
      <h2 className="mb-3 text-sm font-semibold">{title}</h2>
      {items.length === 0 ? (
        <p className="text-sm text-muted">None in this period.</p>
      ) : (
        <ul className="space-y-1.5">
          {items.slice(0, 8).map((i) => (
            <li key={i.name}>
              <Link to={`/?tag=${encodeURIComponent(i.name)}&days=30`} className="group flex items-center gap-2 text-sm" title={`${i.name}: ${i.count} stories`}>
                <span className={cn("w-2/5 shrink-0 truncate text-ink-2 group-hover:text-accent", mono && "font-mono text-xs")}>{i.name}</span>
                <span className="relative h-2 flex-1">
                  <span className="absolute inset-y-0 left-0 rounded-r bg-accent/70" style={{ width: `${(i.count / max) * 100}%` }} />
                </span>
                <span className="w-6 text-right text-xs tabular-nums text-muted">{i.count}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}


function AttackAndTrends({ days }: { days: number }) {
  const fw = useQuery({ queryKey: ["frameworks", days], queryFn: () => intelApi.frameworks(days) });
  const tr = useQuery({ queryKey: ["trends", Math.min(days, 30)], queryFn: () => intelApi.trends(Math.min(days, 30)) });
  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_340px]">
      <div className="card min-w-0 p-4">
        <div className="mb-1 flex items-baseline justify-between">
          <h2 className="text-sm font-semibold">MITRE ATT&CK techniques</h2>
          {fw.data && (
            <span className="text-xs text-muted">
              {fw.data.coverage.taggedAttack} of {fw.data.stories} stories mapped
            </span>
          )}
        </div>
        <p className="mb-3 text-xs text-muted">Techniques described in your stories, by tactic. AI summaries add these, so summarise more stories for fuller coverage.</p>
        {fw.data ? <Heatmap tactics={fw.data.attackTactics} data={fw.data.coverage.attack} empty="No ATT&CK techniques mapped yet. Summarise a few stories to populate this." /> : <Spinner />}
      </div>
      <div className="card p-4">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Rising this period</h2>
          <Link to="/events" className="text-xs text-muted hover:text-accent">
            Events
          </Link>
        </div>
        {tr.data ? <TrendList trends={tr.data.rising} limit={10} /> : <Spinner />}
      </div>
    </div>
  );
}
