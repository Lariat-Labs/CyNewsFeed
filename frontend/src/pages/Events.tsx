import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronRight, Layers, Sparkles, TrendingUp } from "lucide-react";
import { intelApi, type NewsEvent } from "../api";
import { useAsk } from "../components/Highlight";
import { TrendList } from "../components/Viz";
import { Chip, Empty, ErrorBox, PageHeader, Segmented, SeverityBadge, Spinner } from "../components/ui";
import { cn, sevDot, timeAgo } from "../util";

export default function Events() {
  const [days, setDays] = useState(7);
  const events = useQuery({ queryKey: ["events", days], queryFn: () => intelApi.events(days) });
  const trends = useQuery({ queryKey: ["trends", days], queryFn: () => intelApi.trends(days) });
  const baselineThin = trends.data && new Date(trends.data.oldest).getTime() > Date.now() - (trends.data.recentDays + trends.data.baselineDays) * 86400e3 * 0.8;

  return (
    <div className="mx-auto max-w-6xl p-4 md:p-6">
      <PageHeader
        title="Events & trends"
        subtitle="Coverage of the same incident across sources, grouped into one event, plus what's rising"
        actions={
          <Segmented
            value={days}
            onChange={setDays}
            options={[
              { value: 3, label: "3d" },
              { value: 7, label: "7d" },
              { value: 14, label: "14d" },
              { value: 30, label: "30d" },
            ]}
          />
        }
      />
      <div className="grid gap-5 lg:grid-cols-[1fr_340px]">
        <div className="min-w-0 space-y-3">
          <ErrorBox error={events.error} />
          {events.isLoading ? (
            <Spinner />
          ) : !events.data?.events.length ? (
            <div className="card">
              <Empty icon={<Layers className="size-8" />} title="No multi-source events yet">
                Events form when two or more stories share a CVE or malware family, or have near-identical headlines, within 4 days.
              </Empty>
            </div>
          ) : (
            events.data.events.map((e) => <EventCard key={e.id} e={e} />)
          )}
        </div>
        <aside className="space-y-4">
          <div className="card p-4">
            <h2 className="mb-1 flex items-center gap-1.5 text-sm font-semibold">
              <TrendingUp className="size-4 text-accent" /> Rising
            </h2>
            <p className="mb-3 text-xs text-muted">
              Last {days} days vs the previous {days * 3}.{baselineThin && " The baseline is still filling up, so many items show as NEW for now."}
            </p>
            {trends.isLoading ? <Spinner /> : <TrendList trends={trends.data?.rising ?? []} limit={15} />}
          </div>
        </aside>
      </div>
    </div>
  );
}

function EventCard({ e }: { e: NewsEvent }) {
  const [open, setOpen] = useState(false);
  const ask = useAsk();
  const ents = [...(e.cves ?? []), ...(e.actors ?? []), ...(e.malware ?? []), ...(e.products ?? [])].slice(0, 8);
  return (
    <div className="card overflow-hidden">
      <button className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-hover/40" onClick={() => setOpen((o) => !o)}>
        <span className={cn("mt-1.5 size-2.5 shrink-0 rounded-full", sevDot[e.severity])} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 text-[11px] text-muted">
            <span className="font-medium text-ink-2">
              {e.sources} sources · {e.stories} stories
            </span>
            <span>
              {timeAgo(e.firstSeen)} → {timeAgo(e.lastSeen)}
            </span>
            <SeverityBadge severity={e.severity} compact />
          </div>
          <h3 className="mt-0.5 font-medium leading-snug">{e.title}</h3>
          {ents.length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {ents.map((x) => (
                <Chip key={x} kind={x.startsWith("CVE-") ? "cve" : "default"}>
                  {x}
                </Chip>
              ))}
            </div>
          )}
        </div>
        <ChevronRight className={cn("mt-1 size-4 shrink-0 text-muted transition", open && "rotate-90")} />
      </button>
      {open && (
        <div className="border-t border-line bg-panel-2/40 px-4 py-3">
          <ol className="space-y-2.5">
            {e.items.map((it) => (
              <li key={it.id} className="flex gap-2 text-sm">
                <span className="w-16 shrink-0 text-[11px] text-muted">{new Date(it.published).toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>
                <div className="min-w-0">
                  <Link to={`/?item=${it.id}&days=30`} className="font-medium text-ink hover:text-accent">
                    {it.title}
                  </Link>
                  <span className="text-xs text-muted"> · {it.source}</span>
                  {it.tldr && <p className="line-clamp-2 text-xs text-ink-2">{it.tldr}</p>}
                </div>
              </li>
            ))}
          </ol>
          <button
            className="btn-ghost mt-3 py-1 text-xs"
            disabled={ask.isPending}
            onClick={() =>
              ask.mutate({
                text: `Brief me on this multi-source event: "${e.title}". Story ids: ${e.items.map((i) => i.id).join(", ")}. Reconcile what the sources agree and disagree on, give a timeline, and list what we should do.`,
              })
            }
          >
            <Sparkles className="size-3.5" /> Brief me on this event
          </button>
        </div>
      )}
    </div>
  );
}
