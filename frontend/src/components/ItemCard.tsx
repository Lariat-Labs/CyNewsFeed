import { BellRing, Mic, Sparkles, Star } from "lucide-react";
import type { Item } from "../api";
import { cn, sevDot, timeAgo } from "../util";
import { Chip } from "./ui";

export default function ItemCard({
  item,
  selected,
  onSelect,
  onTag,
  activeTag,
}: {
  item: Item;
  selected: boolean;
  onSelect: () => void;
  onTag: (t: string) => void;
  activeTag?: string;
}) {
  const t = item.tags;
  const chips: { v: string; kind: string }[] = [
    ...(t.cves ?? []).slice(0, 3).map((v) => ({ v, kind: "cve" })),
    ...(t.threatActors ?? []).slice(0, 2).map((v) => ({ v, kind: "actor" })),
    ...(t.malware ?? []).slice(0, 2).map((v) => ({ v, kind: "malware" })),
    ...(t.vendors ?? []).slice(0, 2).map((v) => ({ v, kind: "vendor" })),
    ...(t.topics ?? []).slice(0, 3).map((v) => ({ v, kind: "topic" })),
  ].slice(0, 7);
  const summary = item.tldr || item.snippet;

  return (
    <article
      data-item-id={item.id}
      onClick={onSelect}
      className={cn(
        "group cursor-pointer border-b border-line px-4 py-3 transition",
        selected ? "bg-panel-2 shadow-[inset_3px_0_0_var(--accent)]" : "hover:bg-hover/60",
      )}
    >
      <div className="flex items-start gap-3">
        <span className={cn("mt-1.5 size-2.5 shrink-0 rounded-full", sevDot[item.severity])} title={`Severity: ${item.severity}`} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 text-[11px] text-muted">
            {item.category === "podcast" && <Mic className="size-3" />}
            <span className="truncate font-medium text-ink-2">{item.feedName}</span>
            <span>·</span>
            <time dateTime={item.published} title={new Date(item.published).toLocaleString()}>
              {timeAgo(item.published)}
            </time>
            <span>·</span>
            <span className="capitalize">{item.severity}</span>
            {item.aiStatus === "done" && <Sparkles className="size-3 text-accent" aria-label="AI summarised" />}
            {item.starred && <Star className="ml-auto size-3 fill-current text-accent" />}
          </div>
          <h3 className={cn("mt-0.5 text-[15px] font-medium leading-snug", item.read ? "text-ink-2" : "text-ink")}>{item.title}</h3>
          {summary && <p className="mt-1 line-clamp-2 text-sm leading-relaxed text-ink-2">{summary}</p>}
          {(item.ruleHits?.length || chips.length > 0) && (
            <div className="mt-2 flex flex-wrap items-center gap-1">
              {item.ruleHits?.map((h) => (
                <span
                  key={h.ruleId}
                  className="inline-flex items-center gap-1 rounded-md bg-accent/15 px-1.5 py-0.5 text-[11px] font-medium text-accent"
                  title={h.reason}
                >
                  <BellRing className="size-3" />
                  {h.ruleName} · {h.score}
                </span>
              ))}
              {chips.map((c) => (
                <Chip key={c.kind + c.v} kind={c.kind} onClick={() => onTag(c.v)} active={activeTag?.toLowerCase() === c.v.toLowerCase()} title={`Filter by ${c.v}`}>
                  {c.v}
                </Chip>
              ))}
            </div>
          )}
        </div>
      </div>
    </article>
  );
}
