import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, BellRing, ChevronDown, ExternalLink, Loader2, Sparkles, Star, X } from "lucide-react";
import { api, type Item } from "../api";
import { cn, fmtDateTime, fmtUSD, hostname, tagGroups } from "../util";
import { Chip, SeverityBadge, Spinner } from "./ui";
import { HighlightedText, itemEntities, useAsk, usePopover } from "./Highlight";
import { DetectionsPanel, FrameworkTags } from "./StoryIntel";

function EntityChip({ kind, value, itemId, itemTitle }: { kind: string; value: string; itemId: string; itemTitle: string }) {
  const open = usePopover();
  return (
    <span className="inline-flex">
      <button
        type="button"
        className="inline-flex"
        onClick={(e) => open({ type: kind, value }, e.currentTarget.getBoundingClientRect(), { itemId, itemTitle })}
        title={`Ask about ${value}`}
      >
        <Chip kind={kind === "cve" || ["ip", "domain", "url", "md5", "sha1", "sha256", "email"].includes(kind) ? "cve" : kind}>{value}</Chip>
      </button>
    </span>
  );
}

export default function ItemDetail({ id, onClose }: { id: string; onClose: () => void; onTag?: (t: string) => void }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["item", id], queryFn: () => api.item(id) });
  const [showSource, setShowSource] = useState(false);
  const [allTags, setAllTags] = useState(false);
  const ask = useAsk();
  const summarize = useMutation({
    mutationFn: () => api.summarize(id),
    onSuccess: (r) => {
      const it = r.items[0];
      qc.setQueryData(["item", id], (old: Item | undefined) => (old ? { ...it, content: old.content } : it));
      qc.setQueriesData({ queryKey: ["items"] }, (old: { items: Item[]; total: number } | undefined) =>
        old ? { ...old, items: old.items.map((x) => (x.id === id ? { ...x, ...it } : x)) } : old,
      );
      qc.invalidateQueries({ queryKey: ["usage"] });
    },
  });

  const patch = useMutation({
    mutationFn: (p: { read?: boolean; starred?: boolean }) => api.patchItem(id, p),
    onSuccess: (it) => {
      qc.setQueryData(["item", id], (old: Item | undefined) => (old ? { ...old, read: it.read, starred: it.starred } : old));
      qc.setQueriesData({ queryKey: ["items"] }, (old: { items: Item[]; total: number } | undefined) =>
        old ? { ...old, items: old.items.map((x) => (x.id === id ? { ...x, read: it.read, starred: it.starred } : x)) } : old,
      );
    },
  });

  const item = q.data;
  useEffect(() => {
    setShowSource(false);
    setAllTags(false);
    if (item && !item.read) patch.mutate({ read: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item?.id]);

  if (q.isLoading)
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner />
      </div>
    );
  if (!item) return <div className="p-6 text-sm text-muted">Item not found.</div>;

  const groups = tagGroups(item.tags);
  const source = item.content || item.snippet;
  const ents = itemEntities(item);
  const hl = (text: string) => <HighlightedText text={text} entities={ents} itemId={item.id} itemTitle={item.title} />;

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between gap-2 border-b border-line px-5 py-2.5">
        <div className="flex min-w-0 items-center gap-2 text-xs text-muted">
          <SeverityBadge severity={item.severity} />
          <span className="truncate">{item.feedName}</span>
        </div>
        <div className="flex items-center gap-1">
          <button
            className={cn("rounded p-1.5 hover:bg-hover", item.starred ? "text-accent" : "text-muted hover:text-ink")}
            onClick={() => patch.mutate({ starred: !item.starred })}
            aria-label={item.starred ? "Unstar" : "Star"}
            title="Star (s)"
          >
            <Star className={cn("size-4", item.starred && "fill-current")} />
          </button>
          <a className="rounded p-1.5 text-muted hover:bg-hover hover:text-ink" href={item.link} target="_blank" rel="noreferrer" title="Open original (o)">
            <ExternalLink className="size-4" />
          </a>
          <button className="btn-ghost mr-1 py-1 text-xs" onClick={() => ask.mutate({ text: `Tell me more about this story and what else our sources say about it: "${item.title}" (story id ${item.id}).` })} disabled={ask.isPending} title="Ask the agent about this story">
            <Sparkles className="size-3.5" /> Ask
          </button>
          <button className="rounded p-1.5 text-muted hover:bg-hover hover:text-ink" onClick={onClose} aria-label="Close">
            <X className="size-4" />
          </button>
        </div>
      </div>

      <div className="scroll-thin flex-1 overflow-y-auto px-5 py-5">
        <a href={item.link} target="_blank" rel="noreferrer" className="group block">
          <h2 className="text-lg font-semibold leading-snug group-hover:text-accent">{item.title}</h2>
        </a>
        <div className="mt-1.5 flex flex-wrap gap-x-2 text-xs text-muted">
          <span>{fmtDateTime(item.published)}</span>
          {item.author && <span>· {item.author}</span>}
          <span>· {hostname(item.link)}</span>
          {item.duration && <span>· {item.duration}</span>}
        </div>

        {item.audioUrl && (
          <audio controls preload="none" src={item.audioUrl} className="mt-4 w-full">
            <a href={item.audioUrl}>Download episode</a>
          </audio>
        )}

        {item.aiStatus !== "done" && (
          <div className="mt-4 flex flex-wrap items-center gap-3 rounded-lg border border-dashed border-line bg-panel-2 px-4 py-3">
            <div className="min-w-0 flex-1 text-sm">
              <div className="font-medium text-ink">Not summarised yet</div>
              <div className="text-xs text-muted">
                {item.aiStatus === "error" ? "The last AI attempt failed. " : "AI summaries are on demand. "}
                Get a TL;DR, key points, severity, entities, IOCs and highlighted follow-ups.
              </div>
            </div>
            <button className="btn-primary" onClick={() => summarize.mutate()} disabled={summarize.isPending}>
              {summarize.isPending ? <Loader2 className="size-4 animate-spin" /> : <Sparkles className="size-4" />}
              {summarize.isPending ? "Summarising…" : "Summarise with AI"}
            </button>
            {summarize.error && <div className="w-full text-xs text-danger">{summarize.error.message}</div>}
          </div>
        )}
        {summarize.data && (
          <p className="mt-2 text-[11px] text-muted">
            Summarised for {fmtUSD(summarize.data.usage.costUsd)} ({summarize.data.usage.input.toLocaleString()} in / {summarize.data.usage.output.toLocaleString()} out tokens).
          </p>
        )}

        {item.aiStatus === "error" && (
          <div className="mt-4 flex items-start gap-2 rounded-md border border-line bg-panel-2 px-3 py-2 text-xs text-ink-2">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-danger" />
            <span>AI summary failed and will be retried on the next run. {item.aiError}</span>
          </div>
        )}

        {item.tldr && (
          <section className="mt-5">
            <div className="label flex items-center gap-1">
              {item.aiStatus === "done" ? (
                <>
                  <Sparkles className="size-3" /> TL;DR
                </>
              ) : (
                "Lead (excerpt, not AI)"
              )}
            </div>
            <p className="text-[15px] leading-relaxed text-ink">{hl(item.tldr)}</p>
          </section>
        )}

        {item.bullets && item.bullets.length > 0 && (
          <section className="mt-5">
            <div className="label">Key points</div>
            <ul className="space-y-1.5 text-sm leading-relaxed text-ink-2">
              {item.bullets.map((b, i) => (
                <li key={i} className="flex gap-2">
                  <span className="mt-2 size-1 shrink-0 rounded-full bg-muted" />
                  <span>{hl(b)}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        {item.whyItMatters && (
          <section className="mt-5 rounded-lg border border-line bg-panel-2 px-4 py-3">
            <div className="label">Why it matters</div>
            <p className="text-sm leading-relaxed text-ink-2">{hl(item.whyItMatters)}</p>
          </section>
        )}

        {item.ruleHits && item.ruleHits.length > 0 && (
          <section className="mt-5">
            <div className="label">Matched alert rules</div>
            <div className="space-y-2">
              {item.ruleHits.map((h) => (
                <div key={h.ruleId} className="rounded-lg border border-accent/30 bg-accent/5 px-3 py-2 text-sm">
                  <div className="flex items-center gap-2 font-medium text-accent">
                    <BellRing className="size-3.5" /> {h.ruleName}
                    <span className="ml-auto text-xs tabular-nums">relevance {h.score}</span>
                  </div>
                  {h.reason && <p className="mt-0.5 text-xs text-ink-2">{h.reason}</p>}
                  {h.matchedKeywords && h.matchedKeywords.length > 0 && (
                    <p className="mt-0.5 text-xs text-muted">Keywords: {h.matchedKeywords.join(", ")}</p>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}

        <FrameworkTags item={item} />

        {groups.length > 0 && (
          <section className="mt-5 space-y-2.5">
            {groups.map((g) => (
              <div key={g.kind}>
                <div className="label">{g.label}</div>
                <div className="flex flex-wrap gap-1">
                  {(allTags ? g.values : g.values.slice(0, 16)).map((v) => (
                    <EntityChip key={v} kind={g.kind} value={v} itemId={item.id} itemTitle={item.title} />
                  ))}
                  {!allTags && g.values.length > 16 && (
                    <button className="text-[11px] text-muted hover:text-accent" onClick={() => setAllTags(true)}>
                      +{g.values.length - 16} more
                    </button>
                  )}
                </div>
              </div>
            ))}
          </section>
        )}

        <DetectionsPanel item={item} />

        {source && (
          <section className="mt-6 border-t border-line pt-4">
            <button className="flex items-center gap-1 text-xs font-medium uppercase tracking-wide text-muted hover:text-ink" onClick={() => setShowSource((s) => !s)}>
              <ChevronDown className={cn("size-3.5 transition", showSource && "rotate-180")} />
              Source text
            </button>
            {showSource && <div className="mt-3 whitespace-pre-line text-sm leading-relaxed text-ink-2">{hl(source)}</div>}
          </section>
        )}

        {ents.length > 0 && (
          <p className="mt-6 text-[11px] text-muted">
            Tip: click any <span className="rounded-[3px] bg-amber-300/20 px-0.5 ring-1 ring-amber-400/40">highlighted detail</span>, CVE, actor or indicator to ask the agent about it.
          </p>
        )}
        {item.aiModel && <p className="mt-2 text-[11px] text-muted">Summarised by {item.aiModel}. AI summaries can be wrong; check the source.</p>}
      </div>
    </div>
  );
}
