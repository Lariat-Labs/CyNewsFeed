import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellRing, Inbox, Keyboard, Search, Sparkles, Star, X } from "lucide-react";
import { api, CATEGORIES, SEVERITIES } from "../api";
import ItemCard from "../components/ItemCard";
import ItemDetail from "../components/ItemDetail";
import { HighlightProvider } from "../components/Highlight";
import { ErrorBox, Segmented, Spinner } from "../components/ui";
import { catLabel, cn } from "../util";

const DAY_OPTIONS = [
  { value: 1, label: "24h" },
  { value: 3, label: "3d" },
  { value: 7, label: "7d" },
  { value: 30, label: "30d" },
];

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t);
  }, [v, ms]);
  return d;
}

export default function Feed() {
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? "";
  const set = useCallback(
    (patch: Record<string, string | null>) => {
      setParams(
        (p) => {
          const n = new URLSearchParams(p);
          for (const [k, v] of Object.entries(patch)) {
            if (v === null || v === "") n.delete(k);
            else n.set(k, v);
          }
          return n;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  const days = Number(get("days") || 3);
  const [search, setSearch] = useState(get("q"));
  const q = useDebounced(search, 300);
  useEffect(() => set({ q: q || null }), [q, set]);
  const [limit, setLimit] = useState(100);

  const query = {
    days,
    q,
    category: get("category"),
    severity: get("severity"),
    feed: get("feed"),
    tag: get("tag"),
    rule: get("rule"),
    hits: get("hits") === "1",
    starred: get("starred") === "1",
    unread: get("unread") === "1",
    limit,
  };
  useEffect(() => setLimit(100), [days, q, query.category, query.severity, query.feed, query.tag, query.hits, query.starred, query.unread]);

  const items = useQuery({ queryKey: ["items", query], queryFn: () => api.items(query), placeholderData: keepPreviousData });
  const feeds = useQuery({ queryKey: ["feeds"], queryFn: api.feeds, staleTime: 60_000 });
  const selected = get("item");
  const list = useMemo(() => items.data?.items ?? [], [items.data]);
  const searchRef = useRef<HTMLInputElement>(null);
  const qc = useQueryClient();
  const unsummarized = list.filter((i) => i.aiStatus !== "done").slice(0, 25);
  const bulk = useMutation({
    mutationFn: () => api.summarizeMany(unsummarized.map((i) => i.id)),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["items"] });
      qc.invalidateQueries({ queryKey: ["usage"] });
    },
  });

  // Keyboard navigation: j/k move, o open original, s star (handled in detail via click), / search, esc close.
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || e.metaKey || e.ctrlKey) return;
      const idx = list.findIndex((i) => i.id === selected);
      if (e.key === "j" || e.key === "k") {
        const next = list[Math.max(0, Math.min(list.length - 1, idx + (e.key === "j" ? 1 : -1)))];
        if (next) {
          set({ item: next.id });
          document.querySelector(`[data-item-id="${next.id}"]`)?.scrollIntoView({ block: "nearest" });
        }
      } else if (e.key === "o" && idx >= 0) {
        window.open(list[idx].link, "_blank", "noopener");
      } else if (e.key === "s" && idx >= 0) {
        (document.querySelector('[aria-label="Star"],[aria-label="Unstar"]') as HTMLButtonElement | null)?.click();
      } else if (e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "Escape") {
        set({ item: null });
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [list, selected, set]);

  const toggle = (k: string) => set({ [k]: get(k) === "1" ? null : "1" });
  const activeFilters = ["category", "severity", "feed", "tag", "rule", "hits", "starred", "unread"].filter((k) => get(k));

  return (
    <HighlightProvider onFilter={(v) => set({ tag: v, item: null })}>
    <div className="flex h-full">
      <section className={cn("flex min-w-0 flex-1 flex-col", selected && "hidden lg:flex")}>
        <div className="border-b border-line bg-panel">
        <div className={cn("mx-auto w-full space-y-2.5 px-4 py-3", !selected && "max-w-5xl")}>
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted" />
              <input
                ref={searchRef}
                className="input pl-8"
                placeholder="Search titles, summaries, CVEs, actors…  ( / )"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Segmented value={days} options={DAY_OPTIONS} onChange={(v) => set({ days: String(v) })} />
          </div>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <select className="input w-auto py-1 text-xs" value={get("category")} onChange={(e) => set({ category: e.target.value })} aria-label="Category">
              <option value="">All categories</option>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {catLabel(c)}
                </option>
              ))}
            </select>
            <select className="input w-auto py-1 text-xs" value={get("severity")} onChange={(e) => set({ severity: e.target.value })} aria-label="Minimum severity">
              <option value="">Any severity</option>
              {SEVERITIES.filter((s) => s !== "info").map((s) => (
                <option key={s} value={s}>
                  {s[0].toUpperCase() + s.slice(1)}+
                </option>
              ))}
            </select>
            <select className="input w-auto max-w-44 py-1 text-xs" value={get("feed")} onChange={(e) => set({ feed: e.target.value })} aria-label="Source">
              <option value="">All sources</option>
              {feeds.data?.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name}
                </option>
              ))}
            </select>
            <FilterToggle on={get("hits") === "1"} onClick={() => toggle("hits")} icon={<BellRing className="size-3.5" />} label="Rule hits" />
            <FilterToggle on={get("starred") === "1"} onClick={() => toggle("starred")} icon={<Star className="size-3.5" />} label="Starred" />
            <FilterToggle on={get("unread") === "1"} onClick={() => toggle("unread")} label="Unread" />
            {get("tag") && (
              <span className="inline-flex items-center gap-1 rounded-md border border-accent px-2 py-1 text-xs text-accent">
                tag: {get("tag")}
                <button onClick={() => set({ tag: null })} aria-label="Clear tag">
                  <X className="size-3" />
                </button>
              </span>
            )}
            {activeFilters.length > 0 && (
              <button
                className="text-xs text-muted hover:text-ink"
                onClick={() => set(Object.fromEntries(activeFilters.map((k) => [k, null])))}
              >
                Clear filters
              </button>
            )}
            {unsummarized.length > 0 && (activeFilters.length > 0 || q) && (
              <button
                className="inline-flex items-center gap-1 rounded-md border border-line px-2 py-1 text-xs text-ink-2 hover:border-accent hover:text-accent disabled:opacity-50"
                disabled={bulk.isPending}
                title="Summarise the unsummarised stories in this filtered view (max 25)"
                onClick={() => confirm(`Summarise ${unsummarized.length} stories with AI?`) && bulk.mutate()}
              >
                <Sparkles className={cn("size-3.5", bulk.isPending && "animate-pulse")} />
                {bulk.isPending ? "Summarising…" : `Summarise ${unsummarized.length}`}
              </button>
            )}
            <span className="ml-auto inline-flex items-center gap-2 text-xs tabular-nums text-muted">
              {items.isFetching && <Spinner className="inline size-3" />}
              {items.data ? `${items.data.total.toLocaleString()} items` : ""}
              <span className="group relative hidden md:inline-flex">
                <button className="rounded p-1 hover:bg-hover hover:text-ink" aria-label="Keyboard shortcuts">
                  <Keyboard className="size-3.5" />
                </button>
                <span className="pointer-events-none absolute right-0 top-full z-20 mt-1 hidden w-max rounded-lg border border-line bg-panel px-3 py-2 text-[11px] text-ink-2 shadow-xl group-hover:block group-focus-within:block">
                  <Kbd>j</Kbd>/<Kbd>k</Kbd> next/previous · <Kbd>o</Kbd> open original · <Kbd>s</Kbd> star · <Kbd>/</Kbd> search · <Kbd>esc</Kbd> close
                </span>
              </span>
            </span>
          </div>
        </div>
        </div>

        <div className="scroll-thin flex-1 overflow-y-auto">
          <div className={cn("mx-auto w-full", !selected && "max-w-5xl lg:border-x lg:border-line")}>
          {items.error ? (
            <div className="p-4">
              <ErrorBox error={items.error} />
            </div>
          ) : items.isLoading ? (
            <div className="flex justify-center p-10">
              <Spinner />
            </div>
          ) : list.length === 0 ? (
            <div className="flex flex-col items-center gap-2 px-6 py-20 text-center">
              <Inbox className="size-8 text-muted" />
              <p className="font-medium">Nothing here yet</p>
              <p className="max-w-sm text-sm text-muted">
                {activeFilters.length || q ? "No items match these filters." : "Run an aggregation with “Refresh now” to pull the latest news."}
              </p>
            </div>
          ) : (
            <>
              {list.map((it) => (
                <ItemCard
                  key={it.id}
                  item={it}
                  selected={it.id === selected}
                  onSelect={() => set({ item: it.id === selected ? null : it.id })}
                  onTag={(t) => set({ tag: t })}
                  activeTag={get("tag")}
                />
              ))}
              {items.data && items.data.total > list.length && (
                <div className="flex justify-center p-4">
                  <button className="btn-ghost" onClick={() => setLimit((l) => l + 100)}>
                    Load more ({(items.data.total - list.length).toLocaleString()} remaining)
                  </button>
                </div>
              )}
            </>
          )}
          </div>
        </div>
      </section>

      {/* Detail panel: only present when a story is open. Full screen below lg, side panel above. */}
      {selected && (
        <aside
          className="animate-panel-in min-w-0 flex-1 bg-panel lg:max-w-[min(48%,820px)] lg:flex-none lg:basis-[min(48%,820px)] lg:border-l lg:border-line lg:shadow-[-12px_0_32px_-16px_rgba(0,0,0,0.5)]"
        >
          <ItemDetail id={selected} onClose={() => set({ item: null })} onTag={(t) => set({ tag: t, item: null })} />
        </aside>
      )}
    </div>
    </HighlightProvider>
  );
}

function FilterToggle({ on, onClick, icon, label }: { on: boolean; onClick: () => void; icon?: React.ReactNode; label: string }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs transition",
        on ? "border-accent bg-accent/10 text-accent" : "border-line text-ink-2 hover:text-ink",
      )}
    >
      {icon}
      {label}
    </button>
  );
}

function Kbd({ children }: { children: React.ReactNode }) {
  return <kbd className="rounded border border-line bg-panel-2 px-1.5 py-0.5 font-mono text-[11px] text-ink-2">{children}</kbd>;
}
