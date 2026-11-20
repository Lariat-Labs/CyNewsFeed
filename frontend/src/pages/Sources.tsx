import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, CircleAlert, CircleDashed, Mic, Pencil, Plus, Trash2 } from "lucide-react";
import { api, CATEGORIES, type Category, type Feed } from "../api";
import { ErrorBox, Modal, PageHeader, Segmented, Spinner, Toggle } from "../components/ui";
import { catLabel, cn, hostname, timeAgo } from "../util";

export default function Sources() {
  const qc = useQueryClient();
  const feeds = useQuery({ queryKey: ["feeds"], queryFn: api.feeds });
  const [cat, setCat] = useState<Category | "all">("all");
  const [editing, setEditing] = useState<Partial<Feed> | null>(null);
  const update = useMutation({ mutationFn: api.updateFeed, onSuccess: () => qc.invalidateQueries({ queryKey: ["feeds"] }) });
  const del = useMutation({ mutationFn: api.deleteFeed, onSuccess: () => qc.invalidateQueries({ queryKey: ["feeds"] }) });
  const seed = useMutation({ mutationFn: api.seedFeeds, onSuccess: () => qc.invalidateQueries({ queryKey: ["feeds"] }) });

  const list = useMemo(() => (feeds.data ?? []).filter((f) => cat === "all" || f.category === cat), [feeds.data, cat]);
  const errors = feeds.data?.filter((f) => f.enabled && f.lastStatus === "error").length ?? 0;
  const counts = useMemo(() => {
    const m: Record<string, number> = { all: feeds.data?.length ?? 0 };
    for (const f of feeds.data ?? []) m[f.category] = (m[f.category] ?? 0) + 1;
    return m;
  }, [feeds.data]);

  return (
    <div className="mx-auto max-w-6xl p-4 md:p-6">
      <PageHeader
        title="Sources"
        subtitle={
          feeds.data
            ? `${feeds.data.filter((f) => f.enabled).length} of ${feeds.data.length} sources enabled${errors ? ` · ${errors} failing` : ""}`
            : undefined
        }
        actions={
          <>
            <button className="btn-ghost" onClick={() => seed.mutate()} disabled={seed.isPending} title="Add any missing built-in sources">
              Restore defaults
            </button>
            <button className="btn-primary" onClick={() => setEditing({ kind: "rss", category: "news", weight: 3, enabled: true })}>
              <Plus className="size-4" /> Add source
            </button>
          </>
        }
      />
      <div className="mb-4">
        <Segmented
          value={cat}
          onChange={setCat}
          options={[{ value: "all" as const, label: `All ${counts.all}` }, ...CATEGORIES.map((c) => ({ value: c, label: `${catLabel(c)} ${counts[c] ?? 0}` }))]}
        />
      </div>
      <ErrorBox error={feeds.error || update.error || del.error} />
      {seed.data && <p className="mb-3 text-sm text-muted">Added {seed.data.added} default sources.</p>}
      {feeds.isLoading ? (
        <div className="flex justify-center p-10">
          <Spinner />
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="border-b border-line text-left text-xs text-muted">
              <tr>
                <th className="px-4 py-2.5 font-medium">Source</th>
                <th className="px-2 py-2.5 font-medium">Category</th>
                <th className="px-2 py-2.5 font-medium">Health</th>
                <th className="px-2 py-2.5 text-right font-medium">Items</th>
                <th className="px-2 py-2.5 font-medium">Enabled</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {list.map((f) => (
                <tr key={f.id} className={cn("border-b border-line last:border-0", !f.enabled && "opacity-55")}>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1.5 font-medium">
                      {f.category === "podcast" && <Mic className="size-3.5 text-muted" />}
                      <Link to={`/?feed=${f.id}&days=30`} className="hover:text-accent">
                        {f.name}
                      </Link>
                    </div>
                    <div className="text-xs text-muted">
                      {hostname(f.url)}
                      {f.kind === "cisa-kev" && " · KEV JSON"}
                      {f.kind === "osv-watch" && " · OSV inventory watch"}
                    </div>
                  </td>
                  <td className="px-2 py-2.5 text-ink-2">{catLabel(f.category)}</td>
                  <td className="px-2 py-2.5">
                    <Health feed={f} />
                  </td>
                  <td className="px-2 py-2.5 text-right tabular-nums text-ink-2">
                    {f.itemCount}
                    {f.lastNewItems > 0 && <span className="ml-1 text-xs text-accent">+{f.lastNewItems}</span>}
                  </td>
                  <td className="px-2 py-2.5">
                    <Toggle checked={f.enabled} onChange={(v) => update.mutate({ ...f, enabled: v })} label={`Toggle ${f.name}`} />
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <button className="rounded p-1.5 text-muted hover:bg-hover hover:text-ink" onClick={() => setEditing(f)} aria-label={`Edit ${f.name}`}>
                      <Pencil className="size-4" />
                    </button>
                    <button
                      className="rounded p-1.5 text-muted hover:bg-hover hover:text-danger"
                      onClick={() => confirm(`Delete “${f.name}”? Existing items are kept.`) && del.mutate(f.id)}
                      aria-label={`Delete ${f.name}`}
                    >
                      <Trash2 className="size-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editing && <FeedEditor feed={editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

function Health({ feed }: { feed: Feed }) {
  if (!feed.lastFetched || feed.lastFetched.startsWith("0001"))
    return (
      <span className="inline-flex items-center gap-1 text-xs text-muted">
        <CircleDashed className="size-3.5" /> not fetched yet
      </span>
    );
  if (feed.lastStatus === "error")
    return (
      <span className="inline-flex max-w-xs items-center gap-1 text-xs text-danger" title={feed.lastError}>
        <CircleAlert className="size-3.5 shrink-0" />
        <span className="truncate">{feed.lastError}</span>
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1 text-xs text-ink-2">
      <CheckCircle2 className="size-3.5 text-ok" /> {timeAgo(feed.lastFetched)}
      {feed.lastStatus === "not-modified" && <span className="text-muted">· unchanged</span>}
    </span>
  );
}

function FeedEditor({ feed, onClose }: { feed: Partial<Feed>; onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState<Partial<Feed>>(feed);
  const isNew = !feed.id;
  const save = useMutation({
    mutationFn: () => (isNew ? api.createFeed(f) : api.updateFeed(f as Feed)),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["feeds"] });
      onClose();
    },
  });
  const test = useMutation({
    mutationFn: () => api.testFeed(f),
    onSuccess: (r) => {
      if (r.ok && !f.name && r.title) setF((x) => ({ ...x, name: r.title }));
    },
  });

  return (
    <Modal open onClose={onClose} title={isNew ? "Add source" : `Edit ${feed.name}`}>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <div>
          <label className="label" htmlFor="furl">Feed URL</label>
          <div className="flex gap-2">
            <input id="furl" className="input" type="url" required value={f.url ?? ""} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://example.com/feed.xml" />
            <button type="button" className="btn-ghost shrink-0" disabled={!f.url || test.isPending} onClick={() => test.mutate()}>
              {test.isPending ? <Spinner className="size-3" /> : "Test"}
            </button>
          </div>
          {test.data && (
            <div className={cn("mt-2 rounded-md border px-3 py-2 text-xs", test.data.ok ? "border-line bg-panel-2 text-ink-2" : "border-danger/40 bg-danger/10 text-danger")}>
              {test.data.ok ? (
                <>
                  <div className="mb-1 font-medium text-ink">
                    ✓ {test.data.title || "Feed"} · {test.data.itemCount} items
                  </div>
                  <ul className="space-y-0.5">
                    {test.data.preview?.map((p) => (
                      <li key={p.link} className="truncate">
                        {p.audio ? "🎧 " : "• "}
                        {p.title}
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                test.data.error
              )}
            </div>
          )}
        </div>
        <div>
          <label className="label" htmlFor="fname">Name</label>
          <input id="fname" className="input" required value={f.name ?? ""} onChange={(e) => setF({ ...f, name: e.target.value })} />
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="label" htmlFor="fcat">Category</label>
            <select id="fcat" className="input" value={f.category} onChange={(e) => setF({ ...f, category: e.target.value as Category })}>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label" htmlFor="fkind">Type</label>
            <select id="fkind" className="input" value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as Feed["kind"] })}>
              <option value="rss">RSS / Atom / JSON</option>
              <option value="cisa-kev">CISA KEV JSON</option>
              <option value="osv-watch">OSV inventory watch</option>
            </select>
          </div>
          <div>
            <label className="label" htmlFor="fw">Digest weight</label>
            <select id="fw" className="input" value={f.weight ?? 3} onChange={(e) => setF({ ...f, weight: Number(e.target.value) })}>
              {[1, 2, 3, 4, 5].map((w) => (
                <option key={w} value={w}>
                  {w}
                </option>
              ))}
            </select>
          </div>
        </div>
        <ErrorBox error={save.error} />
        <div className="flex justify-end gap-2 border-t border-line pt-4">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={save.isPending}>
            {isNew ? "Add source" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
