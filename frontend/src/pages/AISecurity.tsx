import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BrainCircuit, PackageSearch, Plus, RefreshCw, Skull, Trash2 } from "lucide-react";
import { api, intelApi, type InventoryPackage } from "../api";
import { Heatmap } from "../components/Viz";
import { ErrorBox, PageHeader, Segmented, SeverityBadge, Spinner } from "../components/ui";
import { cn, timeAgo } from "../util";

export default function AISecurity() {
  const [days, setDays] = useState(30);
  const fw = useQuery({ queryKey: ["frameworks", days], queryFn: () => intelApi.frameworks(days) });
  const stories = useQuery({ queryKey: ["items", { category: "ai-security", days, limit: 8 }], queryFn: () => api.items({ category: "ai-security", days, limit: 8 }) });
  const c = fw.data?.coverage;

  return (
    <div className="mx-auto max-w-6xl p-4 md:p-6">
      <PageHeader
        title="AI security"
        subtitle="Threats to AI/LLM systems, mapped to the OWASP LLM Top 10 and MITRE ATLAS, plus your AI supply chain"
        actions={
          <Segmented
            value={days}
            onChange={setDays}
            options={[
              { value: 7, label: "7d" },
              { value: 30, label: "30d" },
              { value: 90, label: "90d" },
            ]}
          />
        }
      />
      <ErrorBox error={fw.error} />
      {fw.data && fw.data.summarised < fw.data.stories * 0.5 && (
        <div className="mb-4 rounded-md border border-line bg-panel-2 px-3 py-2 text-xs text-ink-2">
          Framework mappings come from AI summaries (plus IDs written literally in articles). {fw.data.summarised} of {fw.data.stories} stories in this window are
          summarised. Summarise AI-security stories, or turn on auto-summarise in Settings, for fuller coverage.
        </div>
      )}

      <section className="card mb-5 p-4">
        <h2 className="mb-3 text-sm font-semibold">OWASP Top 10 for LLM Applications (2025)</h2>
        {!fw.data ? (
          <Spinner />
        ) : (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            {Object.entries(fw.data.owaspNames)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([id, name]) => {
                const n = c?.owasp[id] ?? 0;
                return (
                  <Link
                    key={id}
                    to={`/?tag=${id}&days=${days}`}
                    className={cn("rounded-lg border p-2.5 transition hover:border-accent", n ? "border-amber-400/40 bg-amber-300/5" : "border-line opacity-70")}
                  >
                    <div className="flex items-baseline justify-between">
                      <span className="font-mono text-xs font-semibold text-ink">{id}</span>
                      <span className="text-lg font-semibold tabular-nums">{n}</span>
                    </div>
                    <div className="text-[11px] leading-snug text-ink-2">{name}</div>
                  </Link>
                );
              })}
          </div>
        )}
      </section>

      <section className="card mb-5 p-4">
        <h2 className="mb-1 text-sm font-semibold">MITRE ATLAS techniques</h2>
        <p className="mb-3 text-xs text-muted">Adversarial techniques against AI/ML systems seen in your stories, by tactic. Click a technique to see its stories.</p>
        {fw.data ? <Heatmap tactics={fw.data.atlasTactics} data={c?.atlas ?? {}} empty="No ATLAS techniques tagged in this window yet." /> : <Spinner />}
      </section>

      <div className="grid gap-5 lg:grid-cols-[1fr_360px]">
        <SupplyChain />
        <section className="card p-4">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="flex items-center gap-1.5 text-sm font-semibold">
              <BrainCircuit className="size-4 text-accent" /> Latest AI-security stories
            </h2>
            <Link to={`/?category=ai-security&days=${days}`} className="text-xs text-muted hover:text-accent">
              View all
            </Link>
          </div>
          <ul className="space-y-2.5">
            {stories.data?.items.map((it) => (
              <li key={it.id} className="text-sm">
                <Link to={`/?item=${it.id}&days=${days}`} className="line-clamp-2 leading-snug hover:text-accent">
                  {it.title}
                </Link>
                <div className="text-[11px] text-muted">
                  {it.feedName} · {timeAgo(it.published)}
                </div>
              </li>
            ))}
            {stories.data?.items.length === 0 && <li className="text-sm text-muted">None in this window.</li>}
          </ul>
        </section>
      </div>
    </div>
  );
}

function SupplyChain() {
  const qc = useQueryClient();
  const inv = useQuery({ queryKey: ["inventory"], queryFn: intelApi.inventory });
  const [rows, setRows] = useState<InventoryPackage[]>([]);
  const [refresh, setRefresh] = useState(false);
  useEffect(() => {
    if (inv.data) setRows(inv.data.packages);
  }, [inv.data]);
  const exposure = useQuery({ queryKey: ["exposure", refresh], queryFn: () => intelApi.exposure(refresh), staleTime: 5 * 60_000 });
  const save = useMutation({
    mutationFn: () => intelApi.saveInventory(rows),
    onSuccess: (d) => {
      qc.setQueryData(["inventory"], (o: { ecosystems: string[] } | undefined) => ({ ecosystems: o?.ecosystems ?? [], packages: d.packages }));
      qc.invalidateQueries({ queryKey: ["exposure"] });
    },
  });
  const dirty = JSON.stringify(rows) !== JSON.stringify(inv.data?.packages ?? []);
  const results = exposure.data?.results ?? [];
  const byKey = new Map(results.map((r) => [`${r.package.ecosystem}|${r.package.name}|${r.package.version ?? ""}`, r]));

  return (
    <section className="card p-4">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold">
          <PackageSearch className="size-4 text-accent" /> AI supply-chain watch
        </h2>
        <div className="ml-auto flex gap-2">
          <button className="btn-ghost py-1 text-xs" onClick={() => setRefresh((r) => !r)} disabled={exposure.isFetching}>
            <RefreshCw className={cn("size-3.5", exposure.isFetching && "animate-spin")} /> Re-check OSV
          </button>
          <button className="btn-primary py-1 text-xs" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save inventory"}
          </button>
        </div>
      </div>
      <p className="mb-3 text-xs text-muted">
        Packages your AI stack depends on. Each hourly run turns new OSV.dev advisories (vulnerabilities and malicious packages) into stories. Pin a version to see only
        advisories that affect it.
      </p>
      <ErrorBox error={inv.error || save.error || exposure.error} />
      <div className="scroll-thin max-h-[480px] overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-panel text-left text-xs text-muted">
            <tr>
              <th className="py-1.5 font-medium">Ecosystem</th>
              <th className="py-1.5 font-medium">Package</th>
              <th className="py-1.5 font-medium">Pinned version</th>
              <th className="py-1.5 font-medium">Advisories</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((p, i) => {
              const ex = byKey.get(`${p.ecosystem}|${p.name}|${p.version ?? ""}`);
              const mal = ex?.advisories.some((a) => a.malicious);
              const worst = ex?.advisories.find((a) => a.severity === "critical") ?? ex?.advisories.find((a) => a.severity === "high");
              return (
                <tr key={i} className="border-t border-line align-top">
                  <td className="py-1.5 pr-2">
                    <select className="input py-1 text-xs" value={p.ecosystem} onChange={(e) => setRows(rows.map((r, j) => (j === i ? { ...r, ecosystem: e.target.value } : r)))}>
                      {(inv.data?.ecosystems ?? ["PyPI"]).map((e) => (
                        <option key={e}>{e}</option>
                      ))}
                    </select>
                  </td>
                  <td className="py-1.5 pr-2">
                    <input className="input py-1 font-mono text-xs" value={p.name} onChange={(e) => setRows(rows.map((r, j) => (j === i ? { ...r, name: e.target.value } : r)))} />
                  </td>
                  <td className="py-1.5 pr-2">
                    <input
                      className="input w-28 py-1 font-mono text-xs"
                      placeholder="any"
                      value={p.version ?? ""}
                      onChange={(e) => setRows(rows.map((r, j) => (j === i ? { ...r, version: e.target.value } : r)))}
                    />
                  </td>
                  <td className="py-1.5 pr-2 text-xs">
                    {!ex ? (
                      <span className="text-muted">{exposure.isFetching ? "…" : dirty ? "save to check" : "—"}</span>
                    ) : ex.error ? (
                      <span className="text-danger" title={ex.error}>
                        error
                      </span>
                    ) : (
                      <details>
                        <summary className={cn("cursor-pointer", ex.advisories.length ? "text-ink" : "text-muted")}>
                          {mal && <Skull className="mr-1 inline size-3.5 text-danger" />}
                          {ex.advisories.length} {p.version ? "affecting" : "total"}
                          {worst && (
                            <span className="ml-1">
                              <SeverityBadge severity={worst.severity} compact />
                            </span>
                          )}
                        </summary>
                        <ul className="mt-1 max-w-sm space-y-1">
                          {ex.advisories.slice(0, 8).map((a) => (
                            <li key={a.id}>
                              <a href={`https://osv.dev/vulnerability/${a.id}`} target="_blank" rel="noreferrer" className="font-mono text-accent hover:underline">
                                {a.id}
                              </a>{" "}
                              <span className="text-ink-2">{a.summary}</span>
                              {a.fixed?.length ? <span className="text-muted"> · fixed {a.fixed.join(", ")}</span> : null}
                            </li>
                          ))}
                          {ex.advisories.length > 8 && <li className="text-muted">+{ex.advisories.length - 8} more</li>}
                        </ul>
                      </details>
                    )}
                  </td>
                  <td className="py-1.5 text-right">
                    <button className="rounded p-1 text-muted hover:text-danger" aria-label="Remove package" onClick={() => setRows(rows.filter((_, j) => j !== i))}>
                      <Trash2 className="size-3.5" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <button className="btn-ghost mt-2 py-1 text-xs" onClick={() => setRows([...rows, { ecosystem: "PyPI", name: "", version: "" }])}>
        <Plus className="size-3.5" /> Add package
      </button>
      {exposure.data && <p className="mt-2 text-[11px] text-muted">Checked against OSV.dev {timeAgo(exposure.data.checkedAt)}.</p>}
    </section>
  );
}
