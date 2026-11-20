import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Download, FileCode2, Loader2, ShieldAlert, TriangleAlert } from "lucide-react";
import { intelApi, type Detection, type Item } from "../api";
import { cn, fmtUSD } from "../util";
import { usePopover } from "./Highlight";

const OWASP: Record<string, string> = {
  LLM01: "Prompt Injection", LLM02: "Sensitive Information Disclosure", LLM03: "Supply Chain", LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling", LLM06: "Excessive Agency", LLM07: "System Prompt Leakage", LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation", LLM10: "Unbounded Consumption",
};

/** ATT&CK / ATLAS / OWASP LLM tags; click opens the ask popover. */
export function FrameworkTags({ item }: { item: Item }) {
  const open = usePopover();
  const t = item.tags;
  const groups = [
    { label: "MITRE ATT&CK", kind: "attack", vals: (t.attack ?? []).map((x) => ({ id: x.id, text: x.name ? `${x.id} ${x.name}` : x.id, title: x.tactic })) },
    { label: "MITRE ATLAS", kind: "atlas", vals: (t.atlas ?? []).map((x) => ({ id: x.id, text: x.name ? `${x.id} ${x.name}` : x.id, title: x.tactic })) },
    { label: "OWASP LLM Top 10", kind: "owasp", vals: (t.owaspLlm ?? []).map((x) => ({ id: x, text: `${x} ${OWASP[x] ?? ""}`, title: "OWASP Top 10 for LLM Applications 2025" })) },
  ].filter((g) => g.vals.length);
  if (!groups.length) return null;
  return (
    <section className="mt-5 space-y-2.5">
      {groups.map((g) => (
        <div key={g.kind}>
          <div className="label">{g.label}</div>
          <div className="flex flex-wrap gap-1">
            {g.vals.map((v) => (
              <button
                key={v.id}
                type="button"
                title={v.title ? `${v.title}: click to ask the agent` : "Ask the agent"}
                onClick={(e) => open({ type: g.kind, value: v.text.trim() }, e.currentTarget.getBoundingClientRect(), { itemId: item.id, itemTitle: item.title })}
                className={cn(
                  "rounded-md border px-1.5 py-0.5 text-[11px] leading-4 transition hover:border-accent hover:text-accent",
                  g.kind === "attack" ? "border-sev-critical/40 text-ink" : g.kind === "atlas" ? "border-accent/40 text-ink" : "border-amber-400/40 text-ink",
                )}
              >
                <span className="font-mono">{v.id}</span>
                {v.text.length > v.id.length && <span className="text-ink-2">{v.text.slice(v.id.length)}</span>}
              </button>
            ))}
          </div>
        </div>
      ))}
    </section>
  );
}

const FORMAT_LABEL: Record<string, string> = { kql: "KQL · Sentinel / Defender", spl: "SPL · Splunk", sigma: "Sigma", yara: "YARA" };

export function DetectionsPanel({ item }: { item: Item }) {
  const qc = useQueryClient();
  const [formats, setFormats] = useState<string[]>(["kql", "spl", "sigma", "yara"]);
  const gen = useMutation({
    mutationFn: () => intelApi.detections(item.id, formats),
    onSuccess: (r) => {
      qc.setQueryData(["item", item.id], (old: Item | undefined) => (old ? { ...old, detections: r.detections } : old));
      qc.invalidateQueries({ queryKey: ["usage"] });
    },
  });
  const existing = item.detections ?? [];
  const hasIOCs = (item.tags.iocs ?? []).length > 0;

  return (
    <section className="mt-6 border-t border-line pt-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <div className="label mb-0 flex items-center gap-1">
          <ShieldAlert className="size-3" /> Detections & sharing
        </div>
        {hasIOCs && (
          <div className="ml-auto flex gap-1">
            <a className="btn-ghost px-2 py-0.5 text-xs" href={intelApi.exportUrl({ format: "stix", items: item.id, days: 90 })} title="Download this story's IOCs as a STIX 2.1 bundle">
              <Download className="size-3" /> STIX
            </a>
            <a className="btn-ghost px-2 py-0.5 text-xs" href={intelApi.exportUrl({ format: "csv", items: item.id, days: 90 })}>
              <Download className="size-3" /> CSV
            </a>
          </div>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {["kql", "spl", "sigma", "yara"].map((f) => (
          <label key={f} className="inline-flex items-center gap-1 text-xs text-ink-2">
            <input
              type="checkbox"
              className="accent-[var(--accent)]"
              checked={formats.includes(f)}
              onChange={(e) => setFormats(e.target.checked ? [...formats, f] : formats.filter((x) => x !== f))}
            />
            {f.toUpperCase()}
          </label>
        ))}
        <button className="btn-ghost ml-auto py-1 text-xs" disabled={gen.isPending || formats.length === 0} onClick={() => gen.mutate()}>
          {gen.isPending ? <Loader2 className="size-3.5 animate-spin" /> : <FileCode2 className="size-3.5" />}
          {gen.isPending ? "Writing detections…" : existing.length ? "Regenerate" : "Generate detections"}
        </button>
      </div>
      {gen.error && <p className="mt-2 text-xs text-danger">{gen.error.message}</p>}
      {gen.data && <p className="mt-1 text-[11px] text-muted">Generated for {fmtUSD(gen.data.usage.costUsd)} with {gen.data.usage.model}.</p>}
      <div className="mt-3 space-y-3">
        {existing.map((d, i) => (
          <DetectionCard key={i} d={d} />
        ))}
      </div>
      {existing.length > 0 && <p className="mt-2 text-[11px] text-muted">AI-generated: review, test against your data and tune before deploying.</p>}
    </section>
  );
}

function DetectionCard({ d }: { d: Detection }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="overflow-hidden rounded-lg border border-line">
      <div className="flex items-center gap-2 border-b border-line bg-panel-2 px-3 py-1.5">
        <span className="rounded bg-panel px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase text-accent">{d.format}</span>
        <span className="min-w-0 flex-1 truncate text-xs font-medium text-ink" title={d.description}>
          {d.title}
        </span>
        {d.valid ? (
          <span className="inline-flex items-center gap-0.5 text-[10px] text-ok" title="Passed structural validation">
            <Check className="size-3" /> valid
          </span>
        ) : (
          <span className="inline-flex items-center gap-0.5 text-[10px] text-danger" title={d.issue}>
            <TriangleAlert className="size-3" /> {d.issue}
          </span>
        )}
        {d.confidence && <span className="text-[10px] text-muted">{d.confidence} confidence</span>}
        <button
          className="rounded p-1 text-muted hover:bg-hover hover:text-ink"
          onClick={() => navigator.clipboard?.writeText(d.query).then(() => setCopied(true))}
          aria-label="Copy query"
          title={FORMAT_LABEL[d.format]}
        >
          {copied ? <Check className="size-3.5 text-ok" /> : <Copy className="size-3.5" />}
        </button>
      </div>
      <pre className="scroll-thin max-h-72 overflow-auto bg-bg px-3 py-2 font-mono text-[11px] leading-relaxed text-ink-2">{d.query}</pre>
      {(d.description || d.notes) && (
        <div className="space-y-0.5 border-t border-line px-3 py-1.5 text-[11px] text-muted">
          {d.description && <p>{d.description}</p>}
          {d.notes && <p>Tuning: {d.notes}</p>}
        </div>
      )}
    </div>
  );
}
