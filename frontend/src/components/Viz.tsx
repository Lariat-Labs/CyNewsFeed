import { Link } from "react-router-dom";
import type { TechniqueCount, Trend } from "../api";
import { cn } from "../util";

// Sequential single-hue scale (accent): magnitude only, light -> strong.
const STEPS = [12, 28, 45, 65, 88];
function stepFor(v: number, max: number) {
  if (max <= 1) return STEPS[2];
  const r = (v - 1) / (max - 1);
  return STEPS[Math.min(STEPS.length - 1, Math.floor(r * STEPS.length))];
}

/** Tactic-column heatmap (MITRE ATT&CK / ATLAS style). */
export function Heatmap({ tactics, data, empty }: { tactics: string[]; data: Record<string, TechniqueCount[]>; empty: string }) {
  const cols = [...tactics, ...(data["Unspecified"]?.length ? ["Unspecified"] : [])];
  const max = Math.max(1, ...Object.values(data).flat().map((t) => t.count));
  const total = Object.values(data).flat().length;
  if (total === 0) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <div>
      <div className="scroll-thin overflow-x-auto pb-1">
        <div className="grid min-w-max gap-1" style={{ gridTemplateColumns: `repeat(${cols.length}, minmax(118px, 1fr))` }}>
          {cols.map((tac) => (
            <div key={tac} className="min-w-0">
              <div className="mb-1 truncate border-b border-line pb-1 text-[10px] font-semibold uppercase tracking-wide text-muted" title={tac}>
                {tac} <span className="font-normal">{data[tac]?.length ? `· ${data[tac].length}` : ""}</span>
              </div>
              <div className="space-y-[2px]">
                {(data[tac] ?? []).slice(0, 12).map((t) => {
                  const pct = stepFor(t.count, max);
                  return (
                    <Link
                      key={t.id}
                      to={`/?tag=${encodeURIComponent(t.id)}&days=30`}
                      title={`${t.id} ${t.name || ""}\n${t.count} stor${t.count === 1 ? "y" : "ies"} · click to view`}
                      className="block truncate rounded-[4px] px-1.5 py-1 text-[10px] leading-tight transition hover:ring-1 hover:ring-accent"
                      style={{
                        background: `color-mix(in oklab, var(--accent) ${pct}%, var(--panel-2))`,
                        color: pct >= 65 ? "var(--accent-ink)" : "var(--text)",
                      }}
                    >
                      <span className="font-mono font-semibold">{t.id}</span> {t.name}
                      <span className="float-right tabular-nums opacity-80">{t.count}</span>
                    </Link>
                  );
                })}
                {(data[tac]?.length ?? 0) > 12 && <div className="px-1.5 text-[10px] text-muted">+{data[tac].length - 12} more</div>}
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-2 flex items-center gap-1 text-[10px] text-muted">
        fewer
        {STEPS.map((s) => (
          <span key={s} className="h-2.5 w-5 rounded-sm" style={{ background: `color-mix(in oklab, var(--accent) ${s}%, var(--panel-2))` }} />
        ))}
        more stories
      </div>
    </div>
  );
}

export function Sparkline({ values, className }: { values: number[]; className?: string }) {
  const w = 52;
  const h = 18;
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? w / (values.length - 1) : w;
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 1 - (v / max) * (h - 3)).toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width={w} height={h} className={cn("overflow-visible", className)} aria-hidden>
      <polyline points={pts} fill="none" stroke="var(--accent)" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

const KIND_LABEL: Record<string, string> = { cve: "CVE", actor: "Actor", malware: "Malware", vendor: "Vendor", product: "Product", topic: "Topic", attack: "ATT&CK", owasp: "OWASP" };

export function TrendList({ trends, limit = 10 }: { trends: Trend[]; limit?: number }) {
  if (!trends.length) return <p className="text-sm text-muted">Nothing is rising unusually right now.</p>;
  return (
    <ul className="space-y-1.5">
      {trends.slice(0, limit).map((t) => (
        <li key={t.kind + t.name}>
          <Link to={`/?tag=${encodeURIComponent(t.name)}&days=30`} className="group flex items-center gap-2 text-sm" title={`${t.recent} recent vs ${t.baseline} in baseline`}>
            <span className="w-11 shrink-0 text-[9px] uppercase tracking-wide text-muted">{KIND_LABEL[t.kind] ?? t.kind}</span>
            <span className="min-w-0 flex-1 truncate text-ink-2 group-hover:text-accent">{t.name}</span>
            <Sparkline values={t.daily} />
            <span className="w-10 shrink-0 text-right text-xs tabular-nums">
              {t.new ? <span className="rounded bg-accent/15 px-1 text-[10px] font-semibold text-accent">NEW</span> : <span className="text-ink-2">×{t.ratio.toFixed(1)}</span>}
            </span>
            <span className="w-6 shrink-0 text-right text-xs tabular-nums text-muted">{t.recent}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}
