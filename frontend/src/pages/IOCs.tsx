import { useState } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useMutation, useQuery } from "@tanstack/react-query";
import { Copy, Download, Fingerprint, Search, Send, Sparkles } from "lucide-react";
import { intelApi, SEVERITIES, type Indicator } from "../api";
import { useAsk } from "../components/Highlight";
import { Empty, ErrorBox, PageHeader, Segmented, SeverityBadge, Spinner } from "../components/ui";
import { timeAgo } from "../util";

const TYPES = [
  { value: "", label: "All" },
  { value: "ip", label: "IPs" },
  { value: "domain", label: "Domains" },
  { value: "url", label: "URLs" },
  { value: "hash", label: "Hashes" },
  { value: "email", label: "Emails" },
];

export default function IOCs() {
  const [days, setDays] = useState(30);
  const [type, setType] = useState("");
  const [minSev, setMinSev] = useState("");
  const [q, setQ] = useState("");
  const params = { days, type, min_severity: minSev, q };
  const iocs = useQuery({ queryKey: ["iocs", params], queryFn: () => intelApi.iocs(params), placeholderData: keepPreviousData });
  const integ = useQuery({ queryKey: ["integrations"], queryFn: intelApi.integrations, staleTime: 60_000 });
  const misp = useMutation({ mutationFn: () => intelApi.pushMISP({ days, minSeverity: minSev, type }) });
  const ask = useAsk();
  const list = iocs.data?.indicators ?? [];

  return (
    <div className="mx-auto max-w-6xl p-4 md:p-6">
      <PageHeader
        title="Indicators of compromise"
        subtitle="Every IOC extracted from your stories, deduplicated, with first and last seen. Export it, or share it over TAXII."
        actions={
          <>
            {(["stix", "csv", "txt"] as const).map((f) => (
              <a key={f} className="btn-ghost" href={intelApi.exportUrl({ format: f, ...params, defang: f === "txt" ? false : undefined })} title={`Download ${f.toUpperCase()}`}>
                <Download className="size-4" /> {f === "stix" ? "STIX 2.1" : f.toUpperCase()}
              </a>
            ))}
            {integ.data?.misp.configured && (
              <button className="btn-primary" disabled={misp.isPending || !list.length} onClick={() => confirm(`Create a MISP event with ${list.length} indicators?`) && misp.mutate()}>
                <Send className="size-4" /> {misp.isPending ? "Pushing…" : "Push to MISP"}
              </button>
            )}
          </>
        }
      />
      {misp.data && (
        <p className="mb-3 text-sm text-ok">
          Created MISP event{" "}
          <a className="underline" href={misp.data.url} target="_blank" rel="noreferrer">
            #{misp.data.eventId}
          </a>{" "}
          with {misp.data.attributes} attributes.
        </p>
      )}
      <ErrorBox error={iocs.error || misp.error} />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-56 flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted" />
          <input className="input pl-8" placeholder="Search indicator values" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <Segmented value={type} onChange={setType} options={TYPES.map((t) => ({ ...t, label: t.value && iocs.data?.counts ? `${t.label} ${countFor(iocs.data.counts, t.value)}` : t.label }))} />
        <select className="input w-auto py-1.5 text-xs" value={minSev} onChange={(e) => setMinSev(e.target.value)} aria-label="Minimum severity">
          <option value="">Any severity</option>
          {SEVERITIES.filter((s) => s !== "info").map((s) => (
            <option key={s} value={s}>
              {s}+
            </option>
          ))}
        </select>
        <Segmented
          value={days}
          onChange={setDays}
          options={[
            { value: 7, label: "7d" },
            { value: 30, label: "30d" },
            { value: 90, label: "90d" },
          ]}
        />
      </div>

      {iocs.isLoading ? (
        <Spinner />
      ) : !list.length ? (
        <div className="card">
          <Empty icon={<Fingerprint className="size-8" />} title="No indicators in this window">
            IOCs come from defanged indicators in articles and from AI summaries. Vendor research and advisories are the richest sources; summarise those stories
            to extract more.
          </Empty>
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[820px] text-sm">
            <thead className="border-b border-line text-left text-xs text-muted">
              <tr>
                <th className="px-4 py-2.5 font-medium">Indicator</th>
                <th className="px-2 py-2.5 font-medium">Severity</th>
                <th className="px-2 py-2.5 font-medium">Context</th>
                <th className="px-2 py-2.5 font-medium">Seen</th>
                <th className="px-2 py-2.5 font-medium">Stories</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {list.map((i) => (
                <Row key={i.type + i.value} i={i} onAsk={() => ask.mutate({ brief: { type: i.type, value: i.value, itemId: i.stories[0]?.id } })} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {integ.data?.taxii.enabled && (
        <p className="mt-3 text-xs text-muted">
          Also available over TAXII 2.1 at <code className="font-mono">{integ.data.taxii.apiRoot}</code>. See <Link to="/settings" className="text-accent">Settings → Integrations</Link>.
        </p>
      )}
    </div>
  );
}

function countFor(c: Record<string, number>, t: string) {
  return t === "hash" ? (c.md5 ?? 0) + (c.sha1 ?? 0) + (c.sha256 ?? 0) : (c[t] ?? 0);
}

function Row({ i, onAsk }: { i: Indicator; onAsk: () => void }) {
  const [copied, setCopied] = useState(false);
  const ctx = [...(i.malware ?? []), ...(i.actors ?? []), ...(i.cves ?? [])].slice(0, 4);
  return (
    <tr className="border-b border-line align-top last:border-0">
      <td className="max-w-[340px] px-4 py-2.5">
        <div className="text-[10px] uppercase tracking-wide text-muted">{i.type}</div>
        <div className="break-all font-mono text-[13px] text-ink">{i.defanged}</div>
      </td>
      <td className="px-2 py-2.5">
        <SeverityBadge severity={i.severity} compact />
      </td>
      <td className="px-2 py-2.5 text-xs text-ink-2">{ctx.join(", ") || <span className="text-muted">—</span>}</td>
      <td className="whitespace-nowrap px-2 py-2.5 text-xs text-ink-2">
        {timeAgo(i.lastSeen)}
        {i.firstSeen !== i.lastSeen && <div className="text-muted">first {timeAgo(i.firstSeen)}</div>}
      </td>
      <td className="max-w-[260px] px-2 py-2.5 text-xs">
        {i.stories.slice(0, 2).map((s) => (
          <Link key={s.id} to={`/?item=${s.id}&days=90`} className="block truncate text-ink-2 hover:text-accent" title={s.title}>
            {s.source}: {s.title}
          </Link>
        ))}
        {i.stories.length > 2 && <span className="text-muted">+{i.stories.length - 2} more</span>}
      </td>
      <td className="whitespace-nowrap px-4 py-2.5 text-right">
        <button className="rounded p-1.5 text-muted hover:bg-hover hover:text-ink" title="Copy (defanged)" onClick={() => navigator.clipboard?.writeText(i.defanged).then(() => setCopied(true))}>
          <Copy className={copied ? "size-4 text-ok" : "size-4"} />
        </button>
        <button className="rounded p-1.5 text-muted hover:bg-hover hover:text-accent" title="Investigate with the agent" onClick={onAsk}>
          <Sparkles className="size-4" />
        </button>
      </td>
    </tr>
  );
}
