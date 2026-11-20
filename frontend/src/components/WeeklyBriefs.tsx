import { useEffect } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileText, Printer, Sparkles } from "lucide-react";
import { intelApi } from "../api";
import { Empty, ErrorBox, Spinner } from "./ui";
import { cn, fmtDateTime } from "../util";

export default function WeeklyBriefs() {
  const { reportId } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["reports"], queryFn: intelApi.reports });
  const current = reportId ?? list.data?.[0]?.id;
  const rep = useQuery({ queryKey: ["report", current], queryFn: () => intelApi.report(current!), enabled: !!current });
  const gen = useMutation({
    mutationFn: intelApi.generateWeekly,
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["reports"] });
      qc.setQueryData(["report", r.id], r);
      qc.invalidateQueries({ queryKey: ["usage"] });
      navigate(`/digests/weekly/${r.id}`);
    },
  });
  useEffect(() => {
    if (!reportId && list.data?.[0]) navigate(`/digests/weekly/${list.data[0].id}`, { replace: true });
  }, [reportId, list.data, navigate]);
  const r = rep.data;

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-2 print:hidden">
        <p className="text-sm text-muted">An AI-written executive brief for leadership covering the last 7 days: top events, key risks, metrics and recommendations.</p>
        <div className="ml-auto flex gap-2">
          {r && (
            <>
              <a className="btn-ghost" href={`/api/reports/${r.id}/markdown`}>
                <Download className="size-4" /> Markdown
              </a>
              <button className="btn-ghost" onClick={() => window.print()} title="Print or save as PDF">
                <Printer className="size-4" /> PDF
              </button>
            </>
          )}
          <button className="btn-primary" onClick={() => gen.mutate()} disabled={gen.isPending}>
            <Sparkles className="size-4" /> {gen.isPending ? "Writing brief… (~1 min)" : "Generate this week's brief"}
          </button>
        </div>
      </div>
      <ErrorBox error={list.error || gen.error} />
      {list.isLoading ? (
        <Spinner />
      ) : !list.data?.length ? (
        <div className="card">
          <Empty icon={<FileText className="size-8" />} title="No weekly briefs yet">
            Generate one to get a leadership-ready summary of the past week. It's one AI call using the digest model.
          </Empty>
        </div>
      ) : (
        <div className="grid gap-5 md:grid-cols-[180px_1fr]">
          <nav className="flex gap-1 overflow-x-auto md:flex-col print:hidden">
            {list.data.map((x) => (
              <Link
                key={x.id}
                to={`/digests/weekly/${x.id}`}
                className={cn("shrink-0 rounded-md px-3 py-2 text-sm", x.id === current ? "bg-panel-2 font-medium text-ink" : "text-ink-2 hover:bg-hover")}
              >
                {x.id}
              </Link>
            ))}
          </nav>
          <article className="card min-w-0 p-6 md:p-8 print:border-0 print:p-0">
            {!r ? (
              <Spinner />
            ) : (
              <>
                <div className="text-xs font-medium uppercase tracking-wide text-accent">
                  Weekly security brief · {new Date(r.periodStart).toLocaleDateString(undefined, { day: "numeric", month: "short" })} –{" "}
                  {new Date(r.periodEnd).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })}
                </div>
                <h2 className="mt-1 text-2xl font-semibold leading-tight tracking-tight">{r.title}</h2>
                <h3 className="mt-6 text-sm font-semibold uppercase tracking-wide text-ink-2">Executive summary</h3>
                <p className="mt-2 leading-relaxed text-ink">{r.executiveSummary}</p>

                <h3 className="mt-7 text-sm font-semibold uppercase tracking-wide text-ink-2">Key risks</h3>
                <div className="mt-2 space-y-3">
                  {r.keyRisks.map((k, i) => (
                    <div key={i} className="rounded-lg border border-line p-3">
                      <div className="font-medium text-ink">
                        {i + 1}. {k.title}
                      </div>
                      <p className="mt-1 text-sm text-ink-2">{k.detail}</p>
                      <p className="mt-1.5 text-sm">
                        <span className="font-medium text-accent">Recommendation:</span> {k.recommendation}
                      </p>
                    </div>
                  ))}
                </div>

                <h3 className="mt-7 text-sm font-semibold uppercase tracking-wide text-ink-2">Top events</h3>
                <ul className="mt-2 space-y-2">
                  {r.topEvents.map((e, i) => (
                    <li key={i} className="text-sm">
                      <span className="font-medium text-ink">{e.title}</span> <span className="text-ink-2">— {e.why}</span>
                      {e.itemIds?.map((id, j) => (
                        <Link key={id} to={`/?item=${id}&days=30`} className="ml-1 text-xs text-accent print:hidden">
                          [{j + 1}]
                        </Link>
                      ))}
                    </li>
                  ))}
                </ul>

                <h3 className="mt-7 text-sm font-semibold uppercase tracking-wide text-ink-2">This week in numbers</h3>
                {r.metricsNote && <p className="mt-2 text-sm text-ink-2">{r.metricsNote}</p>}
                <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {["stories", "severity_critical", "severity_high", "alerts", "rule_matches", "kev_added", "category_advisory", "category_ai-security"]
                    .filter((k) => r.metrics[k] !== undefined)
                    .map((k) => (
                      <div key={k} className="rounded-lg border border-line px-3 py-2">
                        <div className="text-[11px] capitalize text-muted">{k.replace("severity_", "").replace("category_", "").replace(/_/g, " ")}</div>
                        <div className="text-lg font-semibold tabular-nums">{r.metrics[k]}</div>
                      </div>
                    ))}
                </div>

                <h3 className="mt-7 text-sm font-semibold uppercase tracking-wide text-ink-2">Recommendations for next week</h3>
                <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-ink">
                  {r.recommendations.map((x, i) => (
                    <li key={i}>{x}</li>
                  ))}
                </ol>
                <p className="mt-8 text-xs text-muted">
                  Generated {fmtDateTime(r.createdAt)}
                  {r.model ? ` by ${r.model}` : ""}. AI-written; verify against the linked sources.
                </p>
              </>
            )}
          </article>
        </div>
      )}
    </div>
  );
}
