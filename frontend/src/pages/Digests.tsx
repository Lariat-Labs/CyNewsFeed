import { useEffect } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ScrollText, Sparkles } from "lucide-react";
import { api } from "../api";
import { Empty, ErrorBox, PageHeader, Segmented, Spinner } from "../components/ui";
import WeeklyBriefs from "../components/WeeklyBriefs";
import { cn, fmtDateTime } from "../util";

export default function Digests() {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const weekly = pathname.startsWith("/digests/weekly");
  return (
    <div className="mx-auto max-w-6xl p-4 md:p-6">
      <PageHeader
        title="Digests & briefs"
        subtitle={weekly ? "Weekly executive briefs" : "An AI-written briefing of the past 24 hours, also posted to Slack"}
        actions={
          <span className="print:hidden">
            <Segmented
              value={weekly ? "weekly" : "daily"}
              onChange={(v) => navigate(v === "weekly" ? "/digests/weekly" : "/digests")}
              options={[
                { value: "daily", label: "Daily digest" },
                { value: "weekly", label: "Weekly brief" },
              ]}
            />
          </span>
        }
      />
      {weekly ? <WeeklyBriefs /> : <DailyDigests />}
    </div>
  );
}

function DailyDigests() {
  const { date } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["digests"], queryFn: api.digests });
  const current = date ?? list.data?.[0]?.date;
  const digest = useQuery({ queryKey: ["digest", current], queryFn: () => api.digest(current!), enabled: !!current });
  const run = useMutation({
    mutationFn: api.runDigest,
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ["digests"] });
      qc.setQueryData(["digest", d.date], d);
      navigate(`/digests/${d.date}`);
    },
  });
  useEffect(() => {
    if (!date && list.data?.[0]) navigate(`/digests/${list.data[0].date}`, { replace: true });
  }, [date, list.data, navigate]);

  const d = digest.data;
  return (
    <div>
      <div className="mb-4 flex justify-end">
        <button className="btn-primary" onClick={() => run.mutate()} disabled={run.isPending}>
          {run.isPending ? <Spinner className="size-4 text-accent-ink" /> : <Sparkles className="size-4" />}
          {run.isPending ? "Writing digest…" : "Generate now"}
        </button>
      </div>
      <ErrorBox error={list.error || run.error} />
      {list.isLoading ? (
        <div className="flex justify-center p-10">
          <Spinner />
        </div>
      ) : !list.data?.length ? (
        <div className="card">
          <Empty icon={<ScrollText className="size-8" />} title="No digests yet">
            Digests are generated on a schedule (daily by default). Click “Generate now” to create one from the last 24 hours.
          </Empty>
        </div>
      ) : (
        <div className="grid gap-5 md:grid-cols-[180px_1fr]">
          <nav className="flex gap-1 overflow-x-auto md:flex-col">
            {list.data.map((x) => (
              <Link
                key={x.date}
                to={`/digests/${x.date}`}
                className={cn(
                  "shrink-0 rounded-md px-3 py-2 text-sm",
                  x.date === current ? "bg-panel-2 font-medium text-ink" : "text-ink-2 hover:bg-hover",
                )}
              >
                {new Date(x.date + "T12:00:00").toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })}
              </Link>
            ))}
          </nav>
          <article className="card min-w-0 p-5 md:p-7">
            {!d ? (
              <Spinner />
            ) : (
              <>
                <div className="text-xs font-medium uppercase tracking-wide text-accent">Daily brief · {d.date}</div>
                <h2 className="mt-1 text-2xl font-semibold leading-tight tracking-tight">{d.headline}</h2>
                <p className="mt-3 leading-relaxed text-ink-2">{d.overview}</p>
                {d.sections.map((s) => (
                  <section key={s.title} className="mt-7">
                    <h3 className="mb-2 border-b border-line pb-1.5 text-sm font-semibold uppercase tracking-wide text-ink-2">{s.title}</h3>
                    <ul className="space-y-2.5">
                      {s.items.map((e) => (
                        <li key={e.itemId} className="flex gap-2.5 text-[15px] leading-relaxed">
                          <span className="mt-2.5 size-1.5 shrink-0 rounded-full bg-accent" />
                          <span>
                            {e.line}{" "}
                            <Link to={`/?item=${e.itemId}`} className="whitespace-nowrap text-xs text-muted hover:text-accent">
                              details
                            </Link>
                            {e.link && (
                              <a href={e.link} target="_blank" rel="noreferrer" className="ml-2 whitespace-nowrap text-xs text-muted hover:text-accent">
                                source ↗
                              </a>
                            )}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </section>
                ))}
                <p className="mt-8 text-xs text-muted">
                  Built from {d.itemCount} top-ranked stories{d.model ? ` by ${d.model}` : ""} · {fmtDateTime(d.createdAt)}
                </p>
              </>
            )}
          </article>
        </div>
      )}
    </div>
  );
}
