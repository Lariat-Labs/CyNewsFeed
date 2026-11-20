import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, BellRing, BrainCircuit, Fingerprint, Layers, LayoutDashboard, Menu, MessageSquareText, Moon, Newspaper, RefreshCw, Rss, ScrollText, Settings, Sun, X } from "lucide-react";
import { api } from "../api";
import { cn, fmtUSD, timeAgo } from "../util";

const navGroups = [
  {
    label: "Monitor",
    items: [
      { to: "/", label: "Feed", icon: Newspaper, end: true },
      { to: "/events", label: "Events & trends", icon: Layers },
      { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { to: "/digests", label: "Digests & briefs", icon: ScrollText },
    ],
  },
  {
    label: "Investigate",
    items: [
      { to: "/chat", label: "Ask the agent", icon: MessageSquareText },
      { to: "/iocs", label: "IOCs", icon: Fingerprint },
      { to: "/ai-security", label: "AI security", icon: BrainCircuit },
    ],
  },
  {
    label: "Configure",
    items: [
      { to: "/rules", label: "Alert rules", icon: BellRing },
      { to: "/sources", label: "Sources", icon: Rss },
      { to: "/activity", label: "Activity", icon: Activity },
      { to: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    try {
      return (localStorage.getItem("theme") as "dark" | "light") || "dark";
    } catch {
      return "dark";
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);
  return [theme, setTheme] as const;
}

export default function Layout() {
  const [theme, setTheme] = useTheme();
  const [open, setOpen] = useState(false);
  const qc = useQueryClient();
  const cfg = useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: Infinity });
  const me = useQuery({ queryKey: ["me"], queryFn: api.me, staleTime: Infinity });
  const runs = useQuery({
    queryKey: ["runs"],
    queryFn: api.runs,
    refetchInterval: (q) => (q.state.data?.running ? 3000 : 60000),
  });
  const usage = useQuery({ queryKey: ["usage", 30], queryFn: () => api.usage(30), refetchInterval: 60_000 });
  const running = runs.data?.running ?? false;
  const lastAgg = runs.data?.runs.find((r) => r.kind === "aggregate" && r.status !== "running");

  // When a run finishes, refresh everything.
  const [wasRunning, setWasRunning] = useState(false);
  useEffect(() => {
    if (wasRunning && !running) qc.invalidateQueries();
    setWasRunning(running);
  }, [running, wasRunning, qc]);

  const runNow = useMutation({
    mutationFn: api.runNow,
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ["runs"] }), 500),
  });

  const sidebar = (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2.5 px-4 py-4">
        <img src="/favicon.svg" alt="" className="size-7" />
        <div>
          <div className="text-[15px] font-semibold leading-tight">CyNewsFeed</div>
          <div className="text-[11px] text-muted">Security intel, summarised</div>
        </div>
      </div>
      <nav className="scroll-thin flex-1 space-y-3 overflow-y-auto px-2">
        {navGroups.map((g) => (
          <div key={g.label} className="space-y-0.5">
            <div className="px-3 pb-0.5 text-[10px] font-semibold uppercase tracking-wider text-muted">{g.label}</div>
        {g.items.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={() => setOpen(false)}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition",
                isActive ? "bg-panel-2 font-medium text-ink" : "text-ink-2 hover:bg-hover hover:text-ink",
              )
            }
          >
            <Icon className="size-4" />
            {label}
          </NavLink>
        ))}
          </div>
        ))}
      </nav>
      <div className="space-y-3 border-t border-line p-4 text-xs text-muted">
        <button className="btn-ghost w-full" disabled={running || runNow.isPending} onClick={() => runNow.mutate()}>
          <RefreshCw className={cn("size-3.5", running && "animate-spin")} />
          {running ? "Refreshing…" : "Refresh now"}
        </button>
        <div className="space-y-1">
          <div>Last run: {lastAgg ? timeAgo(lastAgg.finished ?? lastAgg.started) : "never"}</div>
          {cfg.data && (
            <div title={`Model: ${cfg.data.aiModel}`}>
              AI: {cfg.data.aiProvider === "none" ? "off" : `${cfg.data.aiProvider} · ${cfg.data.aiModel}`}
            </div>
          )}
          {cfg.data && <div>Slack: {cfg.data.slack ? "connected" : "not configured"}</div>}
          {usage.data && (
            <NavLink to="/settings" className="block hover:text-accent" title="AI spend (estimated)">
              AI spend: {fmtUSD(usage.data.today.costUsd)} today · {fmtUSD(usage.data.total.costUsd)} / 30d
            </NavLink>
          )}
        </div>
        <div className="flex items-center justify-between">
          <span className="truncate" title={me.data?.name}>
            {me.data?.name ?? ""}
          </span>
          <button
            className="rounded p-1.5 hover:bg-hover hover:text-ink"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-label="Toggle theme"
          >
            {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="flex h-full">
      <aside className="hidden w-60 shrink-0 border-r border-line bg-panel md:block">{sidebar}</aside>
      {open && (
        <div className="fixed inset-0 z-40 md:hidden" onClick={() => setOpen(false)}>
          <div className="absolute inset-0 bg-black/50" />
          <aside className="absolute inset-y-0 left-0 w-64 border-r border-line bg-panel" onClick={(e) => e.stopPropagation()}>
            <button className="absolute right-2 top-3 p-1.5 text-muted" onClick={() => setOpen(false)} aria-label="Close menu">
              <X className="size-4" />
            </button>
            {sidebar}
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-line bg-panel px-4 py-2.5 md:hidden">
          <button onClick={() => setOpen(true)} aria-label="Open menu" className="p-1 text-ink-2">
            <Menu className="size-5" />
          </button>
          <span className="font-semibold">CyNewsFeed</span>
        </header>
        <main className="scroll-thin min-w-0 flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
