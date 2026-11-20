import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { AlertTriangle, Bot, ChevronRight, Loader2, MessageSquarePlus, Pencil, Search, Send, Sparkles, Trash2, Wrench } from "lucide-react";
import { chatApi, streamMessage, type Brief, type ChatMessage, type ToolStep } from "../api";
import { ErrorBox, Spinner } from "../components/ui";
import { cn, defang, fmtUSD, timeAgo } from "../util";

const SUGGESTIONS = [
  "What were the most critical vulnerabilities this week, and which are exploited?",
  "Which threat actors were most active in the last 7 days?",
  "Summarise everything about ransomware attacks on healthcare this month.",
  "What alerts fired in the last 3 days and why?",
];

interface Live {
  user: ChatMessage;
  text: string;
  steps: ToolStep[];
}

export default function ChatPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const qc = useQueryClient();
  const chats = useQuery({ queryKey: ["chats"], queryFn: chatApi.list });
  const status = useQuery({ queryKey: ["agent"], queryFn: chatApi.status, staleTime: 60_000 });
  const thread = useQuery({
    queryKey: ["chat", id],
    queryFn: () => chatApi.get(id!),
    enabled: !!id,
    // A reply can keep running server-side after navigating away; poll until done.
    refetchInterval: (q) => (q.state.data?.busy ? 3000 : false),
  });
  const [live, setLive] = useState<Live | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const scroller = useRef<HTMLDivElement>(null);
  const started = useRef<string | null>(null);

  const send = useCallback(
    async (chatId: string, body: { text?: string; brief?: Brief }) => {
      setError(null);
      const display = body.text ?? (body.brief ? `Brief: ${body.brief.value}` : "");
      setLive({
        user: { seq: -1, role: "user", text: display, createdAt: new Date().toISOString(), context: body.brief ? { entityType: body.brief.type, entityValue: body.brief.value } : undefined },
        text: "",
        steps: [],
      });
      try {
        await streamMessage(chatId, body, (e) => {
          if (e.type === "text") setLive((l) => (l ? { ...l, text: l.text + e.delta } : l));
          else if (e.type === "step_start") setLive((l) => (l ? { ...l, steps: [...l.steps, e.step] } : l));
          else if (e.type === "step_end") setLive((l) => (l ? { ...l, steps: l.steps.map((s) => (s.id === e.step.id ? e.step : s)) } : l));
          else if (e.type === "error") setError(e.error);
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
      await qc.invalidateQueries({ queryKey: ["chat", chatId] });
      qc.invalidateQueries({ queryKey: ["chats"] });
      setLive(null);
    },
    [qc],
  );

  // A highlight click navigates here with a pending brief/question.
  useEffect(() => {
    const pending = (location.state as { pending?: { brief?: Brief; text?: string } } | null)?.pending;
    if (id && pending && started.current !== id) {
      started.current = id;
      navigate(location.pathname, { replace: true, state: null });
      send(id, pending);
    }
  }, [id, location, navigate, send]);

  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight, behavior: "smooth" });
  }, [live?.text, live?.steps.length, thread.data?.messages.length]);

  const create = useMutation({
    mutationFn: (text: string) => chatApi.create().then((c) => ({ c, text })),
    onSuccess: ({ c, text }) => {
      qc.invalidateQueries({ queryKey: ["chats"] });
      started.current = c.id;
      navigate(`/chat/${c.id}`);
      send(c.id, { text });
    },
  });
  const remove = useMutation({
    mutationFn: chatApi.remove,
    onSuccess: (_, removed) => {
      qc.invalidateQueries({ queryKey: ["chats"] });
      if (removed === id) navigate("/chat");
    },
  });
  const rename = useMutation({
    mutationFn: ({ cid, title }: { cid: string; title: string }) => chatApi.rename(cid, title),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["chats"] }),
  });

  const submit = (text: string) => {
    if (!text.trim() || live) return;
    if (id) send(id, { text: text.trim() });
    else create.mutate(text.trim());
  };

  const messages = thread.data?.messages ?? [];
  const busy = !!live || thread.data?.busy;
  const filtered = (chats.data ?? []).filter((c) => c.title.toLowerCase().includes(filter.toLowerCase()));

  if (status.data && !status.data.enabled) {
    return (
      <div className="mx-auto max-w-xl p-10 text-center">
        <Bot className="mx-auto size-10 text-muted" />
        <h1 className="mt-3 text-lg font-semibold">The agent is not enabled</h1>
        <p className="mt-1 text-sm text-muted">{status.data.reason}</p>
      </div>
    );
  }

  return (
    <div className="flex h-full">
      {/* history */}
      <aside className={cn("w-72 shrink-0 flex-col border-r border-line bg-panel", id ? "hidden lg:flex" : "flex w-full lg:w-72")}>
        <div className="space-y-2 border-b border-line p-3">
          <Link to="/chat" className="btn-primary w-full">
            <MessageSquarePlus className="size-4" /> New chat
          </Link>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted" />
            <input className="input py-1.5 pl-8 text-xs" placeholder="Search chats" value={filter} onChange={(e) => setFilter(e.target.value)} />
          </div>
        </div>
        <nav className="scroll-thin flex-1 overflow-y-auto p-2">
          {chats.isLoading && <Spinner className="m-3" />}
          {filtered.map((c) => (
            <div key={c.id} className={cn("group flex items-center rounded-md", c.id === id ? "bg-panel-2" : "hover:bg-hover")}>
              <Link to={`/chat/${c.id}`} className="min-w-0 flex-1 px-3 py-2">
                <div className={cn("truncate text-sm", c.id === id ? "font-medium text-ink" : "text-ink-2")}>{c.title}</div>
                <div className="text-[11px] text-muted">
                  {timeAgo(c.updatedAt)} · {Math.ceil(c.messages / 2)} question{c.messages > 2 ? "s" : ""}
                </div>
              </Link>
              <button
                className="hidden p-1.5 text-muted hover:text-ink group-hover:block"
                aria-label="Rename chat"
                onClick={() => {
                  const t = prompt("Rename chat", c.title);
                  if (t?.trim()) rename.mutate({ cid: c.id, title: t.trim() });
                }}
              >
                <Pencil className="size-3.5" />
              </button>
              <button className="mr-1 hidden p-1.5 text-muted hover:text-danger group-hover:block" aria-label="Delete chat" onClick={() => confirm(`Delete “${c.title}”?`) && remove.mutate(c.id)}>
                <Trash2 className="size-3.5" />
              </button>
            </div>
          ))}
          {chats.data?.length === 0 && <p className="p-3 text-xs text-muted">No chats yet. Ask a question, or click a highlight on any story.</p>}
        </nav>
      </aside>

      {/* thread */}
      <section className={cn("min-w-0 flex-1 flex-col", id ? "flex" : "hidden lg:flex")}>
        <div ref={scroller} className="scroll-thin flex-1 overflow-y-auto">
          <div className="mx-auto max-w-3xl space-y-6 px-4 py-6">
            {!id && !live && (
              <div className="pt-[8vh] text-center">
                <Sparkles className="mx-auto size-9 text-accent" />
                <h1 className="mt-3 text-xl font-semibold">Ask about your threat landscape</h1>
                <p className="mx-auto mt-1 max-w-md text-sm text-muted">
                  The agent searches your stored stories, alerts and digests{status.data?.tools?.includes("lookup_cve") ? ", checks NVD and CISA KEV" : ""}
                  {status.data?.tools?.includes("ioc_reputation") ? ", looks up IOC reputation" : ""} and cites its sources.
                </p>
                <div className="mx-auto mt-6 grid max-w-2xl gap-2 sm:grid-cols-2">
                  {SUGGESTIONS.map((s) => (
                    <button key={s} className="card px-4 py-3 text-left text-sm text-ink-2 transition hover:border-accent hover:text-ink" onClick={() => submit(s)}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {id && thread.isLoading && <Spinner />}
            {messages.map((m) => (m.role === "user" ? <UserBubble key={m.seq} m={m} /> : <AssistantMessage key={m.seq} text={m.text} steps={m.steps ?? []} error={m.error} model={m.model ? `${m.model}${m.usage ? ` · ${fmtUSD(m.usage.costUsd)}` : ""}` : undefined} />))}
            {live && (
              <>
                <UserBubble m={live.user} />
                <AssistantMessage text={live.text} steps={live.steps} streaming />
              </>
            )}
            {!live && thread.data?.busy && (
              <div className="flex items-center gap-2 text-sm text-muted">
                <Loader2 className="size-4 animate-spin" /> Still answering in the background…
              </div>
            )}
            {error && <ErrorBox error={error} />}
          </div>
        </div>
        <Composer onSubmit={submit} disabled={!!busy} model={status.data?.model} />
      </section>
    </div>
  );
}

function UserBubble({ m }: { m: ChatMessage }) {
  const [expanded, setExpanded] = useState(false);
  const isBrief = !!m.context?.entityValue && m.text.length > 160;
  return (
    <div className="flex flex-col items-end gap-1">
      {m.context?.entityValue && (
        <div className="text-[11px] text-muted">
          from highlight · <span className="font-mono">{defang(m.context.entityType ?? "", m.context.entityValue)}</span>
          {m.context.itemId && (
            <>
              {" "}
              in{" "}
              <Link to={`/?item=${m.context.itemId}`} className="hover:text-accent">
                {m.context.itemTitle ?? "story"}
              </Link>
            </>
          )}
        </div>
      )}
      <div className="max-w-[85%] whitespace-pre-wrap rounded-2xl rounded-br-md bg-accent/15 px-4 py-2.5 text-sm text-ink">
        {isBrief && !expanded ? (
          <>
            {m.text.split("\n")[0]}{" "}
            <button className="text-xs text-muted hover:text-accent" onClick={() => setExpanded(true)}>
              show full prompt
            </button>
          </>
        ) : (
          m.text
        )}
      </div>
    </div>
  );
}

/** Pulls {id,title} pairs out of tool results so citations can show titles. */
function citationTitles(steps: ToolStep[]): Record<string, string> {
  const map: Record<string, string> = {};
  const re = /"id":"([a-f0-9]{6,})","title":"((?:[^"\\]|\\.)*)"/g;
  for (const s of steps) {
    let m;
    while ((m = re.exec(s.result ?? ""))) {
      try {
        map[m[1]] = JSON.parse(`"${m[2]}"`);
      } catch {
        map[m[1]] = m[2];
      }
    }
  }
  return map;
}

function AssistantMessage({ text, steps, streaming, error, model }: { text: string; steps: ToolStep[]; streaming?: boolean; error?: string; model?: string }) {
  const titles = useMemo(() => citationTitles(steps), [steps]);
  // Number citations in order of first appearance and turn them into links.
  const { md, order } = useMemo(() => {
    const order: string[] = [];
    const md = text.replace(/\[\[story:([A-Za-z0-9]+)\]\]/g, (_, sid: string) => {
      let n = order.indexOf(sid);
      if (n < 0) {
        order.push(sid);
        n = order.length - 1;
      }
      return `[${n + 1}](/?item=${sid} "cite")`;
    });
    return { md, order };
  }, [text]);

  return (
    <div className="flex gap-3">
      <div className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full bg-panel-2 text-accent">
        <Bot className="size-4" />
      </div>
      <div className="min-w-0 flex-1">
        {steps.length > 0 && <Steps steps={steps} live={streaming} />}
        {text ? (
          <div className="prose-chat text-[15px] leading-relaxed text-ink">
            <ReactMarkdown
              remarkPlugins={[[remarkGfm, { singleTilde: false }]]}
              components={{
                a: ({ href, title, children }) => {
                  if (title === "cite" && href?.startsWith("/?item=")) {
                    const sid = href.slice(7);
                    return (
                      <Link
                        to={href}
                        title={titles[sid] ?? "Open story"}
                        className="mx-0.5 inline-flex h-4 min-w-4 -translate-y-0.5 items-center justify-center rounded bg-accent/15 px-1 align-middle text-[10px] font-semibold text-accent no-underline hover:bg-accent hover:text-accent-ink"
                      >
                        {children}
                      </Link>
                    );
                  }
                  return (
                    <a href={href} target="_blank" rel="noreferrer noopener" className="text-accent underline">
                      {children}
                    </a>
                  );
                },
              }}
            >
              {md}
            </ReactMarkdown>
            {streaming && <span className="ml-0.5 inline-block h-4 w-1.5 animate-pulse bg-accent align-middle" />}
          </div>
        ) : streaming ? (
          <div className="flex items-center gap-2 text-sm text-muted">
            <Loader2 className="size-4 animate-spin" /> {steps.length ? "Reading results…" : "Thinking…"}
          </div>
        ) : null}
        {error && (
          <div className="mt-2 flex items-start gap-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0" /> {error}
          </div>
        )}
        {!streaming && order.length > 0 && (
          <div className="mt-3 border-t border-line pt-2">
            <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted">Sources</div>
            <ol className="space-y-0.5 text-xs">
              {order.map((sid, i) => (
                <li key={sid} className="flex gap-1.5">
                  <span className="w-4 shrink-0 text-right text-muted">{i + 1}.</span>
                  <Link to={`/?item=${sid}`} className="truncate text-ink-2 hover:text-accent">
                    {titles[sid] ?? sid}
                  </Link>
                </li>
              ))}
            </ol>
          </div>
        )}
        {!streaming && model && <div className="mt-1 text-[11px] text-muted">{model}</div>}
      </div>
    </div>
  );
}

const TOOL_LABEL: Record<string, string> = {
  search_stories: "Search stories",
  get_story: "Read story",
  entity_timeline: "Entity timeline",
  top_entities: "Top entities",
  list_alerts: "Alerts",
  get_digest: "Digest",
  list_sources: "Sources",
  lookup_cve: "NVD / KEV lookup",
  ioc_reputation: "IOC reputation",
};

function Steps({ steps, live }: { steps: ToolStep[]; live?: boolean }) {
  const [open, setOpen] = useState(false);
  const running = steps.filter((s) => !s.summary).length;
  return (
    <div className="mb-2 rounded-lg border border-line bg-panel">
      <button className="flex w-full items-center gap-2 px-3 py-1.5 text-xs text-muted hover:text-ink" onClick={() => setOpen((o) => !o)}>
        <ChevronRight className={cn("size-3.5 transition", open && "rotate-90")} />
        <Wrench className="size-3.5" />
        {live && running > 0 ? `Working… ${steps.length - running}/${steps.length} lookups done` : `Used ${steps.length} lookup${steps.length > 1 ? "s" : ""}`}
        {live && running > 0 && <Loader2 className="ml-auto size-3.5 animate-spin" />}
      </button>
      {(open || (live && running > 0)) && (
        <ul className="space-y-1 border-t border-line px-3 py-2">
          {steps.map((s) => (
            <li key={s.id} className="text-xs">
              <div className="flex items-start gap-2">
                {s.summary ? (
                  <span className={cn("mt-0.5 size-1.5 shrink-0 rounded-full", s.isError ? "bg-danger" : "bg-ok")} />
                ) : (
                  <Loader2 className="mt-0.5 size-3 shrink-0 animate-spin text-muted" />
                )}
                <span className="font-medium text-ink-2">{TOOL_LABEL[s.name] ?? s.name}</span>
                <span className={cn("min-w-0 flex-1 truncate", s.isError ? "text-danger" : "text-muted")}>{s.summary ?? s.input}</span>
              </div>
              {open && <code className="ml-3.5 mt-0.5 block truncate font-mono text-[10px] text-muted">{s.input}</code>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Composer({ onSubmit, disabled, model }: { onSubmit: (t: string) => void; disabled: boolean; model?: string }) {
  const [text, setText] = useState("");
  const ref = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = Math.min(200, el.scrollHeight) + "px";
  }, [text]);
  const go = () => {
    if (!text.trim() || disabled) return;
    onSubmit(text);
    setText("");
  };
  return (
    <div className="border-t border-line bg-panel px-4 py-3">
      <div className="mx-auto max-w-3xl">
        <div className="flex items-end gap-2 rounded-xl border border-line bg-panel-2 p-2 focus-within:border-accent">
          <textarea
            ref={ref}
            rows={1}
            className="max-h-48 flex-1 resize-none bg-transparent px-2 py-1.5 text-sm text-ink outline-none placeholder:text-muted"
            placeholder="Ask about a CVE, actor, IOC, vendor, or anything in your feed…"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                go();
              }
            }}
          />
          <button className="btn-primary px-2.5" onClick={go} disabled={disabled || !text.trim()} aria-label="Send">
            {disabled ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
          </button>
        </div>
        <div className="mt-1 text-center text-[11px] text-muted">
          Read-only agent{model ? ` · ${model}` : ""} · answers can be wrong; check the cited sources · Enter to send, Shift+Enter for a new line
        </div>
      </div>
    </div>
  );
}
