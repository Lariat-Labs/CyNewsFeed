import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { Copy, Filter, MessageSquareText, Sparkles, X } from "lucide-react";
import { chatApi, type Brief, type Item } from "../api";
import { cn, defang, IOC_TYPES } from "../util";

/** Something in the text worth asking about. */
export interface Entity {
  type: string; // cve | actor | malware | vendor | product | topic | ip | domain | url | md5 | sha1 | sha256 | email | detail
  value: string;
  reason?: string; // key details only
  kind?: string; // key detail kind
}

const TYPE_LABEL: Record<string, string> = {
  cve: "Vulnerability", actor: "Threat actor", malware: "Malware / tool", vendor: "Vendor", product: "Product", topic: "Topic",
  ip: "IP address", domain: "Domain", url: "URL", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", email: "Email", detail: "Key detail",
  attack: "MITRE ATT&CK technique", atlas: "MITRE ATLAS technique", owasp: "OWASP LLM Top 10",
};

/** Visual style per entity class. Key details get a highlighter box. */
function markClass(e: Entity): string {
  if (e.type === "detail") return "rounded-[3px] bg-amber-300/20 px-0.5 ring-1 ring-amber-400/40 text-ink";
  if (IOC_TYPES.has(e.type)) return "rounded-[3px] bg-sev-high/15 px-0.5 font-mono text-[0.92em] text-ink";
  if (e.type === "cve") return "text-accent underline decoration-accent/50 decoration-1 underline-offset-2";
  if (e.type === "actor" || e.type === "malware") return "underline decoration-sev-critical/70 decoration-dotted decoration-2 underline-offset-2";
  return "underline decoration-muted/60 decoration-dotted underline-offset-2";
}

/** Builds the list of highlightable entities for a story. */
export function itemEntities(item: Item): Entity[] {
  const t = item.tags;
  const out: Entity[] = [];
  const push = (type: string, vals?: string[] | null) => vals?.forEach((value) => value && out.push({ type, value }));
  push("cve", t.cves);
  push("actor", t.threatActors);
  push("malware", t.malware);
  push("vendor", t.vendors);
  push("product", t.products);
  (t.iocs ?? []).forEach((i) => out.push({ type: i.type, value: i.value }));
  (item.keyDetails ?? []).forEach((k) => out.push({ type: "detail", value: k.text, reason: k.reason, kind: k.kind }));
  return out;
}

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Renders text with entities wrapped in clickable marks (longest match wins, no overlaps). */
export function HighlightedText({ text, entities, itemId, itemTitle }: { text: string; entities: Entity[]; itemId?: string; itemTitle?: string }) {
  const open = usePopover();
  const parts = useMemo(() => {
    if (!text || entities.length === 0) return [text];
    // Map each search form (incl. defanged IOC forms) back to its entity.
    const forms: { form: string; e: Entity }[] = [];
    for (const e of entities) {
      if (e.value.length < 2) continue;
      forms.push({ form: e.value, e });
      if (IOC_TYPES.has(e.type)) {
        const d = defang(e.type, e.value);
        if (d !== e.value) forms.push({ form: d, e });
      }
    }
    forms.sort((a, b) => b.form.length - a.form.length);
    const ranges: { s: number; end: number; e: Entity }[] = [];
    for (const { form, e } of forms) {
      const wordy = /^\w/.test(form) && /\w$/.test(form) && e.type !== "detail";
      const re = new RegExp((wordy ? "\\b" : "") + escapeRe(form) + (wordy ? "\\b" : ""), e.type === "detail" ? "g" : "gi");
      let m: RegExpExecArray | null;
      while ((m = re.exec(text))) {
        const s = m.index;
        const end = s + m[0].length;
        if (!ranges.some((r) => s < r.end && end > r.s)) ranges.push({ s, end, e });
        if (m[0].length === 0) re.lastIndex++;
      }
    }
    ranges.sort((a, b) => a.s - b.s);
    const out: ReactNode[] = [];
    let pos = 0;
    ranges.forEach((r, i) => {
      if (r.s > pos) out.push(text.slice(pos, r.s));
      const label = text.slice(r.s, r.end);
      out.push(
        <button
          key={i}
          type="button"
          className={cn("cursor-pointer transition hover:brightness-125 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent", markClass(r.e))}
          title={r.e.type === "detail" ? r.e.reason : `${TYPE_LABEL[r.e.type] ?? r.e.type}: ask the agent`}
          onClick={(ev) => {
            ev.stopPropagation();
            open(r.e, ev.currentTarget.getBoundingClientRect(), { itemId, itemTitle });
          }}
        >
          {label}
        </button>,
      );
      pos = r.end;
    });
    if (pos < text.length) out.push(text.slice(pos));
    return out;
  }, [text, entities, itemId, itemTitle, open]);
  return <>{parts}</>;
}

// ---------------- popover ----------------

interface PopoverState {
  entity: Entity;
  rect: DOMRect;
  itemId?: string;
  itemTitle?: string;
}

type OpenFn = (e: Entity, rect: DOMRect, ctx: { itemId?: string; itemTitle?: string }) => void;
const PopoverCtx = createContext<OpenFn>(() => {});
export const usePopover = () => useContext(PopoverCtx);

/** Starts an agent chat for a highlight and navigates to it. */
export function useAsk() {
  const navigate = useNavigate();
  return useMutation({
    mutationFn: async ({ brief, text }: { brief?: Brief; text?: string }) => {
      const chat = await chatApi.create(brief ? `Brief: ${brief.value}` : undefined);
      return { chat, brief, text };
    },
    onSuccess: ({ chat, brief, text }) => navigate(`/chat/${chat.id}`, { state: { pending: { brief, text } } }),
  });
}

export function HighlightProvider({ children, onFilter }: { children: ReactNode; onFilter?: (value: string) => void }) {
  const [state, setState] = useState<PopoverState | null>(null);
  const open = useCallback<OpenFn>((entity, rect, ctx) => setState({ entity, rect, ...ctx }), []);
  return (
    <PopoverCtx.Provider value={open}>
      {children}
      {state && <AskPopover state={state} onClose={() => setState(null)} onFilter={onFilter} />}
    </PopoverCtx.Provider>
  );
}

function AskPopover({ state, onClose, onFilter }: { state: PopoverState; onClose: () => void; onFilter?: (v: string) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [q, setQ] = useState("");
  const [pos, setPos] = useState({ top: 0, left: 0 });
  const [copied, setCopied] = useState(false);
  const ask = useAsk();
  const { entity: e } = state;
  const isIOC = IOC_TYPES.has(e.type);
  const shown = isIOC ? defang(e.type, e.value) : e.value;
  const brief: Brief = { type: e.type, value: e.value, itemId: state.itemId, reason: e.reason };

  useLayoutEffect(() => {
    const w = ref.current?.offsetWidth ?? 340;
    const h = ref.current?.offsetHeight ?? 200;
    let top = state.rect.bottom + 6;
    if (top + h > window.innerHeight - 8) top = Math.max(8, state.rect.top - h - 6);
    const left = Math.min(Math.max(8, state.rect.left), window.innerWidth - w - 8);
    setPos({ top, left });
  }, [state.rect]);

  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => ev.key === "Escape" && onClose();
    const onDown = (ev: MouseEvent) => ref.current && !ref.current.contains(ev.target as Node) && onClose();
    const onScroll = () => onClose();
    window.addEventListener("keydown", onKey);
    window.addEventListener("mousedown", onDown);
    window.addEventListener("scroll", onScroll, true);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("scroll", onScroll, true);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      role="dialog"
      aria-label={`Ask about ${shown}`}
      className="fixed z-50 w-[340px] max-w-[calc(100vw-16px)] rounded-xl border border-line bg-panel p-3 shadow-2xl"
      style={{ top: pos.top, left: pos.left }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[11px] font-medium uppercase tracking-wide text-muted">{TYPE_LABEL[e.type] ?? e.type}</div>
          <div className={cn("mt-0.5 break-words text-sm font-medium text-ink", isIOC && "font-mono text-[13px]")}>{shown}</div>
          {e.reason && <div className="mt-1 text-xs text-ink-2">{e.reason}</div>}
        </div>
        <button className="rounded p-1 text-muted hover:bg-hover hover:text-ink" onClick={onClose} aria-label="Close">
          <X className="size-3.5" />
        </button>
      </div>

      <button className="btn-primary mt-3 w-full" disabled={ask.isPending} onClick={() => ask.mutate({ brief })}>
        <Sparkles className="size-4" />
        {e.type === "detail" ? "Follow up on this" : isIOC ? "Investigate indicator" : "Analyst brief"}
      </button>

      <form
        className="mt-2 flex gap-1.5"
        onSubmit={(ev) => {
          ev.preventDefault();
          if (q.trim()) ask.mutate({ brief, text: q.trim() });
        }}
      >
        <input className="input py-1.5 text-xs" placeholder="Or ask your own question…" value={q} onChange={(ev) => setQ(ev.target.value)} autoFocus />
        <button className="btn-ghost shrink-0 px-2" type="submit" disabled={!q.trim() || ask.isPending} aria-label="Ask">
          <MessageSquareText className="size-4" />
        </button>
      </form>

      <div className="mt-2 flex gap-3 border-t border-line pt-2 text-xs text-muted">
        {onFilter && e.type !== "detail" && (
          <button
            className="inline-flex items-center gap-1 hover:text-accent"
            onClick={() => {
              onFilter(e.value);
              onClose();
            }}
          >
            <Filter className="size-3" /> Filter feed
          </button>
        )}
        <button
          className="inline-flex items-center gap-1 hover:text-accent"
          onClick={() => {
            navigator.clipboard?.writeText(shown).then(() => setCopied(true));
          }}
        >
          <Copy className="size-3" /> {copied ? "Copied" : isIOC ? "Copy (defanged)" : "Copy"}
        </button>
      </div>
      {ask.error && <div className="mt-2 text-xs text-danger">{ask.error.message}</div>}
    </div>
  );
}
