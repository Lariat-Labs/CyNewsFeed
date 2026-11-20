import { useEffect, type ReactNode } from "react";
import { Loader2, X } from "lucide-react";
import type { Severity } from "../api";
import { cn, sevDot } from "../util";

export function SeverityBadge({ severity, compact }: { severity: Severity; compact?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border border-line bg-panel-2 font-medium capitalize text-ink-2",
        compact ? "px-1.5 py-0 text-[11px]" : "px-2 py-0.5 text-xs",
      )}
      title={`Severity: ${severity}`}
    >
      <span className={cn("size-2 rounded-full", sevDot[severity])} />
      {severity}
    </span>
  );
}

const chipTone: Record<string, string> = {
  cve: "text-accent border-accent/30 font-mono",
  actor: "text-ink border-line",
  malware: "text-ink border-line",
  default: "text-ink-2 border-line",
};

export function Chip({
  children,
  kind = "default",
  onClick,
  active,
  title,
}: {
  children: ReactNode;
  kind?: string;
  onClick?: () => void;
  active?: boolean;
  title?: string;
}) {
  const cls = cn(
    "inline-flex max-w-full items-center truncate rounded-md border bg-panel-2 px-1.5 py-0.5 text-[11px] leading-4",
    chipTone[kind] ?? chipTone.default,
    onClick && "cursor-pointer hover:border-accent hover:text-accent",
    active && "border-accent text-accent",
  );
  return onClick ? (
    <button
      type="button"
      className={cls}
      title={title}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
    >
      {children}
    </button>
  ) : (
    <span className={cls} title={title}>
      {children}
    </span>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("size-4 animate-spin text-muted", className)} />;
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-16 text-center">
      {icon && <div className="text-muted">{icon}</div>}
      <p className="font-medium text-ink">{title}</p>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger">
      {error instanceof Error ? error.message : String(error)}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-line transition",
        checked ? "bg-accent" : "bg-panel-2",
      )}
    >
      <span className={cn("inline-block size-3.5 rounded-full bg-white shadow transition", checked ? "translate-x-4.5" : "translate-x-0.5")} />
    </button>
  );
}

export function Modal({
  open,
  onClose,
  title,
  children,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-[6vh] backdrop-blur-sm" onMouseDown={onClose}>
      <div
        className={cn("card w-full shadow-2xl", wide ? "max-w-4xl" : "max-w-xl")}
        onMouseDown={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="flex items-center justify-between border-b border-line px-5 py-3">
          <h2 className="font-semibold">{title}</h2>
          <button className="rounded p-1 text-muted hover:bg-hover hover:text-ink" onClick={onClose} aria-label="Close">
            <X className="size-4" />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="card px-4 py-3">
      <div className="text-xs font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Segmented<T extends string | number>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="inline-flex rounded-md border border-line bg-panel p-0.5">
      {options.map((o) => (
        <button
          key={String(o.value)}
          type="button"
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded px-2.5 py-1 text-xs font-medium transition",
            o.value === value ? "bg-panel-2 text-ink shadow-sm" : "text-muted hover:text-ink",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
