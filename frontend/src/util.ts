import type { Severity, Tags } from "./api";

export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

export function timeAgo(iso?: string): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (!t || t < 0) return "never";
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(iso).toLocaleDateString();
}

export function fmtDateTime(iso?: string): string {
  if (!iso) return "";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function fmtDuration(startIso: string, endIso?: string): string {
  if (!endIso) return "…";
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime();
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  return s < 60 ? `${s.toFixed(1)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

export function fmtNum(n: number): string {
  return n >= 1_000_000 ? `${(n / 1e6).toFixed(1)}M` : n >= 10_000 ? `${Math.round(n / 1000)}k` : n.toLocaleString();
}

/** Tailwind classes for the severity ramp (bg dot / text). */
export const sevDot: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export const sevVar: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export function tagGroups(t: Tags): { kind: string; label: string; values: string[] }[] {
  return [
    { kind: "cve", label: "CVEs", values: t.cves ?? [] },
    { kind: "actor", label: "Threat actors", values: t.threatActors ?? [] },
    { kind: "malware", label: "Malware", values: t.malware ?? [] },
    { kind: "vendor", label: "Vendors", values: t.vendors ?? [] },
    { kind: "product", label: "Products", values: t.products ?? [] },
    { kind: "topic", label: "Topics", values: t.topics ?? [] },
    ...(["ip", "domain", "url", "sha256", "sha1", "md5", "email"] as const).map((k) => ({
      kind: k,
      label: { ip: "IP addresses", domain: "Domains", url: "URLs", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5", email: "Emails" }[k],
      values: (t.iocs ?? []).filter((i) => i.type === k).map((i) => i.value),
    })),
  ].filter((g) => g.values.length > 0);
}

export function hostname(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

export const IOC_TYPES = new Set(["ip", "domain", "url", "md5", "sha1", "sha256", "email"]);

/** Defang an indicator for safe display/copy. */
export function defang(type: string, v: string): string {
  if (!IOC_TYPES.has(type) || ["md5", "sha1", "sha256"].includes(type)) return v;
  let s = v.replace(/^https:\/\//i, "hxxps://").replace(/^http:\/\//i, "hxxp://");
  const i = s.lastIndexOf(".");
  if (i > 0) s = s.slice(0, i) + "[.]" + s.slice(i + 1);
  return s.replace("@", "[@]");
}

export function fmtUSD(n?: number): string {
  if (!n) return "$0.00";
  if (n < 0.01) return "<$0.01";
  return "$" + n.toFixed(n < 10 ? 2 : 0);
}

export const CATEGORY_LABEL: Record<string, string> = {
  news: "News", research: "Research", advisory: "Advisories", podcast: "Podcasts", "ai-security": "AI security",
};
export const catLabel = (c: string) => CATEGORY_LABEL[c] ?? c;
