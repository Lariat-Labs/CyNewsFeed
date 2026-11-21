// Typed client for the CyNewsFeed REST API.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Category = "news" | "research" | "advisory" | "podcast" | "ai-security";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const CATEGORIES: Category[] = ["news", "research", "advisory", "ai-security", "podcast"];

export interface Tags {
  cves: string[] | null;
  threatActors: string[] | null;
  malware: string[] | null;
  vendors: string[] | null;
  products: string[] | null;
  topics: string[] | null;
  iocs?: IOC[] | null;
  attack?: Technique[] | null;
  atlas?: Technique[] | null;
  owaspLlm?: string[] | null;
}

export interface RuleHit {
  ruleId: string;
  ruleName: string;
  score: number;
  reason?: string;
  matchedKeywords?: string[];
}

export interface Item {
  id: string;
  feedId: string;
  feedName: string;
  category: Category;
  title: string;
  link: string;
  published: string;
  fetched: string;
  author?: string;
  snippet?: string;
  tldr?: string;
  bullets?: string[];
  whyItMatters?: string;
  keyDetails?: KeyDetail[];
  detections?: Detection[];
  severity: Severity;
  tags: Tags;
  ruleHits?: RuleHit[];
  audioUrl?: string;
  imageUrl?: string;
  duration?: string;
  aiStatus: "pending" | "done" | "error" | "skipped";
  aiModel?: string;
  aiError?: string;
  read: boolean;
  starred: boolean;
  content?: string;
}

export interface Feed {
  id: string;
  name: string;
  url: string;
  siteUrl?: string;
  kind: "rss" | "cisa-kev" | "osv-watch";
  category: Category;
  enabled: boolean;
  weight: number;
  lastFetched?: string;
  lastStatus?: string;
  lastError?: string;
  lastNewItems: number;
  itemCount: number;
}

export type RuleMode = "keyword" | "semantic" | "hybrid";

export interface Rule {
  id: string;
  name: string;
  description: string;
  keywords: string[];
  regexes: string[];
  mode: RuleMode;
  threshold: number;
  minSeverity?: Severity | "";
  slackWebhook?: string;
  enabled: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface Alert {
  id: string;
  ruleId: string;
  ruleName: string;
  itemId: string;
  title: string;
  link: string;
  feedName: string;
  severity: Severity;
  score: number;
  reason?: string;
  matchedKeywords?: string[];
  createdAt: string;
  notified: boolean;
  notifyError?: string;
}

export interface FeedRunStat {
  feedId: string;
  status: string;
  new: number;
  seen: number;
  error?: string;
  durationMs: number;
}

export interface Run {
  id: string;
  kind: "aggregate" | "digest";
  trigger: string;
  started: string;
  finished?: string;
  status: "running" | "ok" | "error";
  error?: string;
  stats: {
    feeds: number;
    feedErrors: number;
    newItems: number;
    enriched: number;
    aiErrors: number;
    retried: number;
    alerts: number;
    purged: number;
    inputTokens: number;
    outputTokens: number;
    cachedTokens: number;
    costUsd?: number;
    perFeed?: FeedRunStat[];
  };
}

export interface Digest {
  date: string;
  headline: string;
  overview: string;
  sections: { title: string; items: { itemId: string; line: string; title?: string; link?: string }[] }[];
  itemCount: number;
  model?: string;
  createdAt: string;
}

export interface Stats {
  total: number;
  ruleHits: number;
  bySeverity: Partial<Record<Severity, number>>;
  byCategory: Partial<Record<Category, number>>;
  byDay: { date: string; bySeverity: Partial<Record<Severity, number>> }[];
  top: Record<"cves" | "threatActors" | "malware" | "vendors" | "topics", { name: string; count: number }[]>;
}

export interface AppConfig {
  version?: string;
  aiProvider: string;
  aiModel: string;
  slack: boolean;
  fetchCron: string;
  digestCron: string;
  timezone: string;
  retentionDays: number;
  schedulerEnabled: boolean;
  defaultThreshold: number;
}

export interface TestResult {
  item: Item;
  score: number;
  reason?: string;
  keywords?: string[];
  wouldAlert: boolean;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  if (res.status === 401) {
    // Easy Auth session expired: bounce through the login flow.
    window.location.href = "/.auth/login/aad?post_login_redirect_uri=" + encodeURIComponent(location.pathname);
    throw new ApiError(401, "Not signed in");
  }
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, (data as { error?: string }).error ?? res.statusText);
  return data as T;
}

export interface ItemQuery {
  days?: number;
  category?: string;
  severity?: string;
  feed?: string;
  tag?: string;
  q?: string;
  rule?: string;
  hits?: boolean;
  starred?: boolean;
  unread?: boolean;
  limit?: number;
  offset?: number;
}

function qs(params: object): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "" && v !== false && v !== null) u.set(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : "";
}

export const api = {
  config: () => req<AppConfig>("GET", "/config"),
  me: () => req<{ name: string; authMode: string }>("GET", "/me"),
  items: (q: ItemQuery) => req<{ items: Item[]; total: number }>("GET", `/items${qs(q)}`),
  item: (id: string) => req<Item>("GET", `/items/${id}`),
  patchItem: (id: string, p: { read?: boolean; starred?: boolean }) => req<Item>("PATCH", `/items/${id}`, p),
  feeds: () => req<Feed[]>("GET", "/feeds"),
  createFeed: (f: Partial<Feed>) => req<Feed>("POST", "/feeds", f),
  updateFeed: (f: Feed) => req<Feed>("PUT", `/feeds/${f.id}`, f),
  deleteFeed: (id: string) => req<void>("DELETE", `/feeds/${id}`),
  testFeed: (f: Partial<Feed>) =>
    req<{ ok: boolean; error?: string; title?: string; itemCount?: number; preview?: { title: string; link: string; published: string; audio: boolean }[] }>(
      "POST",
      "/feeds/test",
      f,
    ),
  seedFeeds: () => req<{ added: number }>("POST", "/feeds/seed"),
  rules: () => req<Rule[]>("GET", "/rules"),
  createRule: (r: Partial<Rule>) => req<Rule>("POST", "/rules", r),
  updateRule: (r: Rule) => req<Rule>("PUT", `/rules/${r.id}`, r),
  deleteRule: (id: string) => req<void>("DELETE", `/rules/${id}`),
  testRule: (r: Partial<Rule> & { days?: number }) => req<{ results: TestResult[] }>("POST", "/rules/test", r),
  alerts: (days = 7) => req<Alert[]>("GET", `/alerts?days=${days}`),
  digests: () => req<Digest[]>("GET", "/digests"),
  digest: (date: string) => req<Digest>("GET", `/digests/${date}`),
  runDigest: () => req<Digest>("POST", "/digests/run"),
  runs: () => req<{ runs: Run[]; running: boolean }>("GET", "/runs"),
  runNow: () => req<{ status: string }>("POST", "/runs"),
  stats: (days = 7) => req<Stats>("GET", `/stats?days=${days}`),
  aiSettings: () => req<AISettings>("GET", "/settings/ai"),
  saveAISettings: (s: Pick<AISettings, "autoSummarize" | "scheduledDigestAI">) => req<AISettings>("PUT", "/settings/ai", s),
  summarize: (id: string) => req<{ items: Item[]; usage: TokenUsage }>("POST", `/items/${id}/summarize`),
  summarizeMany: (ids: string[]) => req<{ items: Item[]; usage: TokenUsage }>("POST", "/items/summarize", { ids }),
  usage: (days = 30) => req<UsageReport>("GET", `/usage?days=${days}`),
};

// ---------------- Agent / chat ----------------

export interface IOC {
  type: "ip" | "domain" | "url" | "md5" | "sha1" | "sha256" | "email";
  value: string;
}

export interface KeyDetail {
  text: string;
  kind: "deadline" | "exploitation" | "impact" | "action" | "scope" | "other";
  reason: string;
}

export interface Chat {
  id: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  messages: number;
  provider?: string;
}

export interface ToolStep {
  id: string;
  name: string;
  input: string;
  summary?: string;
  result?: string;
  isError?: boolean;
}

export interface ChatContext {
  entityType?: string;
  entityValue?: string;
  itemId?: string;
  itemTitle?: string;
}

export interface ChatMessage {
  seq: number;
  role: "user" | "assistant";
  text: string;
  steps?: ToolStep[];
  context?: ChatContext;
  model?: string;
  error?: string;
  usage?: TokenUsage;
  createdAt: string;
}

export interface TokenUsage {
  model?: string;
  input: number;
  output: number;
  cached: number;
  costUsd: number;
}

export interface AISettings {
  autoSummarize: boolean;
  scheduledDigestAI: boolean;
  provider?: string;
  summaryModel?: string;
  digestModel?: string;
  chatModel?: string;
}

interface UsageAgg {
  costUsd: number;
  input: number;
  output: number;
  calls: number;
}

export interface UsageReport {
  days: number;
  total: UsageAgg;
  today: UsageAgg;
  byKind: Record<string, UsageAgg>;
  byDay: Record<string, UsageAgg>;
  recent: (TokenUsage & { id: string; kind: string; ref?: string; user?: string; at: string; items?: number })[];
}

export interface Brief {
  type: string;
  value: string;
  itemId?: string;
  reason?: string;
}

export type AgentEvent =
  | { type: "start"; chat: Chat }
  | { type: "text"; delta: string }
  | { type: "step_start"; step: ToolStep }
  | { type: "step_end"; step: ToolStep }
  | { type: "done"; message: ChatMessage }
  | { type: "error"; error: string };

export const chatApi = {
  status: () => req<{ enabled: boolean; reason?: string; provider?: string; model?: string; tools?: string[] }>("GET", "/agent"),
  prompts: () => req<{ prompts: Record<string, string>; defaults: Record<string, string> }>("GET", "/agent/prompts"),
  savePrompts: (p: Record<string, string>) => req<{ prompts: Record<string, string>; defaults: Record<string, string> }>("PUT", "/agent/prompts", p),
  list: () => req<Chat[]>("GET", "/chats"),
  create: (title?: string) => req<Chat>("POST", "/chats", { title }),
  get: (id: string) => req<{ chat: Chat; messages: ChatMessage[]; busy: boolean }>("GET", `/chats/${id}`),
  rename: (id: string, title: string) => req<Chat>("PATCH", `/chats/${id}`, { title }),
  remove: (id: string) => req<void>("DELETE", `/chats/${id}`),
};

/** Sends a message and streams agent events (Server-Sent Events over POST). */
export async function streamMessage(
  chatId: string,
  body: { text?: string; brief?: Brief },
  onEvent: (e: AgentEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch(`/api/chats/${chatId}/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
    body: JSON.stringify(body),
    credentials: "same-origin",
    signal,
  });
  if (!res.ok || !res.body) {
    const data = await res.json().catch(() => ({}));
    throw new ApiError(res.status, (data as { error?: string }).error ?? res.statusText);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const chunk = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      for (const line of chunk.split("\n")) {
        if (line.startsWith("data: ")) {
          try {
            onEvent(JSON.parse(line.slice(6)) as AgentEvent);
          } catch {
            /* ignore malformed chunk */
          }
        }
      }
    }
  }
}

// ---------------- Intel: detections, IOCs, events, trends, frameworks, AI security, reports ----------------

export interface Technique {
  id: string;
  name?: string;
  tactic?: string;
}

export interface Detection {
  format: "kql" | "spl" | "sigma" | "yara";
  title: string;
  description?: string;
  query: string;
  confidence?: string;
  notes?: string;
  valid: boolean;
  issue?: string;
}

export interface StoryRef {
  id: string;
  title: string;
  link: string;
  source: string;
  published: string;
}

export interface Indicator {
  type: string;
  value: string;
  defanged: string;
  firstSeen: string;
  lastSeen: string;
  severity: Severity;
  stories: StoryRef[];
  malware?: string[];
  actors?: string[];
  cves?: string[];
}

export interface EventItem {
  id: string;
  title: string;
  source: string;
  published: string;
  severity: Severity;
  tldr?: string;
}

export interface NewsEvent {
  id: string;
  title: string;
  severity: Severity;
  sources: number;
  stories: number;
  firstSeen: string;
  lastSeen: string;
  cves?: string[];
  actors?: string[];
  malware?: string[];
  products?: string[];
  items: EventItem[];
  score: number;
}

export interface Trend {
  kind: string;
  name: string;
  recent: number;
  baseline: number;
  ratio: number;
  new: boolean;
  daily: number[];
}

export interface TechniqueCount {
  id: string;
  name: string;
  tactic: string;
  count: number;
  itemIds: string[];
}

export interface FrameworkReport {
  days: number;
  stories: number;
  summarised: number;
  attackTactics: string[];
  atlasTactics: string[];
  owaspNames: Record<string, string>;
  coverage: {
    attack: Record<string, TechniqueCount[]>;
    atlas: Record<string, TechniqueCount[]>;
    owasp: Record<string, number>;
    owaspItems: Record<string, string[]>;
    taggedAttack: number;
    taggedAi: number;
  };
}

export interface InventoryPackage {
  ecosystem: string;
  name: string;
  version?: string;
}

export interface Exposure {
  package: InventoryPackage;
  advisories: { id: string; summary: string; severity: Severity; fixed?: string[]; published: string; aliases?: string[]; malicious?: boolean }[];
  error?: string;
}

export interface Report {
  id: string;
  title: string;
  periodStart: string;
  periodEnd: string;
  executiveSummary: string;
  keyRisks: { title: string; detail: string; recommendation: string }[];
  topEvents: { title: string; why: string; itemIds?: string[] }[];
  metrics: Record<string, number>;
  metricsNote?: string;
  recommendations: string[];
  model?: string;
  createdAt: string;
}

export interface Integrations {
  taxii: { enabled: boolean; auth: string; discovery: string; apiRoot: string; collections: { id: string; title: string; objectsUrl: string }[] };
  mcp: { enabled: boolean; auth: string; url: string };
  misp: { configured: boolean; url?: string };
}

export const intelApi = {
  detections: (id: string, formats?: string[]) => req<{ detections: Detection[]; usage: TokenUsage }>("POST", `/items/${id}/detections`, { formats }),
  iocs: (p: { days?: number; type?: string; min_severity?: string; q?: string }) =>
    req<{ indicators: Indicator[]; counts: Record<string, number>; total: number }>("GET", `/iocs${qs(p)}`),
  exportUrl: (p: { format: string; days?: number; type?: string; min_severity?: string; q?: string; items?: string; defang?: boolean }) => `/api/iocs/export${qs(p)}`,
  pushMISP: (p: { days?: number; minSeverity?: string; type?: string; itemIds?: string[] }) => req<{ eventId: string; attributes: number; url: string }>("POST", "/iocs/misp", p),
  events: (days = 7) => req<{ days: number; events: NewsEvent[] }>("GET", `/events?days=${days}`),
  trends: (days = 7) => req<{ recentDays: number; baselineDays: number; oldest: string; rising: Trend[] }>("GET", `/trends?days=${days}`),
  frameworks: (days = 30) => req<FrameworkReport>("GET", `/frameworks?days=${days}`),
  inventory: () => req<{ packages: InventoryPackage[]; ecosystems: string[] }>("GET", "/ai/inventory"),
  saveInventory: (packages: InventoryPackage[]) => req<{ packages: InventoryPackage[] }>("PUT", "/ai/inventory", { packages }),
  exposure: (refresh = false) => req<{ checkedAt: string; results: Exposure[] }>("GET", `/ai/exposure${refresh ? "?refresh=true" : ""}`),
  reports: () => req<Report[]>("GET", "/reports"),
  report: (id: string) => req<Report>("GET", `/reports/${id}`),
  generateWeekly: () => req<Report>("POST", "/reports/weekly"),
  integrations: () => req<Integrations>("GET", "/integrations"),
};
