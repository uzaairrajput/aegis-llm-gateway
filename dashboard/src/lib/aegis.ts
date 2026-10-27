// Server-side client for the Aegis admin API. The admin token is read from a non-public env var,
// so it never reaches the browser: every request is made from Server Components or Server Actions.
import "server-only";

const BASE_URL = (process.env.AEGIS_URL ?? "http://localhost:8080").replace(/\/+$/, "");

export type Decision = "allowed" | "blocked" | "flagged";

export interface Stats {
  window_hours: number;
  requests: number;
  blocked: number;
  flagged: number;
  piiRedacted: number;
  tokens: number;
  inspectLatencyMs: { p50: number; p95: number; p99: number };
  reasons: { reason: string; count: number }[];
  byTenant: { tenant: string; requests: number; blocked: number; tokens: number }[];
  topRules: { rule: string; count: number }[];
}

export interface TimeseriesPoint {
  t: number;
  allowed: number;
  flagged: number;
  blocked: number;
}

export interface Timeseries {
  window_hours: number;
  bucket_ms: number;
  points: TimeseriesPoint[];
}

export interface Finding {
  detector: "injection" | "pii" | "topic" | "canary" | "model";
  rule: string;
  severity: "low" | "medium" | "high";
  score?: number;
  messageIndex?: number;
  excerpt?: string;
}

export interface AuditEvent {
  requestId: string;
  tenantId: string;
  ts: number;
  endpoint: string;
  model: string | null;
  decision: Decision;
  reason: string | null;
  status: number;
  stream: boolean;
  injectionScore: number;
  piiRedacted: number;
  findings: Finding[];
  inspectMs: number;
  upstreamMs: number | null;
  promptTokens: number;
  completionTokens: number;
}

export interface Tenant {
  id: string;
  name: string;
  policy: string;
  keyPrefix: string;
  createdAt: number;
  mode: "enforce" | "monitor" | null;
  monthTokens: number;
  monthlyTokenBudget: number | null;
  requestsPerMinute: number | null;
}

export type Role = "admin" | "analyst" | "viewer";

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
}

export type Result<T> = { ok: true; data: T } | { ok: false; status: number; error: string };

async function request<T>(path: string, init?: { method: "POST"; body: unknown }): Promise<Result<T>> {
  const token = process.env.AEGIS_ADMIN_TOKEN;
  if (!token) return { ok: false, status: 0, error: "AEGIS_ADMIN_TOKEN is not set for the dashboard." };
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      method: init?.method ?? "GET",
      headers: { authorization: `Bearer ${token}`, ...(init ? { "content-type": "application/json" } : {}) },
      body: init ? JSON.stringify(init.body) : undefined,
    });
    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as { error?: { message?: string } } | null;
      return { ok: false, status: res.status, error: body?.error?.message ?? res.statusText };
    }
    return { ok: true, data: (await res.json()) as T };
  } catch {
    return { ok: false, status: 0, error: `Could not reach the Aegis gateway at ${BASE_URL}.` };
  }
}

const get = <T>(path: string) => request<T>(path);

export const verifyCredentials = (email: string, password: string, clientIp?: string) =>
  request<{ user: User }>("/admin/auth/login", { method: "POST", body: { email, password, clientIp } });

export const getUser = (id: string) => get<{ user: User }>(`/admin/users/${encodeURIComponent(id)}`);

export const getStats = (hours: number) => get<Stats>(`/admin/stats?hours=${hours}`);
export const getTimeseries = (hours: number) => get<Timeseries>(`/admin/timeseries?hours=${hours}`);
export const getTenants = () => get<{ tenants: Tenant[] }>("/admin/tenants");

export function getEvents(opts: { limit: number; decision?: Decision; tenant?: string }) {
  const q = new URLSearchParams({ limit: String(opts.limit) });
  if (opts.decision) q.set("decision", opts.decision);
  if (opts.tenant) q.set("tenant", opts.tenant);
  return get<{ events: AuditEvent[] }>(`/admin/events?${q}`);
}
