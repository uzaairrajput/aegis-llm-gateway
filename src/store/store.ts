import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { Finding } from "../detectors/types.js";
import type { Decision } from "../pipeline/inspect.js";

export interface Tenant {
  id: string;
  name: string;
  policy: string;
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

const SCHEMA = `
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  policy TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS usage (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  month TEXT NOT NULL,
  tokens INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, month)
);
CREATE TABLE IF NOT EXISTS audit_events (
  request_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  endpoint TEXT NOT NULL,
  model TEXT,
  decision TEXT NOT NULL,
  reason TEXT,
  status INTEGER NOT NULL,
  stream INTEGER NOT NULL,
  injection_score REAL NOT NULL,
  pii_redacted INTEGER NOT NULL,
  findings TEXT NOT NULL,
  inspect_ms REAL NOT NULL,
  upstream_ms REAL,
  prompt_tokens INTEGER NOT NULL,
  completion_tokens INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_events (tenant_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events (ts DESC);
`;

/** API keys are stored only as SHA-256 hashes; the plaintext is shown once at creation. */
export function hashKey(apiKey: string): string {
  return createHash("sha256").update(apiKey).digest("hex");
}

export function currentMonth(now = new Date()): string {
  return now.toISOString().slice(0, 7);
}

export class Store {
  private db: DatabaseSync;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec(SCHEMA);
  }

  createTenant(name: string, policy: string): { tenant: Tenant; apiKey: string } {
    const apiKey = `aeg_${randomBytes(24).toString("base64url")}`;
    const tenant: Tenant = { id: randomUUID(), name, policy };
    this.db
      .prepare("INSERT INTO tenants (id, name, key_hash, key_prefix, policy, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(tenant.id, name, hashKey(apiKey), apiKey.slice(0, 8), policy, Date.now());
    return { tenant, apiKey };
  }

  findTenantByKey(apiKey: string): Tenant | undefined {
    const row = this.db.prepare("SELECT id, name, policy FROM tenants WHERE key_hash = ?").get(hashKey(apiKey));
    return row as Tenant | undefined;
  }

  listTenants(): (Tenant & { keyPrefix: string; createdAt: number })[] {
    return this.db
      .prepare("SELECT id, name, policy, key_prefix AS keyPrefix, created_at AS createdAt FROM tenants ORDER BY created_at")
      .all() as unknown as (Tenant & { keyPrefix: string; createdAt: number })[];
  }

  getUsage(tenantId: string, month = currentMonth()): number {
    const row = this.db.prepare("SELECT tokens FROM usage WHERE tenant_id = ? AND month = ?").get(tenantId, month) as
      | { tokens: number }
      | undefined;
    return row?.tokens ?? 0;
  }

  addUsage(tenantId: string, tokens: number, month = currentMonth()): void {
    if (tokens <= 0) return;
    this.db
      .prepare(
        "INSERT INTO usage (tenant_id, month, tokens) VALUES (?, ?, ?) ON CONFLICT (tenant_id, month) DO UPDATE SET tokens = tokens + excluded.tokens",
      )
      .run(tenantId, month, tokens);
  }

  recordEvent(e: AuditEvent): void {
    this.db
      .prepare(
        `INSERT INTO audit_events (request_id, tenant_id, ts, endpoint, model, decision, reason, status, stream, injection_score,
          pii_redacted, findings, inspect_ms, upstream_ms, prompt_tokens, completion_tokens)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        e.requestId,
        e.tenantId,
        e.ts,
        e.endpoint,
        e.model,
        e.decision,
        e.reason,
        e.status,
        e.stream ? 1 : 0,
        e.injectionScore,
        e.piiRedacted,
        JSON.stringify(e.findings),
        e.inspectMs,
        e.upstreamMs,
        e.promptTokens,
        e.completionTokens,
      );
  }

  listEvents(opts: { limit: number; tenantId?: string; decision?: Decision }): AuditEvent[] {
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (opts.tenantId) {
      where.push("tenant_id = ?");
      params.push(opts.tenantId);
    }
    if (opts.decision) {
      where.push("decision = ?");
      params.push(opts.decision);
    }
    const sql = `SELECT * FROM audit_events ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY ts DESC LIMIT ?`;
    const rows = this.db.prepare(sql).all(...params, opts.limit) as Record<string, unknown>[];
    return rows.map(toEvent);
  }

  stats(sinceTs: number) {
    const totals = this.db
      .prepare(
        `SELECT COUNT(*) AS requests,
                SUM(decision = 'blocked') AS blocked,
                SUM(decision = 'flagged') AS flagged,
                SUM(pii_redacted) AS piiRedacted,
                SUM(prompt_tokens + completion_tokens) AS tokens
         FROM audit_events WHERE ts >= ?`,
      )
      .get(sinceTs) as Record<string, number | null>;

    const latencies = (
      this.db.prepare("SELECT inspect_ms AS ms FROM audit_events WHERE ts >= ? ORDER BY inspect_ms").all(sinceTs) as { ms: number }[]
    ).map((r) => r.ms);

    const reasons = this.db
      .prepare(
        "SELECT reason, COUNT(*) AS count FROM audit_events WHERE ts >= ? AND reason IS NOT NULL GROUP BY reason ORDER BY count DESC",
      )
      .all(sinceTs);

    const byTenant = this.db
      .prepare(
        `SELECT t.name AS tenant, COUNT(*) AS requests, SUM(e.decision = 'blocked') AS blocked,
                SUM(e.prompt_tokens + e.completion_tokens) AS tokens
         FROM audit_events e JOIN tenants t ON t.id = e.tenant_id
         WHERE e.ts >= ? GROUP BY t.name ORDER BY requests DESC`,
      )
      .all(sinceTs);

    const ruleCounts = new Map<string, number>();
    const findingRows = this.db
      .prepare("SELECT findings FROM audit_events WHERE ts >= ? AND decision != 'allowed'")
      .all(sinceTs) as { findings: string }[];
    for (const row of findingRows) {
      for (const f of JSON.parse(row.findings) as Finding[]) ruleCounts.set(f.rule, (ruleCounts.get(f.rule) ?? 0) + 1);
    }

    return {
      requests: totals.requests ?? 0,
      blocked: totals.blocked ?? 0,
      flagged: totals.flagged ?? 0,
      piiRedacted: totals.piiRedacted ?? 0,
      tokens: totals.tokens ?? 0,
      inspectLatencyMs: { p50: percentile(latencies, 0.5), p95: percentile(latencies, 0.95), p99: percentile(latencies, 0.99) },
      reasons,
      byTenant,
      topRules: [...ruleCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([rule, count]) => ({ rule, count })),
    };
  }

  /** Request counts per decision, bucketed. Empty buckets are included so charts have no gaps. */
  timeseries(sinceTs: number, bucketMs: number, now = Date.now()) {
    const rows = this.db
      .prepare(
        // node:sqlite binds JS numbers as REAL, so cast to get integer division.
        "SELECT (ts / CAST(? AS INTEGER)) * CAST(? AS INTEGER) AS bucket, decision, COUNT(*) AS count FROM audit_events WHERE ts >= ? GROUP BY bucket, decision",
      )
      .all(bucketMs, bucketMs, sinceTs) as { bucket: number; decision: Decision; count: number }[];

    const buckets = new Map<number, { t: number; allowed: number; flagged: number; blocked: number }>();
    for (let t = Math.floor(sinceTs / bucketMs) * bucketMs; t <= now; t += bucketMs) {
      buckets.set(t, { t, allowed: 0, flagged: 0, blocked: 0 });
    }
    for (const r of rows) {
      const b = buckets.get(r.bucket);
      if (b) b[r.decision] += r.count;
    }
    return [...buckets.values()];
  }

  /** Deletes all tenants, usage and audit events. Used to remove demo data. */
  reset(): void {
    this.db.exec("DELETE FROM audit_events; DELETE FROM usage; DELETE FROM tenants;");
  }

  close(): void {
    this.db.close();
  }
}

export function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1);
  return Math.round(sorted[Math.max(0, idx)]! * 1000) / 1000;
}

function toEvent(r: Record<string, unknown>): AuditEvent {
  return {
    requestId: r.request_id as string,
    tenantId: r.tenant_id as string,
    ts: r.ts as number,
    endpoint: r.endpoint as string,
    model: r.model as string | null,
    decision: r.decision as Decision,
    reason: r.reason as string | null,
    status: r.status as number,
    stream: r.stream === 1,
    injectionScore: r.injection_score as number,
    piiRedacted: r.pii_redacted as number,
    findings: JSON.parse(r.findings as string) as Finding[],
    inspectMs: r.inspect_ms as number,
    upstreamMs: r.upstream_ms as number | null,
    promptTokens: r.prompt_tokens as number,
    completionTokens: r.completion_tokens as number,
  };
}
