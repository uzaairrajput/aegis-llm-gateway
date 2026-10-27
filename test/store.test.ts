import { describe, expect, it } from "vitest";
import { Store, type AuditEvent } from "../src/store/store.js";

const HOUR = 3_600_000;

function event(store: Store, tenantId: string, ts: number, decision: AuditEvent["decision"]) {
  store.recordEvent({
    requestId: `req_${ts}_${Math.random()}`,
    tenantId,
    ts,
    endpoint: "chat.completions",
    model: "m",
    decision,
    reason: decision === "allowed" ? null : "prompt_injection",
    status: decision === "blocked" ? 403 : 200,
    stream: false,
    injectionScore: 0,
    piiRedacted: 0,
    findings: [],
    inspectMs: 0.1,
    upstreamMs: null,
    promptTokens: 1,
    completionTokens: 1,
  });
}

describe("Store.timeseries", () => {
  it("buckets events by decision, including empty buckets", () => {
    const store = new Store(":memory:");
    const { tenant } = store.createTenant("t", "default");
    const now = 100 * HOUR + 30 * 60_000;
    event(store, tenant.id, now - 10 * 60_000, "allowed");
    event(store, tenant.id, now - 20 * 60_000, "blocked");
    event(store, tenant.id, now - 2 * HOUR, "flagged");

    const points = store.timeseries(now - 3 * HOUR, HOUR, now);
    expect(points.map((p) => p.t)).toEqual([97, 98, 99, 100].map((h) => h * HOUR));
    expect(points.at(-1)).toMatchObject({ allowed: 1, blocked: 1, flagged: 0 });
    expect(points[1]).toMatchObject({ allowed: 0, blocked: 0, flagged: 1 });
    expect(points[0]).toMatchObject({ allowed: 0, blocked: 0, flagged: 0 });
    store.close();
  });
});
