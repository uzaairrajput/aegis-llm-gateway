import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Policy } from "../policy/schema.js";
import type { Store } from "../store/store.js";

const HOUR = 3_600_000;

const eventsQuery = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(50),
  tenant: z.string().optional(),
  decision: z.enum(["allowed", "blocked", "flagged"]).optional(),
});

const windowQuery = z.object({
  hours: z.coerce.number().positive().max(24 * 90).default(24),
});

export function registerAdminRoutes(app: FastifyInstance, store: Store, policies: Map<string, Policy>) {
  app.get("/admin/stats", async (request) => {
    const { hours } = windowQuery.parse(request.query);
    return { window_hours: hours, ...store.stats(Date.now() - hours * HOUR) };
  });

  app.get("/admin/timeseries", async (request) => {
    const { hours } = windowQuery.parse(request.query);
    // Keep roughly 24–30 columns per chart: hourly up to two days, 6-hourly up to a week, then daily.
    const bucketMs = hours <= 48 ? HOUR : hours <= 168 ? 6 * HOUR : 24 * HOUR;
    return { window_hours: hours, bucket_ms: bucketMs, points: store.timeseries(Date.now() - hours * HOUR, bucketMs) };
  });

  app.get("/admin/events", async (request) => {
    const q = eventsQuery.parse(request.query);
    return { events: store.listEvents({ limit: q.limit, tenantId: q.tenant, decision: q.decision }) };
  });

  app.get("/admin/tenants", async () => ({
    tenants: store.listTenants().map((t) => {
      const policy = policies.get(t.policy);
      return {
        ...t,
        mode: policy?.mode ?? null,
        monthTokens: store.getUsage(t.id),
        monthlyTokenBudget: policy?.limits.monthly_token_budget ?? null,
        requestsPerMinute: policy?.limits.requests_per_minute ?? null,
      };
    }),
  }));
}
