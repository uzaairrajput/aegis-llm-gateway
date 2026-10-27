import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { dummyPasswordHash, verifyPassword } from "../auth/password.js";
import { RateLimiter } from "../limits/rateLimiter.js";
import type { Policy } from "../policy/schema.js";
import type { Store } from "../store/store.js";
import { sendError } from "./errors.js";

const LOGIN_ATTEMPTS_PER_EMAIL = 5; // per minute
const LOGIN_ATTEMPTS_PER_IP = 20; // per minute

const loginBody = z.object({
  email: z.string().trim().min(3).max(254),
  password: z.string().min(1).max(1024),
  // Forwarded by the dashboard server so attempts can be limited per end-user IP.
  clientIp: z.string().max(64).optional(),
});

const HOUR = 3_600_000;

const eventsQuery = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(50),
  tenant: z.string().optional(),
  decision: z.enum(["allowed", "blocked", "flagged"]).optional(),
});

const windowQuery = z.object({
  hours: z.coerce.number().positive().max(24 * 90).default(24),
});

export function registerAdminRoutes(app: FastifyInstance, store: Store, policies: Map<string, Policy>, loginLimiter = new RateLimiter()) {
  // Dashboard sign-in. Only the dashboard server calls this (it holds the admin token).
  // Unknown email and wrong password produce the same response and take the same time.
  app.post("/admin/auth/login", async (request, reply) => {
    const parsed = loginBody.safeParse(request.body);
    if (!parsed.success) return sendError(reply, 400, "invalid_request", "Email and password are required.", "invalid_request_error");
    const { email, password, clientIp } = parsed.data;

    for (const [key, limit] of [
      [`email:${email.toLowerCase()}`, LOGIN_ATTEMPTS_PER_EMAIL],
      [`ip:${clientIp ?? request.ip}`, LOGIN_ATTEMPTS_PER_IP],
    ] as const) {
      const r = loginLimiter.take(key, limit);
      if (!r.ok) {
        reply.header("retry-after", String(r.retryAfterSec));
        return sendError(reply, 429, "too_many_attempts", `Too many sign-in attempts. Try again in ${r.retryAfterSec}s.`, "rate_limit_error");
      }
    }

    const user = store.findUserForLogin(email);
    const valid = await verifyPassword(password, user?.passwordHash ?? (await dummyPasswordHash()));
    if (!user || !valid) {
      request.log.warn({ email: email.toLowerCase(), ip: clientIp ?? request.ip }, "failed dashboard sign-in");
      return sendError(reply, 401, "invalid_credentials", "Incorrect email or password.", "authentication_error");
    }

    store.recordLogin(user.id);
    const { passwordHash: _, ...safe } = user;
    return { user: safe };
  });

  // The dashboard re-checks the user on every page load, so deleting a user or changing a role
  // takes effect immediately instead of when their session cookie expires.
  app.get<{ Params: { id: string } }>("/admin/users/:id", async (request, reply) => {
    const user = store.findUserById(request.params.id);
    if (!user) return sendError(reply, 404, "user_not_found", "User not found.");
    return { user };
  });
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
