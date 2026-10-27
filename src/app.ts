import { randomUUID } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { ZodError } from "zod";
import type { Config } from "./config.js";
import { INJECTION_RULE_COUNT } from "./detectors/injection.js";
import { registerAdminRoutes } from "./http/admin.js";
import { adminAuth, tenantAuth } from "./http/auth.js";
import { registerChatRoute } from "./http/chat.js";
import { sendError } from "./http/errors.js";
import { registerInspectRoute } from "./http/inspectRoute.js";
import { RateLimiter } from "./limits/rateLimiter.js";
import type { Policy } from "./policy/schema.js";
import type { Store } from "./store/store.js";

export interface AppDeps {
  config: Config;
  store: Store;
  policies: Map<string, Policy>;
  rateLimiter?: RateLimiter;
  logger?: boolean;
}

export function buildApp(deps: AppDeps): FastifyInstance {
  const app = Fastify({
    logger: deps.logger === false ? false : { level: deps.config.logLevel },
    genReqId: () => `req_${randomUUID().replaceAll("-", "")}`,
    bodyLimit: 4 * 1024 * 1024,
  });

  app.setErrorHandler((err, request, reply) => {
    if (err instanceof ZodError) return sendError(reply, 400, "invalid_request", err.issues[0]?.message ?? "Invalid request.", "invalid_request_error");
    const status = (err as { statusCode?: number }).statusCode ?? 500;
    if (status >= 500) request.log.error({ err }, "unhandled error");
    return sendError(reply, status, status >= 500 ? "internal_error" : "invalid_request", status >= 500 ? "Internal error." : (err as Error).message);
  });

  // Landing response for anyone who opens the gateway URL in a browser.
  app.get("/", async () => ({
    service: "Aegis LLM Security Gateway",
    description: "OpenAI-compatible proxy: prompt-injection detection, PII redaction, system-prompt leak detection, rate limits.",
    usage: "Point an OpenAI SDK at <this-url>/v1 with an Aegis API key. This URL is an API, not a web page.",
    dashboard: "http://localhost:3000",
    endpoints: {
      "POST /v1/chat/completions": "Protected chat completions (tenant key)",
      "POST /v1/inspect": "Scan a prompt without calling a model (tenant key)",
      "GET /admin/stats": "Aggregate metrics (admin token)",
      "GET /admin/timeseries": "Requests per decision over time (admin token)",
      "GET /admin/events": "Audit log (admin token)",
      "GET /admin/tenants": "Tenants and usage (admin token)",
      "GET /healthz": "Liveness",
    },
  }));

  app.get("/healthz", async () => ({ status: "ok", policies: [...deps.policies.keys()], injectionRules: INJECTION_RULE_COUNT }));

  app.register(async (scope) => {
    scope.addHook("preHandler", tenantAuth(deps.store, deps.policies));
    registerChatRoute(scope, { config: deps.config, store: deps.store, rateLimiter: deps.rateLimiter ?? new RateLimiter() });
    registerInspectRoute(scope);
  });

  app.register(async (scope) => {
    scope.addHook("preHandler", adminAuth(deps.config.adminToken));
    registerAdminRoutes(scope, deps.store, deps.policies);
  });

  return app;
}
