import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { PiiVault } from "../detectors/pii.js";
import { inspectMessages, redactMessages, type ChatMessage } from "../pipeline/inspect.js";
import { sendError } from "./errors.js";

const inspectBodySchema = z.union([
  z.object({ text: z.string().min(1), role: z.enum(["user", "tool"]).default("user") }),
  z.object({ messages: z.array(z.object({ role: z.string() }).passthrough()).min(1) }),
]);

/**
 * Scan-only API: run the policy against a prompt without calling a model.
 * Useful for apps that call providers directly but still want the detectors, and for tuning policies.
 */
export function registerInspectRoute(app: FastifyInstance) {
  app.post("/v1/inspect", async (request, reply) => {
    const parsed = inspectBodySchema.safeParse(request.body);
    if (!parsed.success) {
      return sendError(reply, 400, "invalid_request", "Provide either { text, role? } or { messages }.", "invalid_request_error");
    }
    const messages: ChatMessage[] =
      "text" in parsed.data ? [{ role: parsed.data.role, content: parsed.data.text }] : (parsed.data.messages as ChatMessage[]);

    const started = performance.now();
    const inspection = inspectMessages(messages, request.policy);
    const redacted = redactMessages(messages, request.policy, new PiiVault());

    return {
      decision: inspection.decision,
      reason: inspection.reason,
      injection_score: inspection.maxInjectionScore,
      findings: inspection.findings,
      pii: { total: redacted.total, counts: redacted.counts },
      redacted_messages: redacted.messages,
      policy: request.policy.name,
      latency_ms: Math.round((performance.now() - started) * 1000) / 1000,
    };
  });
}
