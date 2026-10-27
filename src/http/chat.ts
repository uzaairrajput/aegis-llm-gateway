import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { Config } from "../config.js";
import { CanaryLeakError, canarySystemMessage, createCanary } from "../detectors/canary.js";
import { PiiVault } from "../detectors/pii.js";
import type { Finding } from "../detectors/types.js";
import type { RateLimiter } from "../limits/rateLimiter.js";
import { inspectMessages, messageText, redactMessages, type ChatMessage, type InspectionResult } from "../pipeline/inspect.js";
import { StreamGuard } from "../pipeline/streamGuard.js";
import { modelAllowed } from "../policy/schema.js";
import type { AuditEvent, Store } from "../store/store.js";
import { chatCompletion, estimateTokens } from "../upstream/client.js";
import { sendError } from "./errors.js";

const UPSTREAM_TIMEOUT_MS = 120_000;

const chatBodySchema = z
  .object({
    model: z.string().min(1),
    messages: z.array(z.object({ role: z.string() }).passthrough()).min(1),
    stream: z.boolean().optional(),
    stream_options: z.object({ include_usage: z.boolean().optional() }).passthrough().optional(),
  })
  .passthrough();

interface ChatDeps {
  config: Config;
  store: Store;
  rateLimiter: RateLimiter;
}

interface Upstream {
  choices?: { index?: number; message?: { content?: unknown }; delta?: { content?: unknown }; finish_reason?: string | null }[];
  usage?: { prompt_tokens?: number; completion_tokens?: number };
  [key: string]: unknown;
}

export function registerChatRoute(app: FastifyInstance, deps: ChatDeps) {
  app.post("/v1/chat/completions", async (request, reply) => {
    const { tenant, policy } = request;
    const started = performance.now();

    const audit: AuditEvent = {
      requestId: request.id,
      tenantId: tenant.id,
      ts: Date.now(),
      endpoint: "chat.completions",
      model: null,
      decision: "allowed",
      reason: null,
      status: 200,
      stream: false,
      injectionScore: 0,
      piiRedacted: 0,
      findings: [],
      inspectMs: 0,
      upstreamMs: null,
      promptTokens: 0,
      completionTokens: 0,
    };
    const finish = (patch: Partial<AuditEvent>) => {
      Object.assign(audit, patch);
      deps.store.recordEvent(audit);
      deps.store.addUsage(tenant.id, audit.promptTokens + audit.completionTokens);
    };

    // 1. Rate limit and budget, before doing any work.
    const limited = deps.rateLimiter.take(tenant.id, policy.limits.requests_per_minute);
    if (!limited.ok) {
      reply.header("retry-after", String(limited.retryAfterSec));
      finish({ decision: "blocked", reason: "rate_limited", status: 429 });
      return sendError(reply, 429, "rate_limited", `Rate limit of ${policy.limits.requests_per_minute} requests/minute exceeded.`, "rate_limit_error");
    }
    if (deps.store.getUsage(tenant.id) >= policy.limits.monthly_token_budget) {
      finish({ decision: "blocked", reason: "budget_exceeded", status: 429 });
      return sendError(reply, 429, "budget_exceeded", "Monthly token budget exhausted for this tenant.", "rate_limit_error");
    }

    // 2. Validate the request shape.
    const parsed = chatBodySchema.safeParse(request.body);
    if (!parsed.success) {
      finish({ decision: "blocked", reason: "invalid_request", status: 400 });
      return sendError(reply, 400, "invalid_request", parsed.error.issues[0]?.message ?? "Invalid request body.", "invalid_request_error");
    }
    const body = parsed.data;
    const messages = body.messages as ChatMessage[];
    audit.model = body.model;
    audit.stream = body.stream === true;

    if (!modelAllowed(policy, body.model)) {
      const finding: Finding = { detector: "model", rule: `model:${body.model}`, severity: "medium" };
      finish({ decision: "blocked", reason: "model_not_allowed", status: 403, findings: [finding] });
      return sendError(reply, 403, "model_not_allowed", `Model "${body.model}" is not allowed by policy "${policy.name}".`, "aegis_policy_violation");
    }

    // 3. Inspect input.
    const inspection = inspectMessages(messages, policy);
    audit.findings = inspection.findings;
    audit.injectionScore = inspection.maxInjectionScore;
    audit.decision = inspection.decision;
    audit.reason = inspection.reason;
    reply.header("x-aegis-request-id", request.id);
    reply.header("x-aegis-decision", inspection.decision);

    if (inspection.decision === "blocked") {
      audit.inspectMs = performance.now() - started;
      finish({ status: 403 });
      // Category only: rule ids and scores would help an attacker tune around the detector.
      return sendError(reply, 403, inspection.reason!, blockMessage(inspection, policy.name), "aegis_policy_violation");
    }
    if (inspection.decision === "flagged") {
      request.log.warn({ tenant: tenant.name, reason: inspection.reason }, "policy violation (monitor mode)");
    }

    // 4. Transform: redact PII, plant a canary.
    const vault = new PiiVault();
    const redacted = redactMessages(messages, policy, vault);
    audit.piiRedacted = redacted.total;
    if (redacted.total > 0) {
      audit.findings.push(
        ...Object.entries(redacted.counts).map(([entity, count]): Finding => ({
          detector: "pii",
          rule: `pii:${entity}`,
          severity: "low",
          score: count,
        })),
      );
    }
    const canary = policy.canary.enabled ? createCanary() : null;
    const outgoing = canary ? [canarySystemMessage(canary), ...redacted.messages] : redacted.messages;
    audit.inspectMs = performance.now() - started;

    const promptChars = messages.reduce((n, m) => n + messageText(m).length, 0);
    const clientWantsUsage = body.stream_options?.include_usage === true;
    const upstreamBody = {
      ...body,
      messages: outgoing,
      ...(audit.stream ? { stream_options: { ...body.stream_options, include_usage: true } } : {}),
    };

    // 5. Forward.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
    reply.raw.on("close", () => {
      if (!reply.raw.writableFinished) controller.abort();
    });
    const upstreamStarted = performance.now();
    let upstream: Response;
    try {
      upstream = await chatCompletion(deps.config, upstreamBody, controller.signal);
    } catch (err) {
      clearTimeout(timeout);
      request.log.error({ err }, "upstream request failed");
      finish({ status: 502, upstreamMs: performance.now() - upstreamStarted });
      return sendError(reply, 502, "upstream_unavailable", "The upstream LLM provider could not be reached.", "api_error");
    }

    if (!upstream.ok) {
      clearTimeout(timeout);
      const text = await upstream.text();
      finish({ status: upstream.status, upstreamMs: performance.now() - upstreamStarted });
      return reply.status(upstream.status).header("content-type", upstream.headers.get("content-type") ?? "application/json").send(text);
    }

    const rehydrateVault = policy.pii.rehydrate ? vault : null;

    // 6a. Non-streaming: inspect the full response.
    if (!audit.stream) {
      const json = (await upstream.json()) as Upstream;
      clearTimeout(timeout);
      audit.upstreamMs = performance.now() - upstreamStarted;
      audit.promptTokens = json.usage?.prompt_tokens ?? estimateTokens(promptChars);

      let completionChars = 0;
      for (const choice of json.choices ?? []) {
        const content = choice.message?.content;
        if (typeof content !== "string") continue;
        completionChars += content.length;
        if (canary && content.includes(canary)) {
          audit.completionTokens = json.usage?.completion_tokens ?? estimateTokens(completionChars);
          return blockLeak(reply, audit, finish);
        }
        choice.message!.content = rehydrateVault ? rehydrateVault.rehydrate(content) : content;
      }
      audit.completionTokens = json.usage?.completion_tokens ?? estimateTokens(completionChars);
      finish({ status: 200 });
      return reply.send(json);
    }

    // 6b. Streaming: transform SSE chunk by chunk.
    await streamResponse(request, reply, upstream, { canary, vault: rehydrateVault, clientWantsUsage, audit, promptChars });
    clearTimeout(timeout);
    controller.abort();
    audit.upstreamMs = performance.now() - upstreamStarted;
    finish({});
  });
}

function blockMessage(inspection: InspectionResult, policyName: string): string {
  switch (inspection.reason) {
    case "prompt_injection":
      return `Request blocked by Aegis policy "${policyName}": possible prompt injection.`;
    case "indirect_prompt_injection":
      return `Request blocked by Aegis policy "${policyName}": a tool result contains instructions aimed at the model.`;
    case "blocked_topic":
      return `Request blocked by Aegis policy "${policyName}": topic not permitted.`;
    default:
      return `Request blocked by Aegis policy "${policyName}".`;
  }
}

function blockLeak(reply: FastifyReply, audit: AuditEvent, finish: (p: Partial<AuditEvent>) => void) {
  const finding: Finding = { detector: "canary", rule: "canary.system_prompt_leak", severity: "high" };
  audit.findings.push(finding);
  finish({ decision: "blocked", reason: "system_prompt_leak", status: 403 });
  reply.header("x-aegis-decision", "blocked");
  return sendError(reply, 403, "system_prompt_leak", "Response blocked by Aegis: the model attempted to reveal its system prompt.", "aegis_policy_violation");
}

async function streamResponse(
  request: FastifyRequest,
  reply: FastifyReply,
  upstream: Response,
  ctx: { canary: string | null; vault: PiiVault | null; clientWantsUsage: boolean; audit: AuditEvent; promptChars: number },
) {
  const { audit } = ctx;
  reply.hijack();
  const res = reply.raw;
  res.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache",
    connection: "keep-alive",
    "x-aegis-request-id": request.id,
    "x-aegis-decision": audit.decision,
  });
  const send = (data: unknown) => res.write(`data: ${typeof data === "string" ? data : JSON.stringify(data)}\n\n`);

  const guards = new Map<number, StreamGuard>();
  const guardFor = (index: number) => {
    let g = guards.get(index);
    if (!g) guards.set(index, (g = new StreamGuard(ctx.vault, ctx.canary)));
    return g;
  };

  let completionChars = 0;
  let lastChunk: Upstream | null = null;
  let reportedUsage: Upstream["usage"];

  const handleChunk = (chunk: Upstream) => {
    lastChunk = chunk;
    if (chunk.usage) reportedUsage = chunk.usage;
    for (const choice of chunk.choices ?? []) {
      const guard = guardFor(choice.index ?? 0);
      const delta = typeof choice.delta?.content === "string" ? choice.delta.content : "";
      completionChars += delta.length;
      let out = delta ? guard.push(delta) : "";
      if (choice.finish_reason) out += guard.flush();
      if (choice.delta && (delta || out)) choice.delta.content = out;
    }
    if (!ctx.clientWantsUsage) {
      if (chunk.usage && (chunk.choices?.length ?? 0) === 0) return;
      delete chunk.usage;
    }
    // Skip chunks emptied by the holdback; they carry nothing for the client.
    const carriesSomething =
      chunk.usage !== undefined ||
      (chunk.choices ?? []).some(
        (c) => c.finish_reason || Object.entries(c.delta ?? {}).some(([k, v]) => (k === "content" ? v !== "" : v !== undefined)),
      );
    if (carriesSomething) send(chunk);
  };

  const flushRemaining = () => {
    for (const [index, guard] of guards) {
      const out = guard.flush();
      if (out && lastChunk) send({ ...lastChunk, usage: undefined, choices: [{ index, delta: { content: out }, finish_reason: null }] });
    }
  };

  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for await (const bytes of upstream.body as unknown as AsyncIterable<Uint8Array>) {
      buffer += decoder.decode(bytes, { stream: true });
      let newline: number;
      while ((newline = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newline).replace(/\r$/, "");
        buffer = buffer.slice(newline + 1);
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim();
        if (data === "[DONE]") {
          flushRemaining();
          send("[DONE]");
          continue;
        }
        try {
          handleChunk(JSON.parse(data) as Upstream);
        } catch (err) {
          if (err instanceof CanaryLeakError) throw err;
          request.log.warn({ data: data.slice(0, 200) }, "unparseable upstream SSE chunk");
        }
      }
    }
    audit.status = 200;
  } catch (err) {
    if (err instanceof CanaryLeakError) {
      audit.findings.push({ detector: "canary", rule: "canary.system_prompt_leak", severity: "high" });
      audit.decision = "blocked";
      audit.reason = "system_prompt_leak";
      audit.status = 403;
      send({
        error: {
          message: "Response blocked by Aegis: the model attempted to reveal its system prompt.",
          type: "aegis_policy_violation",
          code: "system_prompt_leak",
          request_id: request.id,
        },
      });
      send("[DONE]");
    } else {
      request.log.error({ err }, "stream interrupted");
      audit.status = 499;
    }
  } finally {
    res.end();
  }

  const usage = reportedUsage as Upstream["usage"];
  audit.promptTokens = usage?.prompt_tokens ?? estimateTokens(ctx.promptChars);
  audit.completionTokens = usage?.completion_tokens ?? estimateTokens(completionChars);
}
