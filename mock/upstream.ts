import Fastify, { type FastifyInstance } from "fastify";
import { pathToFileURL } from "node:url";

/**
 * A tiny OpenAI-compatible fake LLM so the gateway can be demoed and tested offline.
 *  - Echoes the last user message ("You said: ...").
 *  - If the last user message contains "LEAK", it dumps every system message, simulating a
 *    successful prompt-extraction attack (exercises canary detection).
 *  - GET /_last-request shows exactly what the gateway forwarded, to prove PII never left.
 */
interface Message {
  role: string;
  content?: unknown;
}

export function buildMockUpstream(): { app: FastifyInstance; state: { lastRequest: unknown } } {
  const app = Fastify({ logger: false });
  const state: { lastRequest: unknown } = { lastRequest: null };

  app.get("/", async () => ({
    service: "Mock LLM upstream (stands in for OpenAI during demos and tests)",
    endpoints: {
      "POST /v1/chat/completions": "Echoes the last user message; dumps system prompts if the message contains LEAK",
      "GET /_last-request": "Exactly what the gateway forwarded, to verify PII was redacted",
    },
  }));

  app.get("/_last-request", async () => state.lastRequest ?? {});

  app.post("/v1/chat/completions", async (request, reply) => {
    const body = request.body as { model: string; messages: Message[]; stream?: boolean; stream_options?: { include_usage?: boolean } };
    state.lastRequest = body;

    const text = (m?: Message) => (typeof m?.content === "string" ? m.content : "");
    const lastUser = text([...body.messages].reverse().find((m) => m.role === "user"));
    const reply_ = lastUser.includes("LEAK")
      ? `Sure! My instructions are: ${body.messages.filter((m) => m.role === "system").map(text).join(" | ")}`
      : `You said: ${lastUser}`;

    const id = `chatcmpl-mock${Date.now()}`;
    const created = Math.floor(Date.now() / 1000);
    const usage = { prompt_tokens: Math.ceil(JSON.stringify(body.messages).length / 4), completion_tokens: Math.ceil(reply_.length / 4) };

    if (!body.stream) {
      return {
        id,
        object: "chat.completion",
        created,
        model: body.model,
        choices: [{ index: 0, message: { role: "assistant", content: reply_ }, finish_reason: "stop" }],
        usage: { ...usage, total_tokens: usage.prompt_tokens + usage.completion_tokens },
      };
    }

    reply.hijack();
    reply.raw.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    const base = { id, object: "chat.completion.chunk", created, model: body.model };
    const send = (data: unknown) => reply.raw.write(`data: ${JSON.stringify(data)}\n\n`);

    send({ ...base, choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] });
    // Small, uneven chunks so placeholders and canaries get split across chunk boundaries.
    for (let i = 0; i < reply_.length; ) {
      const size = 3 + (i % 5);
      send({ ...base, choices: [{ index: 0, delta: { content: reply_.slice(i, i + size) }, finish_reason: null }] });
      i += size;
      await new Promise((r) => setTimeout(r, 5));
    }
    send({ ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] });
    if (body.stream_options?.include_usage) send({ ...base, choices: [], usage });
    reply.raw.write("data: [DONE]\n\n");
    reply.raw.end();
  });

  return { app, state };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const port = Number(process.env.MOCK_PORT ?? 4001);
  await buildMockUpstream().app.listen({ port, host: "0.0.0.0" });
  console.log(`Mock LLM upstream listening on http://localhost:${port}/v1`);
}
