import type { FastifyReply } from "fastify";

/** OpenAI-shaped error body, so existing SDKs surface it naturally. */
export function sendError(reply: FastifyReply, status: number, code: string, message: string, type = "aegis_error") {
  return reply.status(status).send({ error: { message, type, code, request_id: reply.request.id } });
}
