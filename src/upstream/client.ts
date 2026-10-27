import type { Config } from "../config.js";

export async function chatCompletion(config: Config, body: unknown, signal: AbortSignal): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (config.upstreamApiKey) headers.authorization = `Bearer ${config.upstreamApiKey}`;
  return fetch(`${config.upstreamBaseUrl}/chat/completions`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal,
  });
}

/** Rough fallback when the upstream does not report usage: ~4 characters per token for English. */
export function estimateTokens(chars: number): number {
  return Math.ceil(chars / 4);
}
