const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 });
const integer = new Intl.NumberFormat("en-US");

/** 1,284 below ten thousand; 12.9K / 4.2M above. */
export function formatCount(n: number): string {
  return Math.abs(n) < 10_000 ? integer.format(n) : compact.format(n);
}

export function formatPercent(ratio: number): string {
  if (!Number.isFinite(ratio)) return "–";
  return `${(ratio * 100).toFixed(ratio > 0 && ratio < 0.1 ? 1 : 0)}%`;
}

export function formatMs(ms: number): string {
  if (ms < 1) return `${Math.round(ms * 1000)} µs`;
  if (ms < 100) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
}

// All times render in UTC. That keeps server and client output identical (no hydration
// mismatch), and UTC is the convention in security tooling.
const dateTime = new Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC",
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

export function formatDateTime(ts: number): string {
  return `${dateTime.format(ts)} UTC`;
}

const REASONS: Record<string, string> = {
  prompt_injection: "Prompt injection",
  indirect_prompt_injection: "Indirect injection (tool output)",
  system_prompt_leak: "System prompt leak",
  blocked_topic: "Blocked topic",
  rate_limited: "Rate limited",
  budget_exceeded: "Token budget exceeded",
  model_not_allowed: "Model not allowed",
  invalid_request: "Invalid request",
};

export function reasonLabel(reason: string | null): string {
  if (!reason) return "–";
  return REASONS[reason] ?? reason.replaceAll("_", " ");
}

/** Reasons that represent an attack or leak, as opposed to quota or validation rejections. */
export const THREAT_REASONS = new Set(["prompt_injection", "indirect_prompt_injection", "system_prompt_leak", "blocked_topic"]);
