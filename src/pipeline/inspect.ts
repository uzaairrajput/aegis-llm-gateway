import { scanInjection } from "../detectors/injection.js";
import { PiiVault, redact } from "../detectors/pii.js";
import type { Finding } from "../detectors/types.js";
import type { PiiEntity, Policy } from "../policy/schema.js";

export interface ContentPart {
  type: string;
  text?: string;
  [key: string]: unknown;
}

export interface ChatMessage {
  role: string;
  content?: string | ContentPart[] | null;
  [key: string]: unknown;
}

export type Decision = "allowed" | "blocked" | "flagged";

export interface InspectionResult {
  decision: Decision;
  /** Primary reason, safe to show to the caller (category only, no rule ids). */
  reason: string | null;
  findings: Finding[];
  maxInjectionScore: number;
}

// Messages from these roles carry content the attacker may control indirectly
// (fetched web pages, emails, retrieved documents), so they get the stricter threshold.
const INDIRECT_ROLES = new Set(["tool", "function"]);
// System prompts are written by the application developer and are trusted.
const SKIPPED_ROLES = new Set(["system", "developer", "assistant"]);

export function messageText(message: ChatMessage): string {
  if (typeof message.content === "string") return message.content;
  if (Array.isArray(message.content)) {
    return message.content
      .filter((p) => p.type === "text" && typeof p.text === "string")
      .map((p) => p.text)
      .join("\n");
  }
  return "";
}

export function inspectMessages(messages: ChatMessage[], policy: Policy): InspectionResult {
  const findings: Finding[] = [];
  let maxInjectionScore = 0;
  let reason: string | null = null;

  messages.forEach((message, messageIndex) => {
    if (SKIPPED_ROLES.has(message.role)) return;
    const text = messageText(message);
    if (!text) return;

    if (policy.injection.enabled) {
      const indirect = INDIRECT_ROLES.has(message.role);
      const threshold = indirect ? policy.injection.indirect_threshold : policy.injection.threshold;
      const result = scanInjection(text);
      maxInjectionScore = Math.max(maxInjectionScore, result.score);
      const violates = result.score >= threshold;
      for (const m of result.matches) {
        findings.push({
          detector: "injection",
          rule: m.rule,
          severity: violates ? "high" : "low",
          score: result.score,
          messageIndex,
          excerpt: m.excerpt,
        });
      }
      if (violates) reason ??= indirect ? "indirect_prompt_injection" : "prompt_injection";
    }

    if (message.role === "user" && policy.topics.blocked.length > 0) {
      const lower = text.toLowerCase();
      for (const topic of policy.topics.blocked) {
        if (lower.includes(topic.toLowerCase())) {
          findings.push({ detector: "topic", rule: `topic:${topic}`, severity: "medium", messageIndex });
          reason ??= "blocked_topic";
        }
      }
    }
  });

  const decision: Decision = reason === null ? "allowed" : policy.mode === "enforce" ? "blocked" : "flagged";
  return { decision, reason, findings, maxInjectionScore };
}

export interface RedactedMessages {
  messages: ChatMessage[];
  counts: Partial<Record<PiiEntity, number>>;
  total: number;
}

/** Returns a redacted copy; the original messages are not mutated. */
export function redactMessages(messages: ChatMessage[], policy: Policy, vault: PiiVault): RedactedMessages {
  const counts: Partial<Record<PiiEntity, number>> = {};
  if (!policy.pii.enabled) return { messages, counts, total: 0 };

  const entities = new Set(policy.pii.entities);
  const apply = (text: string) => {
    const r = redact(text, entities, vault);
    for (const [entity, n] of Object.entries(r.counts) as [PiiEntity, number][]) counts[entity] = (counts[entity] ?? 0) + n;
    return r.text;
  };

  const redacted = messages.map((m): ChatMessage => {
    if (typeof m.content === "string") return { ...m, content: apply(m.content) };
    if (Array.isArray(m.content)) {
      return { ...m, content: m.content.map((p) => (p.type === "text" && typeof p.text === "string" ? { ...p, text: apply(p.text) } : p)) };
    }
    return m;
  });

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return { messages: redacted, counts, total };
}
