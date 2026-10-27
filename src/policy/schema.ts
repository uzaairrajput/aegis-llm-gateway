import { z } from "zod";

export const PII_ENTITIES = ["EMAIL", "PHONE", "CREDIT_CARD", "SSN", "IP_ADDRESS", "SECRET"] as const;
export type PiiEntity = (typeof PII_ENTITIES)[number];

export const policySchema = z.object({
  name: z.string().min(1),
  // enforce: block violating requests. monitor: forward everything, but log what would have been blocked.
  mode: z.enum(["enforce", "monitor"]).default("enforce"),
  injection: z
    .object({
      enabled: z.boolean().default(true),
      // Applies to user messages.
      threshold: z.number().min(0).max(1).default(0.5),
      // Applies to tool/function results, which are attacker-reachable (web pages, emails, documents).
      indirect_threshold: z.number().min(0).max(1).default(0.35),
    })
    .default({}),
  pii: z
    .object({
      enabled: z.boolean().default(true),
      entities: z.array(z.enum(PII_ENTITIES)).default([...PII_ENTITIES]),
      rehydrate: z.boolean().default(true),
    })
    .default({}),
  canary: z
    .object({
      enabled: z.boolean().default(true),
    })
    .default({}),
  topics: z
    .object({
      blocked: z.array(z.string().min(1)).default([]),
    })
    .default({}),
  models: z
    .object({
      allowed: z.array(z.string()).default(["*"]),
    })
    .default({}),
  limits: z
    .object({
      requests_per_minute: z.number().int().positive().default(60),
      monthly_token_budget: z.number().int().positive().default(1_000_000),
    })
    .default({}),
});

export type Policy = z.infer<typeof policySchema>;

export function modelAllowed(policy: Policy, model: string): boolean {
  return policy.models.allowed.some((pattern) =>
    pattern.endsWith("*") ? model.startsWith(pattern.slice(0, -1)) : model === pattern,
  );
}
