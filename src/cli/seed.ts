/**
 * Seeds the audit log with a week of simulated traffic for demos and dashboard development.
 *
 *   npm run seed            # ~1,500 requests over the last 7 days
 *   npm run seed -- 5000    # custom count
 *
 * Prompts come from the eval datasets and are run through the real detectors and redaction,
 * so decisions, findings and inspection latency are genuine. Only timestamps, tenants and
 * upstream latency/token counts are simulated.
 */
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadConfig } from "../config.js";
import { PiiVault } from "../detectors/pii.js";
import type { Finding } from "../detectors/types.js";
import { inspectMessages, redactMessages, type ChatMessage } from "../pipeline/inspect.js";
import { loadPolicies } from "../policy/loader.js";
import { currentMonth, Store, type AuditEvent } from "../store/store.js";

try {
  process.loadEnvFile();
} catch {
  // No .env file.
}

const COUNT = Number(process.argv[2] ?? 1500);
const DAYS = 7;
const TENANTS = [
  { name: "acme-support", policy: "default", weight: 0.55 },
  { name: "medibook", policy: "healthcare-strict", weight: 0.3 },
  { name: "shadow-pilot", policy: "monitor", weight: 0.15 },
];
const PII_SUFFIXES = [
  " My email is maria.lopez@gmail.com.",
  " Call me back on +1 (415) 555-0134.",
  " Card on file is 4111 1111 1111 1111.",
  " The server is 10.20.4.17, key sk-proj-a8Kd92LmQz71XcVb03NmPqRt.",
  " SSN 123-45-6789 for the claim.",
];
const MODELS = ["gpt-4o-mini", "gpt-4o-mini", "gpt-4o-mini", "claude-haiku-4-5", "gpt-4.1"];

// Deterministic PRNG so every seed run produces the same shape of data.
let state = 0x9e3779b9;
const rand = () => {
  state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = <T>(items: T[]): T => items[Math.floor(rand() * items.length)]!;
const weighted = <T extends { weight: number }>(items: T[]): T => {
  let r = rand();
  for (const item of items) if ((r -= item.weight) <= 0) return item;
  return items.at(-1)!;
};

interface Sample {
  text: string;
  label: "attack" | "benign";
  source?: "direct" | "indirect";
}
const loadSamples = (file: string): Sample[] =>
  readFileSync(join(import.meta.dirname, "../../eval/datasets", file), "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Sample);
const attacks = loadSamples("attacks.jsonl");
const benign = loadSamples("benign.jsonl");

const config = loadConfig();
const policies = loadPolicies(config.policiesDir);
const store = new Store(config.dbPath);

const existing = new Map(store.listTenants().map((t) => [t.name, t]));
const tenants = TENANTS.map((spec) => {
  const tenant = existing.get(spec.name) ?? store.createTenant(spec.name, spec.policy).tenant;
  return { ...spec, tenant, policy: policies.get(tenant.policy)! };
});

// Business-hours traffic shape (UTC), with a weekend dip.
const now = Date.now();
const timestamp = () => {
  for (;;) {
    const ts = now - rand() * DAYS * 86_400_000;
    const d = new Date(ts);
    const hour = d.getUTCHours();
    const weight = (0.25 + 0.75 * Math.max(0, Math.sin(((hour - 3) / 24) * 2 * Math.PI))) * (d.getUTCDay() % 6 === 0 ? 0.45 : 1);
    if (rand() < weight) return Math.floor(ts);
  }
};

let blocked = 0;
for (let i = 0; i < COUNT; i++) {
  const t = weighted(tenants);
  const isAttack = rand() < 0.12;
  const sample = pick(isAttack ? attacks : benign);
  const text = !isAttack && rand() < 0.22 ? sample.text + pick(PII_SUFFIXES) : sample.text;
  const messages: ChatMessage[] =
    sample.source === "indirect"
      ? [
          { role: "user", content: "Summarize this for me." },
          { role: "tool", content: text },
        ]
      : [{ role: "user", content: text }];

  const started = performance.now();
  const inspection = inspectMessages(messages, t.policy);
  const redacted = redactMessages(messages, t.policy, new PiiVault());
  const inspectMs = performance.now() - started;

  const findings: Finding[] = [
    ...inspection.findings,
    ...Object.entries(redacted.counts).map(([entity, count]): Finding => ({ detector: "pii", rule: `pii:${entity}`, severity: "low", score: count })),
  ];
  const event: AuditEvent = {
    requestId: `req_${randomUUID().replaceAll("-", "")}`,
    tenantId: t.tenant.id,
    ts: timestamp(),
    endpoint: "chat.completions",
    model: pick(MODELS),
    decision: inspection.decision,
    reason: inspection.reason,
    status: inspection.decision === "blocked" ? 403 : 200,
    stream: rand() < 0.6,
    injectionScore: inspection.maxInjectionScore,
    piiRedacted: redacted.total,
    findings,
    inspectMs,
    upstreamMs: null,
    promptTokens: Math.ceil(text.length / 4) + 180,
    completionTokens: 0,
  };

  // Rare events the datasets can't produce on their own: canary leaks and rate limiting.
  const roll = rand();
  if (event.decision !== "blocked" && roll < 0.004) {
    Object.assign(event, { decision: "blocked", reason: "system_prompt_leak", status: 403, completionTokens: 40 + Math.floor(rand() * 200) });
    event.findings.push({ detector: "canary", rule: "canary.system_prompt_leak", severity: "high" });
  } else if (event.decision !== "blocked" && roll < 0.014) {
    Object.assign(event, { decision: "blocked", reason: "rate_limited", status: 429, promptTokens: 0, findings: [] });
  }

  if (event.status === 200) {
    event.upstreamMs = 350 + rand() ** 2 * 2800;
    event.completionTokens = 60 + Math.floor(rand() * 520);
  }
  if (event.decision === "blocked") blocked++;

  store.recordEvent(event);
  const month = new Date(event.ts).toISOString().slice(0, 7);
  if (month === currentMonth()) store.addUsage(t.tenant.id, event.promptTokens + event.completionTokens, month);
}

store.close();
console.log(`Seeded ${COUNT} requests over ${DAYS} days across ${tenants.length} tenants (${blocked} blocked) into ${config.dbPath}`);
