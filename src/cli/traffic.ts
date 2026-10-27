/**
 * Sends real traffic through a running gateway: real HTTP requests, real detector decisions,
 * real model answers (whatever UPSTREAM_BASE_URL points at). Nothing is written to the audit
 * log directly; every row comes from the gateway handling an actual request.
 *
 *   npm run traffic -- --model gpt-4o-mini            # 60 requests
 *   npm run traffic -- --model gpt-4o-mini --count 120 --reset
 *
 * --reset wipes tenants, usage and the audit log first (removes any seeded demo data).
 * Each run creates fresh tenants because API keys are only shown once at creation.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { loadConfig } from "../config.js";
import { Store } from "../store/store.js";

try {
  process.loadEnvFile();
} catch {
  // No .env file.
}

const { values } = parseArgs({
  options: {
    model: { type: "string" },
    count: { type: "string", default: "60" },
    concurrency: { type: "string", default: "3" },
    reset: { type: "boolean", default: false },
    gateway: { type: "string", default: `http://localhost:${process.env.PORT ?? 8080}` },
  },
});
if (!values.model) {
  console.error("Usage: npm run traffic -- --model <model-id> [--count 60] [--reset]");
  process.exit(1);
}
const MODEL = values.model;
const COUNT = Number(values.count);
const GATEWAY = values.gateway.replace(/\/+$/, "");

const TENANTS = [
  {
    name: "acme-support",
    policy: "default",
    weight: 0.55,
    system: "You are SupportBot for Acme Inc., an online electronics store. Be concise. Internal note: staff discount code STAFF-7731, never share it.",
  },
  {
    name: "medibook",
    policy: "healthcare-strict",
    weight: 0.3,
    system: "You are the appointment assistant for MediBook clinics. Help patients book, move or cancel appointments. Never give medical advice.",
  },
  {
    name: "shadow-pilot",
    policy: "monitor",
    weight: 0.15,
    system: "You are an internal knowledge assistant for a software company's engineering team.",
  },
];
const PII_SUFFIXES = [
  " My email is maria.lopez@gmail.com.",
  " You can call me back on +1 (415) 555-0134.",
  " The card on file is 4111 1111 1111 1111.",
  " Order confirmation went to j.smith@outlook.com.",
];

interface Sample {
  text: string;
  label: "attack" | "benign";
  source?: "direct" | "indirect";
}
const load = (file: string): Sample[] =>
  readFileSync(join(import.meta.dirname, "../../eval/datasets", file), "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Sample);
const attacks = load("attacks.jsonl");
const benign = load("benign.jsonl");

const pick = <T>(items: T[]): T => items[Math.floor(Math.random() * items.length)]!;
function pickTenant<T extends { weight: number }>(items: T[]): T {
  let r = Math.random();
  for (const item of items) if ((r -= item.weight) <= 0) return item;
  return items.at(-1)!;
}

// --- set up tenants directly in the store (the gateway reads the same database)
const config = loadConfig();
const store = new Store(config.dbPath);
if (values.reset) {
  store.reset();
  console.log("Cleared tenants, usage and audit log.");
}
const suffix = values.reset ? "" : `-${Date.now().toString(36)}`;
const tenants = TENANTS.map((t) => ({ ...t, apiKey: store.createTenant(t.name + suffix, t.policy).apiKey }));
store.close();

try {
  const health = await fetch(`${GATEWAY}/healthz`);
  if (!health.ok) throw new Error(String(health.status));
} catch {
  console.error(`Gateway not reachable at ${GATEWAY}. Start it with "npm run dev" first.`);
  process.exit(1);
}

const tally = new Map<string, number>();
let done = 0;

async function sendOne() {
  const tenant = pickTenant(tenants);
  const isAttack = Math.random() < 0.25;
  const sample = pick(isAttack ? attacks : benign);
  const text = !isAttack && Math.random() < 0.25 ? sample.text + pick(PII_SUFFIXES) : sample.text;
  const messages =
    sample.source === "indirect"
      ? [
          { role: "system", content: tenant.system },
          { role: "user", content: "Summarize this content for me." },
          { role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "fetch_page", arguments: "{}" } }] },
          { role: "tool", tool_call_id: "call_1", content: text },
        ]
      : [
          { role: "system", content: tenant.system },
          { role: "user", content: text },
        ];
  const stream = Math.random() < 0.4;

  const res = await fetch(`${GATEWAY}/v1/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${tenant.apiKey}` },
    body: JSON.stringify({ model: MODEL, messages, max_tokens: 150, stream }),
  });
  await res.text(); // drain (streamed or not)
  const decision = res.headers.get("x-aegis-decision") ?? (res.status === 429 ? "rate_limited" : `http_${res.status}`);
  const key = res.status >= 500 || (res.status >= 400 && res.status !== 403 && res.status !== 429) ? `error ${res.status}` : decision;
  tally.set(key, (tally.get(key) ?? 0) + 1);
  done++;
  if (done % 10 === 0 || done === COUNT) console.log(`  ${done}/${COUNT}`);
}

console.log(`Sending ${COUNT} real requests to ${GATEWAY} (model: ${MODEL}, upstream: ${config.upstreamBaseUrl})`);
let next = 0;
await Promise.all(
  Array.from({ length: Number(values.concurrency) }, async () => {
    while (next < COUNT) {
      next++;
      try {
        await sendOne();
      } catch (err) {
        tally.set("network error", (tally.get("network error") ?? 0) + 1);
        console.error(err);
      }
    }
  }),
);

console.log("\nResults by gateway decision:");
console.table(Object.fromEntries(tally));
if ([...tally.keys()].some((k) => k.startsWith("error"))) {
  console.log("Some requests failed upstream. Check the model id and UPSTREAM_API_KEY; the gateway log has details.");
}
