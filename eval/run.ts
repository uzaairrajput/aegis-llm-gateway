/**
 * Red-team evaluation for the injection detector.
 *
 *   npm run eval
 *   npm run eval -- --dataset path/to/extra.jsonl --threshold 0.45
 *
 * Dataset format (JSONL): {"text": "...", "label": "attack" | "benign", "category"?: "...", "source"?: "direct" | "indirect"}
 * Writes eval/results/report.md and eval/results/report.json.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { INJECTION_RULE_COUNT, scanInjection } from "../src/detectors/injection.js";
import { percentile } from "../src/store/store.js";

interface Sample {
  text: string;
  label: "attack" | "benign";
  category: string;
  source: "direct" | "indirect";
  file: string;
}

const here = dirname(fileURLToPath(import.meta.url));
const { values } = parseArgs({
  options: {
    dataset: { type: "string", multiple: true },
    threshold: { type: "string", default: "0.5" },
    "indirect-threshold": { type: "string", default: "0.35" },
    iterations: { type: "string", default: "20" },
  },
});

const datasets = values.dataset ?? [join(here, "datasets/attacks.jsonl"), join(here, "datasets/benign.jsonl")];
const threshold = Number(values.threshold);
const indirectThreshold = Number(values["indirect-threshold"]);
const iterations = Number(values.iterations);

const samples: Sample[] = datasets.flatMap((file) =>
  readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line) => {
      const raw = JSON.parse(line) as Partial<Sample>;
      if (typeof raw.text !== "string" || (raw.label !== "attack" && raw.label !== "benign")) throw new Error(`Bad sample in ${file}: ${line}`);
      return { text: raw.text, label: raw.label, category: raw.category ?? "uncategorized", source: raw.source ?? "direct", file: relative(process.cwd(), file) };
    }),
);

// Warm up the regex engine so latency reflects steady state.
for (const s of samples.slice(0, 20)) scanInjection(s.text);

const timings: number[] = [];
const results = samples.map((sample) => {
  let result = scanInjection(sample.text);
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    result = scanInjection(sample.text);
    timings.push(performance.now() - t0);
  }
  const limit = sample.source === "indirect" ? indirectThreshold : threshold;
  return { sample, score: result.score, predicted: result.score >= limit, rules: result.matches.map((m) => m.rule) };
});
timings.sort((a, b) => a - b);

const tp = results.filter((r) => r.sample.label === "attack" && r.predicted).length;
const fn = results.filter((r) => r.sample.label === "attack" && !r.predicted).length;
const fp = results.filter((r) => r.sample.label === "benign" && r.predicted).length;
const tn = results.filter((r) => r.sample.label === "benign" && !r.predicted).length;
const precision = tp / (tp + fp || 1);
const recall = tp / (tp + fn || 1);
const f1 = (2 * precision * recall) / (precision + recall || 1);
const fpr = fp / (fp + tn || 1);

const byCategory = new Map<string, { label: string; total: number; correct: number }>();
for (const r of results) {
  const key = `${r.sample.label}:${r.sample.category}`;
  const entry = byCategory.get(key) ?? { label: r.sample.label, total: 0, correct: 0 };
  entry.total++;
  if (r.predicted === (r.sample.label === "attack")) entry.correct++;
  byCategory.set(key, entry);
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
const ms = (x: number) => `${(x * 1000).toFixed(0)} µs`;
const latency = { p50: percentile(timings, 0.5), p95: percentile(timings, 0.95), p99: percentile(timings, 0.99) };
const escape = (t: string) => t.replace(/\|/g, "\\|").replace(/\s+/g, " ").slice(0, 110);

const report = `# Aegis injection detector — evaluation report

Generated ${new Date().toISOString()} · ${INJECTION_RULE_COUNT} heuristic rules · thresholds: direct ${threshold}, indirect ${indirectThreshold}

Datasets: ${datasets.map((d) => `\`${relative(process.cwd(), d)}\``).join(", ")} — ${samples.length} samples (${tp + fn} attacks, ${fp + tn} benign)

## Summary

| Metric | Value |
|---|---|
| Recall (attacks caught) | **${pct(recall)}** (${tp}/${tp + fn}) |
| Precision | **${pct(precision)}** |
| False-positive rate | **${pct(fpr)}** (${fp}/${fp + tn}) |
| F1 | ${f1.toFixed(3)} |
| Detector latency p50 / p95 / p99 | ${ms(latency.p50)} / ${ms(latency.p95)} / ${ms(latency.p99)} |

## By category

| Label | Category | Accuracy |
|---|---|---|
${[...byCategory.entries()]
  .sort()
  .map(([key, e]) => `| ${e.label} | ${key.split(":")[1]} | ${e.correct}/${e.total} (${pct(e.correct / e.total)}) |`)
  .join("\n")}

## Missed attacks (false negatives)

${
  results
    .filter((r) => r.sample.label === "attack" && !r.predicted)
    .map((r) => `- \`${r.score.toFixed(2)}\` [${r.sample.category}] ${escape(r.sample.text)}`)
    .join("\n") || "_None._"
}

## False positives

${
  results
    .filter((r) => r.sample.label === "benign" && r.predicted)
    .map((r) => `- \`${r.score.toFixed(2)}\` [${r.sample.category}] ${escape(r.sample.text)} — rules: ${r.rules.join(", ")}`)
    .join("\n") || "_None._"
}
`;

const outDir = join(here, "results");
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "report.md"), report);
writeFileSync(
  join(outDir, "report.json"),
  JSON.stringify({ threshold, indirectThreshold, tp, fp, tn, fn, precision, recall, f1, fpr, latencyMs: latency, samples: samples.length }, null, 2),
);

console.log(report);
console.log(`Report written to ${relative(process.cwd(), join(outDir, "report.md"))}`);
