import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { policySchema, type Policy } from "./schema.js";

export function loadPolicies(dir: string): Map<string, Policy> {
  const policies = new Map<string, Policy>();
  for (const file of readdirSync(dir).filter((f) => /\.ya?ml$/.test(f))) {
    const result = policySchema.safeParse(parse(readFileSync(join(dir, file), "utf8")));
    if (!result.success) {
      throw new Error(`Invalid policy ${file}: ${result.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join("; ")}`);
    }
    if (policies.has(result.data.name)) throw new Error(`Duplicate policy name "${result.data.name}" in ${file}`);
    policies.set(result.data.name, result.data);
  }
  if (!policies.has("default")) throw new Error(`No policy named "default" found in ${dir}`);
  return policies;
}
