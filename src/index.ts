import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { loadPolicies } from "./policy/loader.js";
import { Store } from "./store/store.js";

try {
  process.loadEnvFile();
} catch {
  // No .env file: rely on the real environment.
}

const config = loadConfig();
const policies = loadPolicies(config.policiesDir);
const store = new Store(config.dbPath);
const app = buildApp({ config, store, policies });

const shutdown = async () => {
  await app.close();
  store.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

await app.listen({ port: config.port, host: config.host });
app.log.info(`Aegis gateway → upstream ${config.upstreamBaseUrl}, policies: ${[...policies.keys()].join(", ")}`);
