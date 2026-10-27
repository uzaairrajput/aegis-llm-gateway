import { resolve } from "node:path";

export interface Config {
  port: number;
  host: string;
  upstreamBaseUrl: string;
  upstreamApiKey: string;
  dbPath: string;
  policiesDir: string;
  adminToken: string | undefined;
  logLevel: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  return {
    port: Number(env.PORT ?? 8080),
    host: env.HOST ?? "0.0.0.0",
    upstreamBaseUrl: (env.UPSTREAM_BASE_URL ?? "http://localhost:4001/v1").replace(/\/+$/, ""),
    upstreamApiKey: env.UPSTREAM_API_KEY ?? "",
    dbPath: resolve(env.DB_PATH ?? "data/aegis.db"),
    policiesDir: resolve(env.POLICIES_DIR ?? "policies"),
    adminToken: env.ADMIN_TOKEN || undefined,
    logLevel: env.LOG_LEVEL ?? "info",
  };
}
