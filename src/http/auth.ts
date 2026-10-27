import { timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import type { Policy } from "../policy/schema.js";
import type { Store, Tenant } from "../store/store.js";
import { sendError } from "./errors.js";

declare module "fastify" {
  interface FastifyRequest {
    tenant: Tenant;
    policy: Policy;
  }
}

function bearer(request: FastifyRequest): string | undefined {
  const header = request.headers.authorization;
  if (header?.startsWith("Bearer ")) return header.slice(7).trim();
  // Anthropic-style clients send the key in x-api-key.
  const xKey = request.headers["x-api-key"];
  return typeof xKey === "string" ? xKey : undefined;
}

export function tenantAuth(store: Store, policies: Map<string, Policy>) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const key = bearer(request);
    const tenant = key ? store.findTenantByKey(key) : undefined;
    if (!tenant) return sendError(reply, 401, "invalid_api_key", "Missing or invalid Aegis API key.", "authentication_error");
    const policy = policies.get(tenant.policy);
    if (!policy) {
      request.log.error({ tenant: tenant.name, policy: tenant.policy }, "tenant references unknown policy");
      return sendError(reply, 500, "policy_not_found", "Tenant policy is misconfigured.");
    }
    request.tenant = tenant;
    request.policy = policy;
  };
}

export function adminAuth(adminToken: string | undefined) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!adminToken) return sendError(reply, 404, "admin_disabled", "Admin API is disabled. Set ADMIN_TOKEN to enable it.");
    const provided = Buffer.from(bearer(request) ?? "");
    const expected = Buffer.from(adminToken);
    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
      return sendError(reply, 401, "invalid_admin_token", "Invalid admin token.", "authentication_error");
    }
  };
}
