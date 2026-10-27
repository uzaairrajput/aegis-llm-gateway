import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { hashPassword, verifyPassword } from "../src/auth/password.js";
import { loadConfig } from "../src/config.js";
import { loadPolicies } from "../src/policy/loader.js";
import { Store } from "../src/store/store.js";

describe("password hashing", () => {
  it("verifies the right password and rejects others", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(hash).toMatch(/^scrypt\$32768\$8\$1\$/);
    expect(await verifyPassword("correct horse battery staple", hash)).toBe(true);
    expect(await verifyPassword("correct horse battery stapl", hash)).toBe(false);
  });

  it("salts every hash", async () => {
    expect(await hashPassword("same")).not.toBe(await hashPassword("same"));
  });

  it("rejects malformed stored hashes", async () => {
    expect(await verifyPassword("x", "md5$abc")).toBe(false);
  });
});

describe("dashboard sign-in API", () => {
  let app: FastifyInstance;
  let store: Store;
  let userId: string;
  const admin = { authorization: "Bearer admin-secret" };

  beforeAll(async () => {
    store = new Store(":memory:");
    userId = store.createUser({ email: "Ana@Example.com", name: "Ana", role: "analyst", passwordHash: await hashPassword("s3cret-pass") }).id;
    const config = { ...loadConfig({}), adminToken: "admin-secret" };
    app = buildApp({ config, store, policies: loadPolicies(config.policiesDir), logger: false });
  });

  afterAll(async () => {
    await app.close();
    store.close();
  });

  const login = (body: object) => app.inject({ method: "POST", url: "/admin/auth/login", headers: admin, payload: body });

  it("requires the admin token (only the dashboard server may call it)", async () => {
    const res = await app.inject({ method: "POST", url: "/admin/auth/login", payload: { email: "ana@example.com", password: "s3cret-pass" } });
    expect(res.statusCode).toBe(401);
  });

  it("signs in with a case-insensitive email and never returns the hash", async () => {
    const res = await login({ email: "ana@example.com", password: "s3cret-pass", clientIp: "10.0.0.1" });
    expect(res.statusCode).toBe(200);
    expect(res.json().user).toMatchObject({ id: userId, email: "ana@example.com", role: "analyst" });
    expect(res.body).not.toContain("scrypt");
    expect(store.findUserById(userId)?.lastLoginAt).not.toBeNull();
  });

  it("gives the same answer for a wrong password and an unknown email", async () => {
    const wrong = await login({ email: "ana@example.com", password: "nope", clientIp: "10.0.0.2" });
    const unknown = await login({ email: "nobody@example.com", password: "nope", clientIp: "10.0.0.3" });
    expect(wrong.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(wrong.json().error.message).toBe(unknown.json().error.message);
  });

  it("limits attempts per email", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await login({ email: "target@example.com", password: "guess" + i, clientIp: `10.1.0.${i}` })).statusCode);
    expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
    expect(statuses[5]).toBe(429);
  });

  it("looks users up by id, so deleted users lose access immediately", async () => {
    expect((await app.inject({ method: "GET", url: `/admin/users/${userId}`, headers: admin })).json().user.role).toBe("analyst");
    store.deleteUser("ana@example.com");
    expect((await app.inject({ method: "GET", url: `/admin/users/${userId}`, headers: admin })).statusCode).toBe(404);
  });
});
