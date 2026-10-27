import "server-only";
import { jwtVerify, SignJWT } from "jose";
import { cookies } from "next/headers";

export const SESSION_COOKIE = "aegis_session";
const SESSION_HOURS = 8;

// The cookie carries only the user id. Name and role are re-read from the gateway on every
// request, so a deleted user or a changed role takes effect immediately.
export interface SessionPayload {
  sub: string;
}

function key(): Uint8Array {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) throw new Error("SESSION_SECRET must be set to at least 32 characters.");
  return new TextEncoder().encode(secret);
}

export async function encrypt(payload: SessionPayload): Promise<string> {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${SESSION_HOURS}h`)
    .sign(key());
}

/** Returns the payload of a valid, unexpired token, or null. Never throws on bad input. */
export async function decrypt(token: string | undefined): Promise<SessionPayload | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, key(), { algorithms: ["HS256"] });
    return typeof payload.sub === "string" ? { sub: payload.sub } : null;
  } catch {
    return null;
  }
}

function secureCookies(): boolean {
  // Secure by default in production. COOKIE_SECURE=false allows plain-HTTP setups such as a local Docker run.
  const flag = process.env.COOKIE_SECURE;
  return flag ? flag === "true" : process.env.NODE_ENV === "production";
}

export async function createSession(userId: string): Promise<void> {
  const token = await encrypt({ sub: userId });
  (await cookies()).set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: secureCookies(),
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_HOURS * 3600,
  });
}

export async function readSession(): Promise<SessionPayload | null> {
  return decrypt((await cookies()).get(SESSION_COOKIE)?.value);
}

export async function deleteSession(): Promise<void> {
  (await cookies()).delete(SESSION_COOKIE);
}
