import "server-only";
import { redirect } from "next/navigation";
import { cache } from "react";
import { getUser, type Role, type User } from "./aegis";
import { readSession } from "./session";

// Data Access Layer: every page authorizes here, on the server, before fetching any data.
// The proxy only does a fast "is there a session cookie?" redirect; it is not the security boundary.

export const PAGES = [
  { href: "/", label: "Overview", roles: ["admin", "analyst", "viewer"] },
  { href: "/events", label: "Audit log", roles: ["admin", "analyst"] },
  { href: "/tenants", label: "Tenants", roles: ["admin"] },
] as const satisfies readonly { href: string; label: string; roles: readonly Role[] }[];

export type PageHref = (typeof PAGES)[number]["href"];

export const ROLE_LABELS: Record<Role, string> = {
  admin: "Admin",
  analyst: "Security analyst",
  viewer: "Viewer",
};

export type Access = { kind: "allowed"; user: User } | { kind: "forbidden"; user: User } | { kind: "error"; message: string };

/** Current user, or null when signed out. Deduplicated per request. */
export const getCurrentUser = cache(async (): Promise<User | null | { error: string }> => {
  const session = await readSession();
  if (!session) return null;
  const res = await getUser(session.sub);
  if (res.ok) return res.data.user;
  // The user was deleted since signing in: treat the session as ended.
  if (res.status === 404) return null;
  return { error: res.error };
});

/** Authorizes the current request for a page. Redirects to sign-in when there is no valid session. */
export async function authorize(page: PageHref): Promise<Access> {
  const user = await getCurrentUser();
  if (user === null) redirect(`/login?next=${encodeURIComponent(page)}&expired=1`);
  if ("error" in user) return { kind: "error", message: user.error };
  const roles: readonly Role[] = PAGES.find((p) => p.href === page)!.roles;
  return roles.includes(user.role) ? { kind: "allowed", user } : { kind: "forbidden", user };
}

export function pagesFor(role: Role) {
  return PAGES.filter((p) => (p.roles as readonly Role[]).includes(role));
}

/** Only same-site relative paths are accepted as post-login destinations (no open redirects). */
export function safeNext(value: unknown): string {
  const next = typeof value === "string" ? value : "";
  return next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\") && !next.startsWith("/login") ? next : "/";
}
