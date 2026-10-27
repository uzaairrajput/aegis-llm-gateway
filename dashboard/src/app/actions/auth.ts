"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { verifyCredentials } from "@/lib/aegis";
import { safeNext } from "@/lib/auth";
import { createSession, deleteSession } from "@/lib/session";

export type LoginState = { error: string; email: string } | undefined;

export async function login(_prev: LoginState, formData: FormData): Promise<LoginState> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const next = safeNext(formData.get("next"));
  if (!email || !password) return { error: "Enter your email and password.", email };

  // Forwarded so the gateway can rate-limit per end user. Only trustworthy behind a proxy that sets it.
  const h = await headers();
  const clientIp = h.get("x-forwarded-for")?.split(",")[0]?.trim() || h.get("x-real-ip") || undefined;

  const result = await verifyCredentials(email, password, clientIp);
  if (!result.ok) {
    const error = result.status === 0 ? "The Aegis gateway is unreachable. Try again shortly." : result.error;
    return { error, email };
  }

  await createSession(result.data.user.id);
  redirect(next);
}

export async function logout(): Promise<void> {
  await deleteSession();
  redirect("/login");
}
