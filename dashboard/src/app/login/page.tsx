import type { Metadata } from "next";
import { Suspense } from "react";
import { LoginForm } from "./login-form";

export const metadata: Metadata = { title: "Sign in — Aegis" };

export default function LoginPage() {
  return (
    <div className="mx-auto mt-10 max-w-sm sm:mt-16">
      <div className="rounded-xl border border-line bg-surface p-6 sm:p-8">
        <h1 className="text-xl font-semibold text-ink">Sign in</h1>
        <p className="mt-1 text-sm text-ink-2">Aegis security dashboard</p>
        <Suspense>
          <LoginForm />
        </Suspense>
      </div>
      <p className="mt-4 text-center text-xs text-muted">
        Accounts are created by an administrator with <code className="font-mono">npm run user</code>.
      </p>
    </div>
  );
}
