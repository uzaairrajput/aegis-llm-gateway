"use client";

import { useSearchParams } from "next/navigation";
import { useActionState } from "react";
import { login, type LoginState } from "@/app/actions/auth";

export function LoginForm() {
  const params = useSearchParams();
  const [state, action, pending] = useActionState<LoginState, FormData>(login, undefined);
  const expired = params.get("expired") === "1" && !state;

  return (
    <form action={action} className="mt-6 space-y-4" noValidate>
      <input type="hidden" name="next" value={params.get("next") ?? "/"} />

      {expired && (
        <p className="rounded-md border border-line bg-hover px-3 py-2 text-sm text-ink-2">Your session ended. Sign in again to continue.</p>
      )}
      {state?.error && (
        <p role="alert" className="flex items-start gap-2 rounded-md border border-line bg-hover px-3 py-2 text-sm text-ink">
          <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden className="mt-0.5 shrink-0">
            <circle cx="8" cy="8" r="7" fill="var(--critical)" />
            <path d="M8 4.5v4.2M8 11.2v.3" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" />
          </svg>
          {state.error}
        </p>
      )}

      <div>
        <label htmlFor="email" className="mb-1 block text-sm text-ink-2">
          Email
        </label>
        <input
          id="email"
          name="email"
          type="email"
          autoComplete="username"
          required
          autoFocus
          defaultValue={state?.email}
          className="w-full rounded-md border border-line bg-page px-3 py-2 text-ink outline-none focus:border-allowed"
        />
      </div>
      <div>
        <label htmlFor="password" className="mb-1 block text-sm text-ink-2">
          Password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          className="w-full rounded-md border border-line bg-page px-3 py-2 text-ink outline-none focus:border-allowed"
        />
      </div>
      <button
        type="submit"
        disabled={pending}
        className="w-full rounded-md bg-allowed px-3 py-2 text-sm font-semibold text-white hover:opacity-90 disabled:opacity-60"
      >
        {pending ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
