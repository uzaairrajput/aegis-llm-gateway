import type { Metadata } from "next";
import { Suspense } from "react";
import { UserNav } from "@/components/user-nav";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis — LLM Security Gateway",
  description: "Monitoring for prompt injection, PII redaction, system-prompt leaks and token usage across tenants.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full">
        <header className="border-b border-line bg-surface">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
            <div className="flex items-center gap-2.5">
              <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden className="text-allowed">
                <path d="M12 2l8 3.5v6c0 5-3.4 9.1-8 10.5-4.6-1.4-8-5.5-8-10.5v-6L12 2z" fill="currentColor" />
                <path d="M8.5 12l2.5 2.5 4.5-5" stroke="#fff" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <span className="font-semibold text-ink">Aegis</span>
              <span className="hidden text-sm text-muted sm:inline">LLM Security Gateway</span>
            </div>
            {/* Reads the session cookie, so it streams in behind its own boundary. */}
            <Suspense>
              <UserNav />
            </Suspense>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6">{children}</main>
      </body>
    </html>
  );
}
