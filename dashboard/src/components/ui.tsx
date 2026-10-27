import type { ReactNode } from "react";

export function Card({ title, subtitle, action, children, className = "" }: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-xl border border-line bg-surface p-5 ${className}`}>
      {(title || action) && (
        <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            {title && <h2 className="text-sm font-semibold text-ink">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-sm text-ink-2">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function StatTile({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="rounded-xl border border-line bg-surface p-4">
      <p className="text-sm text-ink-2">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-ink">{value}</p>
      {detail && <p className="mt-1 text-xs text-muted">{detail}</p>}
    </div>
  );
}

export function GatewayError({ message }: { message: string }) {
  return (
    <div role="alert" className="rounded-xl border border-line bg-surface p-6">
      <p className="font-semibold text-ink">Can&apos;t load data from the gateway</p>
      <p className="mt-1 text-sm text-ink-2">{message}</p>
      <p className="mt-3 text-sm text-ink-2">
        Start it with <code className="font-mono text-ink">npm run dev</code> in the <code className="font-mono text-ink">aegis</code> folder, and
        check <code className="font-mono text-ink">AEGIS_URL</code> and <code className="font-mono text-ink">AEGIS_ADMIN_TOKEN</code> in{" "}
        <code className="font-mono text-ink">dashboard/.env.local</code>.
      </p>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="py-8 text-center text-sm text-muted">{children}</p>;
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded-xl border border-line bg-surface ${className}`} />;
}
