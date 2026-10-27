import { Suspense } from "react";
import { Meter } from "@/components/bars";
import { Card, EmptyState, GatewayError, NoAccess, Skeleton } from "@/components/ui";
import { getStats, getTenants } from "@/lib/aegis";
import { authorize, ROLE_LABELS } from "@/lib/auth";
import { formatCount, formatPercent } from "@/lib/format";

export default function TenantsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-ink">Tenants</h1>
        <p className="text-sm text-ink-2">Each team gets its own API key, policy, rate limit and monthly token budget.</p>
      </div>
      <Suspense fallback={<Skeleton className="h-72" />}>
        <Tenants />
      </Suspense>
    </div>
  );
}

async function Tenants() {
  const access = await authorize("/tenants");
  if (access.kind === "error") return <GatewayError message={access.message} />;
  if (access.kind === "forbidden") return <NoAccess role={ROLE_LABELS[access.user.role]} />;

  const [tenants, stats] = await Promise.all([getTenants(), getStats(168)]);
  if (!tenants.ok) return <GatewayError message={tenants.error} />;
  const weekly = new Map(stats.ok ? stats.data.byTenant.map((t) => [t.tenant, t]) : []);

  if (tenants.data.tenants.length === 0) {
    return (
      <Card>
        <EmptyState>
          No tenants yet. Create one with <code className="font-mono">npm run tenant -- create &lt;name&gt;</code>.
        </EmptyState>
      </Card>
    );
  }

  return (
    <Card>
      <div className="-mx-5 overflow-x-auto px-5">
        <table className="w-full min-w-[760px] text-sm">
          <thead className="text-left text-ink-2">
            <tr>
              <th className="py-2 pr-4 font-normal">Tenant</th>
              <th className="py-2 pr-4 font-normal">Policy</th>
              <th className="py-2 pr-4 text-right font-normal">Rate limit</th>
              <th className="py-2 pr-4 text-right font-normal">Requests (7d)</th>
              <th className="py-2 pr-4 text-right font-normal">Block rate (7d)</th>
              <th className="w-56 py-2 font-normal">Tokens this month</th>
            </tr>
          </thead>
          <tbody className="tabular">
            {tenants.data.tenants.map((t) => {
              const w = weekly.get(t.name);
              return (
                <tr key={t.id} className="border-t border-line align-top">
                  <td className="py-3 pr-4">
                    <span className="font-semibold text-ink">{t.name}</span>
                    <div className="font-mono text-xs text-muted">{t.keyPrefix}…</div>
                  </td>
                  <td className="py-3 pr-4 text-ink">
                    {t.policy}
                    <div className="text-xs text-muted">{t.mode === "monitor" ? "Monitor only (no blocking)" : "Enforcing"}</div>
                  </td>
                  <td className="py-3 pr-4 text-right text-ink-2">{t.requestsPerMinute ? `${t.requestsPerMinute}/min` : "–"}</td>
                  <td className="py-3 pr-4 text-right text-ink">{formatCount(w?.requests ?? 0)}</td>
                  <td className="py-3 pr-4 text-right text-ink">{w?.requests ? formatPercent(w.blocked / w.requests) : "–"}</td>
                  <td className="py-3">
                    {t.monthlyTokenBudget ? (
                      <>
                        <p className="mb-1 text-ink">{formatCount(t.monthTokens)}</p>
                        <Meter value={t.monthTokens} max={t.monthlyTokenBudget} label={`${t.name} monthly token usage`} />
                      </>
                    ) : (
                      formatCount(t.monthTokens)
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
