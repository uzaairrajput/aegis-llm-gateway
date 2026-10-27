import Link from "next/link";
import { Suspense } from "react";
import { DecisionBadge, DecisionIcon } from "@/components/decision";
import { Card, EmptyState, GatewayError, Skeleton } from "@/components/ui";
import { getEvents, getTenants, type Decision } from "@/lib/aegis";
import { formatDateTime, formatMs, reasonLabel } from "@/lib/format";

const FILTERS: { value: Decision | undefined; label: string }[] = [
  { value: undefined, label: "All" },
  { value: "blocked", label: "Blocked" },
  { value: "flagged", label: "Flagged" },
  { value: "allowed", label: "Allowed" },
];

export default function EventsPage({ searchParams }: PageProps<"/events">) {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-ink">Audit log</h1>
        <p className="text-sm text-ink-2">The 100 most recent requests. Prompts are never stored, only findings and metadata.</p>
      </div>
      <Suspense fallback={<Skeleton className="h-96" />}>
        <Events searchParams={searchParams} />
      </Suspense>
    </div>
  );
}

async function Events({ searchParams }: Pick<PageProps<"/events">, "searchParams">) {
  const params = await searchParams;
  const decision = FILTERS.find((f) => f.value === params.decision)?.value;
  const [events, tenants] = await Promise.all([getEvents({ limit: 100, decision }), getTenants()]);
  if (!events.ok) return <GatewayError message={events.error} />;
  const tenantName = new Map(tenants.ok ? tenants.data.tenants.map((t) => [t.id, t.name]) : []);

  return (
    <Card
      action={
        <nav aria-label="Filter by decision" className="flex flex-wrap gap-1">
          {FILTERS.map((f) => {
            const active = f.value === decision;
            return (
              <Link
                key={f.label}
                href={f.value ? `/events?decision=${f.value}` : "/events"}
                aria-current={active ? "true" : undefined}
                className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-sm ${active ? "border-axis bg-hover font-semibold text-ink" : "border-line text-ink-2 hover:text-ink"}`}
              >
                {f.value && <DecisionIcon decision={f.value} size={12} />}
                {f.label}
              </Link>
            );
          })}
        </nav>
      }
      title="Requests"
    >
      {events.data.events.length === 0 ? (
        <EmptyState>No requests match this filter.</EmptyState>
      ) : (
        <div className="-mx-5 overflow-x-auto px-5">
          <table className="w-full min-w-[820px] text-sm">
            <thead className="text-left text-ink-2">
              <tr>
                <th className="py-2 pr-4 font-normal">Time</th>
                <th className="py-2 pr-4 font-normal">Tenant</th>
                <th className="py-2 pr-4 font-normal">Decision</th>
                <th className="py-2 pr-4 font-normal">Reason</th>
                <th className="py-2 pr-4 text-right font-normal">Injection score</th>
                <th className="py-2 pr-4 text-right font-normal">PII</th>
                <th className="py-2 pr-4 text-right font-normal">Inspect</th>
                <th className="py-2 font-normal">Findings</th>
              </tr>
            </thead>
            <tbody className="tabular">
              {events.data.events.map((e) => (
                <tr key={e.requestId} className="border-t border-line align-top">
                  <td className="whitespace-nowrap py-2 pr-4 text-ink-2">{formatDateTime(e.ts)}</td>
                  <td className="py-2 pr-4 text-ink">
                    {tenantName.get(e.tenantId) ?? e.tenantId.slice(0, 8)}
                    <div className="text-xs text-muted">{e.model ?? "–"}</div>
                  </td>
                  <td className="py-2 pr-4">
                    <DecisionBadge decision={e.decision} />
                    <div className="text-xs text-muted">HTTP {e.status}</div>
                  </td>
                  <td className="py-2 pr-4 text-ink-2">{reasonLabel(e.reason)}</td>
                  <td className="py-2 pr-4 text-right text-ink">{e.injectionScore.toFixed(2)}</td>
                  <td className="py-2 pr-4 text-right text-ink">{e.piiRedacted || "–"}</td>
                  <td className="py-2 pr-4 text-right text-ink-2">{formatMs(e.inspectMs)}</td>
                  <td className="py-2">
                    {e.findings.length === 0 ? (
                      <span className="text-muted">–</span>
                    ) : (
                      <details>
                        <summary className="cursor-pointer text-ink-2 hover:text-ink">
                          {e.findings.length} finding{e.findings.length === 1 ? "" : "s"}
                        </summary>
                        <ul className="mt-1.5 space-y-1">
                          {e.findings.map((f, i) => (
                            <li key={i} className="text-xs">
                              <span className="font-mono text-ink">{f.rule}</span>
                              {f.excerpt && <span className="block max-w-xs truncate text-muted" title={f.excerpt}>“{f.excerpt}”</span>}
                            </li>
                          ))}
                        </ul>
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
