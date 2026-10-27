import { Suspense } from "react";
import { BarList } from "@/components/bars";
import { WindowPicker } from "@/components/nav";
import { TrafficChart } from "@/components/traffic-chart";
import { Card, EmptyState, GatewayError, Skeleton, StatTile } from "@/components/ui";
import { getStats, getTimeseries, parseWindow, WINDOWS, type Stats } from "@/lib/aegis";
import { formatCount, formatMs, formatPercent, reasonLabel, THREAT_REASONS } from "@/lib/format";

export default function OverviewPage({ searchParams }: PageProps<"/">) {
  return (
    <Suspense fallback={<OverviewSkeleton />}>
      <Overview searchParams={searchParams} />
    </Suspense>
  );
}

async function Overview({ searchParams }: Pick<PageProps<"/">, "searchParams">) {
  const hours = parseWindow((await searchParams).hours);
  const windowLabel = WINDOWS.find((w) => w.hours === hours)!.label;
  const [stats, series] = await Promise.all([getStats(hours), getTimeseries(hours)]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-ink">Overview</h1>
          <p className="text-sm text-ink-2">Last {windowLabel}, all tenants</p>
        </div>
        <WindowPicker current={hours} />
      </div>

      {!stats.ok ? (
        <GatewayError message={stats.error} />
      ) : (
        <>
          <Headline stats={stats.data} />

          <Card title="Requests by decision" subtitle="Every request through the gateway, per period">
            {series.ok ? (
              series.data.points.some((p) => p.allowed + p.flagged + p.blocked > 0) ? (
                <TrafficChart points={series.data.points} bucketMs={series.data.bucket_ms} />
              ) : (
                <EmptyState>No traffic in this window. Run <code className="font-mono">npm run seed</code> for demo data.</EmptyState>
              )
            ) : (
              <EmptyState>{series.error}</EmptyState>
            )}
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card title="Why requests were blocked or flagged" subtitle="Requests by reason">
              {stats.data.reasons.length ? (
                <BarList items={stats.data.reasons.map((r) => ({ label: reasonLabel(r.reason), value: r.count }))} />
              ) : (
                <EmptyState>Nothing blocked or flagged.</EmptyState>
              )}
            </Card>
            <Card title="Most triggered rules" subtitle="Detector rules matched on blocked or flagged requests">
              {stats.data.topRules.length ? (
                <BarList mono items={stats.data.topRules.map((r) => ({ label: r.rule, value: r.count }))} />
              ) : (
                <EmptyState>No rules triggered.</EmptyState>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}

function Headline({ stats }: { stats: Stats }) {
  const threats = stats.reasons.filter((r) => THREAT_REASONS.has(r.reason)).reduce((n, r) => n + r.count, 0);
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,2fr)]">
      <div className="rounded-xl border border-line bg-surface p-5">
        <p className="text-sm text-ink-2">Threats detected</p>
        <p className="mt-1 text-5xl font-semibold text-ink">{formatCount(threats)}</p>
        <p className="mt-2 text-sm text-ink-2">
          Prompt injections, indirect injections, system-prompt leaks and blocked topics across{" "}
          <span className="tabular">{formatCount(stats.requests)}</span> requests. Blocked under enforcing policies, flagged under
          monitor-only ones.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <StatTile label="Requests" value={formatCount(stats.requests)} detail={`${formatCount(stats.tokens)} tokens`} />
        <StatTile
          label="Block rate"
          value={formatPercent(stats.requests ? stats.blocked / stats.requests : 0)}
          detail={`${formatCount(stats.blocked)} blocked · ${formatCount(stats.flagged)} flagged`}
        />
        <StatTile label="PII values redacted" value={formatCount(stats.piiRedacted)} detail="Never sent to the model provider" />
        <StatTile
          label="Inspection latency p95"
          value={formatMs(stats.inspectLatencyMs.p95)}
          detail={`p50 ${formatMs(stats.inspectLatencyMs.p50)} · p99 ${formatMs(stats.inspectLatencyMs.p99)}`}
        />
      </div>
    </div>
  );
}

function OverviewSkeleton() {
  return (
    <div className="space-y-6" aria-busy>
      <Skeleton className="h-12 w-64" />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,2fr)]">
        <Skeleton className="h-44" />
        <Skeleton className="h-44" />
      </div>
      <Skeleton className="h-80" />
    </div>
  );
}
