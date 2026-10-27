import { formatCount, formatPercent } from "@/lib/format";

/** Horizontal bars for a ranked list: one series, value at the bar tip, label on the left. */
export function BarList({ items, mono = false }: { items: { label: string; value: number }[]; mono?: boolean }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="space-y-2.5">
      {items.map((item) => (
        <li key={item.label} className="grid grid-cols-[minmax(0,11rem)_1fr] items-center gap-3 sm:grid-cols-[minmax(0,15rem)_1fr]">
          <span className={`truncate text-sm text-ink-2 ${mono ? "font-mono text-xs" : ""}`} title={item.label}>
            {item.label}
          </span>
          <span className="flex items-center gap-2" title={`${item.label}: ${formatCount(item.value)}`}>
            <span
              className="h-3 rounded-r bg-allowed"
              style={{ width: `${Math.max(1, (item.value / max) * 100) * 0.85}%` }}
            />
            <span className="tabular text-sm text-ink">{formatCount(item.value)}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

/** Usage against a limit. The fill carries severity; the track is a lighter step of the same ramp. */
export function Meter({ value, max, label }: { value: number; max: number; label: string }) {
  const ratio = max > 0 ? value / max : 0;
  const severity = ratio >= 0.9 ? "critical" : ratio >= 0.7 ? "warning" : "ok";
  const fill = severity === "critical" ? "var(--critical)" : severity === "warning" ? "var(--warning)" : "var(--allowed)";
  return (
    <div>
      <div
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={value}
        className="h-2 w-full overflow-hidden rounded-full bg-meter-track"
      >
        <div className="h-full rounded-full" style={{ width: `${Math.min(100, ratio * 100)}%`, background: fill }} />
      </div>
      <p className="mt-1 text-xs text-ink-2">
        <span className="tabular">{formatPercent(ratio)}</span> of {formatCount(max)}
        {severity !== "ok" && <span className="ml-1.5 font-semibold text-ink">{severity === "critical" ? "· Near limit" : "· High usage"}</span>}
      </p>
    </div>
  );
}
