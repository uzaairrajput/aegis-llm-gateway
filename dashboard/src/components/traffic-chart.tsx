"use client";

import { useEffect, useRef, useState } from "react";
import type { TimeseriesPoint } from "@/lib/aegis";
import { formatCount } from "@/lib/format";
import { DECISIONS, DecisionIcon } from "./decision";

const STACK = ["allowed", "flagged", "blocked"] as const; // bottom → top
const HEIGHT = 260;
const M = { top: 12, right: 8, bottom: 28, left: 44 };
const GAP = 2; // surface gap between stacked segments
const MAX_COL = 24;
const RADIUS = 4;
const HOUR = 3_600_000;

const utc = (opts: Intl.DateTimeFormatOptions) => new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", hour12: false, ...opts });
const fmtHour = utc({ hour: "2-digit", minute: "2-digit" });
const fmtDay = utc({ day: "numeric", month: "short" });
const fmtDayHour = utc({ day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

function niceStep(max: number, ticks = 4): number {
  const raw = Math.max(max, 1) / ticks;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const norm = raw / mag;
  const step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * mag;
  return Math.max(1, step);
}

/** Column with a rounded data-end and a square baseline. */
function columnPath(x: number, y: number, w: number, h: number, rounded: boolean): string {
  const r = rounded ? Math.min(RADIUS, h, w / 2) : 0;
  if (r === 0) return `M${x},${y + h}V${y}H${x + w}V${y + h}Z`;
  return `M${x},${y + h}V${y + r}A${r},${r} 0 0 1 ${x + r},${y}H${x + w - r}A${r},${r} 0 0 1 ${x + w},${y + r}V${y + h}Z`;
}

function rangeLabel(t: number, bucketMs: number): string {
  if (bucketMs >= 24 * HOUR) return `${fmtDay.format(t)} UTC`;
  return `${fmtDayHour.format(t)}–${fmtHour.format(t + bucketMs)} UTC`;
}

export function TrafficChart({ points, bucketMs }: { points: TimeseriesPoint[]; bucketMs: number }) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(720);
  const [hovered, setHovered] = useState<number | null>(null);
  const [showTable, setShowTable] = useState(false);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    setWidth(Math.max(280, el.clientWidth));
    const ro = new ResizeObserver(([entry]) => setWidth(Math.max(280, entry!.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const totals = Object.fromEntries(STACK.map((k) => [k, points.reduce((n, p) => n + p[k], 0)])) as Record<(typeof STACK)[number], number>;
  const n = points.length;
  const plotW = width - M.left - M.right;
  const plotH = HEIGHT - M.top - M.bottom;
  const maxTotal = Math.max(0, ...points.map((p) => p.allowed + p.flagged + p.blocked));
  const step = niceStep(maxTotal);
  const yMax = Math.max(step, Math.ceil(maxTotal / step) * step);
  const ticks = Array.from({ length: Math.round(yMax / step) + 1 }, (_, i) => i * step);
  const y = (v: number) => M.top + plotH - (v / yMax) * plotH;
  const slot = n > 0 ? plotW / n : plotW;
  const colW = Math.min(MAX_COL, Math.max(2, slot * 0.7));

  // X labels: whole days for 6-hourly data, otherwise every k-th bucket to avoid crowding.
  const maxLabels = Math.max(2, Math.floor(plotW / 72));
  const labelEvery = Math.ceil(n / maxLabels);
  const xLabel = (p: TimeseriesPoint, i: number): string | null => {
    if (bucketMs === 6 * HOUR) {
      if (new Date(p.t).getUTCHours() !== 0) return null;
      const dayIndex = Math.round(p.t / (24 * HOUR));
      return dayIndex % Math.max(1, Math.ceil(labelEvery / 4)) === 0 ? fmtDay.format(p.t) : null;
    }
    if (i % labelEvery !== 0) return null;
    return bucketMs >= 24 * HOUR ? fmtDay.format(p.t) : fmtHour.format(p.t);
  };

  const onPointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - rect.left) * width) / rect.width;
    const i = Math.floor((x - M.left) / slot);
    setHovered(i >= 0 && i < n ? i : null);
  };

  const hp = hovered !== null ? points[hovered] : undefined;
  const tooltipLeft = hovered !== null ? Math.min(Math.max(M.left + slot * (hovered + 0.5), 100), width - 100) : 0;

  return (
    <div ref={wrapRef}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <ul className="flex flex-wrap gap-x-5 gap-y-1" aria-label="Legend">
          {STACK.map((k) => (
            <li key={k} className="flex items-center gap-1.5 text-sm text-ink-2">
              <DecisionIcon decision={k} />
              <span>{DECISIONS[k].label}</span>
              <span className="tabular text-ink">{formatCount(totals[k])}</span>
            </li>
          ))}
        </ul>
        <button
          type="button"
          onClick={() => setShowTable((v) => !v)}
          aria-pressed={showTable}
          className="rounded-md border border-line px-2.5 py-1 text-xs text-ink-2 hover:bg-hover hover:text-ink"
        >
          {showTable ? "Show chart" : "Show table"}
        </button>
      </div>

      {showTable ? (
        <div className="max-h-[260px] overflow-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-surface text-left text-ink-2">
              <tr>
                <th className="py-1.5 pr-4 font-normal">Period (UTC)</th>
                {STACK.map((k) => (
                  <th key={k} className="py-1.5 pr-4 text-right font-normal">
                    {DECISIONS[k].label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="tabular">
              {points.map((p) => (
                <tr key={p.t} className="border-t border-line">
                  <td className="py-1.5 pr-4 text-ink-2">{rangeLabel(p.t, bucketMs)}</td>
                  {STACK.map((k) => (
                    <td key={k} className="py-1.5 pr-4 text-right">
                      {formatCount(p[k])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="relative">
          {/* viewBox + max-w-full: before the first measurement the chart shrinks to fit instead of overflowing. */}
          <svg
            width={width}
            height={HEIGHT}
            viewBox={`0 0 ${width} ${HEIGHT}`}
            role="img"
            aria-label={`Requests per period by decision: ${STACK.map((k) => `${formatCount(totals[k])} ${DECISIONS[k].label.toLowerCase()}`).join(", ")}.`}
            onPointerMove={onPointerMove}
            onPointerLeave={() => setHovered(null)}
            className="block h-auto max-w-full touch-none select-none"
          >
            {ticks.map((t) => (
              <g key={t}>
                <line x1={M.left} x2={width - M.right} y1={y(t)} y2={y(t)} stroke={t === 0 ? "var(--axis)" : "var(--grid)"} strokeWidth={1} shapeRendering="crispEdges" />
                <text x={M.left - 8} y={y(t)} dy="0.32em" textAnchor="end" className="tabular fill-muted text-[11px]">
                  {formatCount(t)}
                </text>
              </g>
            ))}

            {hovered !== null && <rect x={M.left + slot * hovered} y={M.top} width={slot} height={plotH} fill="var(--hover)" />}

            {points.map((p, i) => {
              const x = M.left + slot * i + (slot - colW) / 2;
              const topKey = [...STACK].reverse().find((k) => p[k] > 0);
              let base = p.allowed + p.flagged + p.blocked > 0 ? y(0) : 0;
              let first = true;
              return (
                <g key={p.t}>
                  {STACK.map((k) => {
                    if (p[k] === 0) return null;
                    const h = (p[k] / yMax) * plotH;
                    const gap = first ? 0 : Math.min(GAP, h / 2);
                    const segTop = base - h;
                    const d = columnPath(x, segTop, colW, h - gap, k === topKey);
                    base = segTop;
                    first = false;
                    return <path key={k} d={d} fill={DECISIONS[k].color} />;
                  })}
                  {(() => {
                    const label = xLabel(p, i);
                    return label ? (
                      <text x={M.left + slot * (i + 0.5)} y={HEIGHT - 8} textAnchor="middle" className="fill-muted text-[11px]">
                        {label}
                      </text>
                    ) : null;
                  })()}
                </g>
              );
            })}
          </svg>

          {hp && (
            <div
              className="pointer-events-none absolute top-0 z-10 w-48 -translate-x-1/2 rounded-lg border border-line bg-surface p-3 text-sm shadow-lg"
              style={{ left: tooltipLeft }}
            >
              <p className="mb-2 text-xs text-ink-2">{rangeLabel(hp.t, bucketMs)}</p>
              {[...STACK].reverse().map((k) => (
                <p key={k} className="flex items-center justify-between gap-3">
                  <span className="flex items-center gap-1.5 text-ink-2">
                    <DecisionIcon decision={k} size={12} />
                    {DECISIONS[k].label}
                  </span>
                  <span className="tabular text-ink">{formatCount(hp[k])}</span>
                </p>
              ))}
              <p className="mt-1.5 flex justify-between border-t border-line pt-1.5">
                <span className="text-ink-2">Total</span>
                <span className="tabular font-semibold text-ink">{formatCount(hp.allowed + hp.flagged + hp.blocked)}</span>
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
