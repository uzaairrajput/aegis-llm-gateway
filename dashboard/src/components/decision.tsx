import type { Decision } from "@/lib/aegis";

// Each decision has an icon + label as well as a color, so identity never depends on color alone.
export const DECISIONS: Record<Decision, { label: string; color: string }> = {
  allowed: { label: "Allowed", color: "var(--allowed)" },
  flagged: { label: "Flagged", color: "var(--flagged)" },
  blocked: { label: "Blocked", color: "var(--blocked)" },
};

export function DecisionIcon({ decision, size = 14 }: { decision: Decision; size?: number }) {
  const common = { width: size, height: size, viewBox: "0 0 16 16", fill: "none", "aria-hidden": true } as const;
  const color = DECISIONS[decision].color;
  if (decision === "allowed") {
    return (
      <svg {...common}>
        <circle cx="8" cy="8" r="7" fill={color} />
        <path d="M4.8 8.2l2.1 2.1 4.3-4.6" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    );
  }
  if (decision === "flagged") {
    return (
      <svg {...common}>
        <circle cx="8" cy="8" r="7" fill={color} />
        <path d="M6 11.5V4.5h4.2l-.9 1.6.9 1.6H6" stroke="#fff" strokeWidth="1.5" strokeLinejoin="round" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <circle cx="8" cy="8" r="7" fill={color} />
      <path d="M4.7 8h6.6" stroke="#fff" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm text-ink">
      <DecisionIcon decision={decision} />
      {DECISIONS[decision].label}
    </span>
  );
}
