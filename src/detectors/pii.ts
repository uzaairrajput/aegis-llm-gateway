import type { PiiEntity } from "../policy/schema.js";

interface Recognizer {
  entity: PiiEntity;
  pattern: RegExp;
  validate?: (match: string) => boolean;
}

// Order is priority: when matches overlap, the earlier recognizer wins
// (an API key that contains digits is a SECRET, not a PHONE).
const RECOGNIZERS: Recognizer[] = [
  {
    entity: "SECRET",
    pattern:
      /\b(?:sk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g,
  },
  { entity: "EMAIL", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { entity: "CREDIT_CARD", pattern: /\b\d(?:[ -]?\d){12,18}\b/g, validate: luhn },
  { entity: "SSN", pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  {
    entity: "IP_ADDRESS",
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  },
  {
    entity: "PHONE",
    pattern: /(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]?\d{3,4}(?!\w)/g,
    validate: (m) => {
      const digits = m.replace(/\D/g, "").length;
      return digits >= 10 && digits <= 15;
    },
  },
];

function luhn(match: string): boolean {
  const digits = match.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

const PLACEHOLDER = /\[([A-Z_]+_\d+)\]/g;
export const MAX_PLACEHOLDER_LENGTH = 24;

/**
 * Per-request mapping between real values and placeholders. The same value always maps to
 * the same placeholder, so the model can still reason about "the email from before".
 */
export class PiiVault {
  private byValue = new Map<string, string>();
  private byPlaceholder = new Map<string, string>();
  private counters = new Map<PiiEntity, number>();

  placeholderFor(entity: PiiEntity, value: string): string {
    const existing = this.byValue.get(value);
    if (existing) return existing;
    const n = (this.counters.get(entity) ?? 0) + 1;
    this.counters.set(entity, n);
    const placeholder = `[${entity}_${n}]`;
    this.byValue.set(value, placeholder);
    this.byPlaceholder.set(placeholder, value);
    return placeholder;
  }

  rehydrate(text: string): string {
    if (this.byPlaceholder.size === 0) return text;
    return text.replace(PLACEHOLDER, (whole) => this.byPlaceholder.get(whole) ?? whole);
  }

  get size(): number {
    return this.byPlaceholder.size;
  }
}

export interface RedactionResult {
  text: string;
  counts: Partial<Record<PiiEntity, number>>;
}

export function redact(text: string, entities: ReadonlySet<PiiEntity>, vault: PiiVault): RedactionResult {
  const accepted: { start: number; end: number; entity: PiiEntity }[] = [];

  for (const r of RECOGNIZERS) {
    if (!entities.has(r.entity)) continue;
    for (const m of text.matchAll(r.pattern)) {
      const start = m.index;
      const end = start + m[0].length;
      if (r.validate && !r.validate(m[0])) continue;
      if (accepted.some((a) => start < a.end && end > a.start)) continue;
      accepted.push({ start, end, entity: r.entity });
    }
  }
  if (accepted.length === 0) return { text, counts: {} };

  accepted.sort((a, b) => a.start - b.start);
  const counts: Partial<Record<PiiEntity, number>> = {};
  let out = "";
  let cursor = 0;
  for (const a of accepted) {
    out += text.slice(cursor, a.start) + vault.placeholderFor(a.entity, text.slice(a.start, a.end));
    counts[a.entity] = (counts[a.entity] ?? 0) + 1;
    cursor = a.end;
  }
  return { text: out + text.slice(cursor), counts };
}
