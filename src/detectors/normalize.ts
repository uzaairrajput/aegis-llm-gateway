// Zero-width and formatting characters attackers use to split trigger words ("ig​nore").
const INVISIBLE = /[­᠎​-‏‪-‮⁠-⁤﻿]/g;
// Unicode "tag" block (U+E0000–U+E007F). Renders as nothing, but models read it as ASCII ("ASCII smuggling").
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;
const BASE64_RUN = /[A-Za-z0-9+/]{24,}={0,2}/g;

export interface NormalizedText {
  /** NFKC-folded, invisible characters removed, lowercased, whitespace collapsed. */
  text: string;
  invisibleCount: number;
  /** ASCII hidden in Unicode tag characters, decoded. */
  smuggled: string;
  /** Printable payloads found in base64 runs, decoded. */
  decoded: string[];
  /** Text with leetspeak and letter-spacing undone, or null when that changes nothing. */
  deobfuscated: string | null;
}

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s" };

// "1gn0re" → "ignore". Only tokens mixing letters with leet characters change; plain numbers are left alone.
function deleet(text: string): string {
  return text.replace(/[a-z0-9@$]+/g, (tok) => (/[a-z]/.test(tok) && /[013457@$]/.test(tok) ? tok.replace(/[013457@$]/g, (c) => LEET[c]!) : tok));
}

// "i g n o r e   a l l" → "ignore all". Letters are single-spaced, words are separated by 2+ spaces.
function despace(raw: string): string {
  if (!/(?:\b\w\b ){4,}/.test(raw)) return raw;
  return raw.replace(/ {2,}/g, "\u0000").replace(/(?<=\b\w) (?=\w\b)/g, "").replace(/\u0000/g, " ");
}

export function normalize(raw: string): NormalizedText {
  const invisibleCount = raw.match(INVISIBLE)?.length ?? 0;

  let smuggled = "";
  for (const ch of raw.match(TAG_CHARS) ?? []) {
    const ascii = ch.codePointAt(0)! - 0xe0000;
    if (ascii >= 0x20 && ascii < 0x7f) smuggled += String.fromCharCode(ascii);
  }

  const decoded: string[] = [];
  for (const run of raw.match(BASE64_RUN) ?? []) {
    const text = Buffer.from(run, "base64").toString("utf8");
    if (isMostlyPrintable(text)) decoded.push(fold(text));
  }

  const visible = raw.replace(TAG_CHARS, "").replace(INVISIBLE, "");
  const text = fold(visible);
  const deobfuscated = deleet(fold(despace(visible)));

  return {
    text,
    invisibleCount,
    smuggled: fold(smuggled),
    decoded,
    deobfuscated: deobfuscated === text ? null : deobfuscated,
  };
}

function fold(text: string): string {
  return text.normalize("NFKC").replace(INVISIBLE, "").toLowerCase().replace(/\s+/g, " ").trim();
}

function isMostlyPrintable(text: string): boolean {
  if (text.length < 12) return false;
  const printable = text.match(/[\x20-\x7E]/g)?.length ?? 0;
  return printable / text.length > 0.9 && /[a-z]{3,}\s+[a-z]{2,}/i.test(text);
}
