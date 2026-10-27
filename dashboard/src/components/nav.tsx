"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { WINDOWS } from "@/lib/windows";

/** Links are filtered by role on the server; this only renders them and marks the active one. */
export function NavLinks({ links }: { links: { href: string; label: string }[] }) {
  const pathname = usePathname();
  return (
    <nav className="flex gap-1" aria-label="Main">
      {links.map((link) => {
        const active = link.href === "/" ? pathname === "/" : pathname.startsWith(link.href);
        return (
          <Link
            key={link.href}
            href={link.href}
            aria-current={active ? "page" : undefined}
            className={`rounded-md px-3 py-1.5 text-sm ${active ? "bg-hover font-semibold text-ink" : "text-ink-2 hover:bg-hover hover:text-ink"}`}
          >
            {link.label}
          </Link>
        );
      })}
    </nav>
  );
}

/** Time-window presets, kept in the URL so views are shareable. */
export function WindowPicker({ current }: { current: number }) {
  const pathname = usePathname();
  const params = useSearchParams();
  return (
    <div role="radiogroup" aria-label="Time window" className="inline-flex rounded-lg border border-line bg-surface p-0.5">
      {WINDOWS.map((w) => {
        const next = new URLSearchParams(params);
        next.set("hours", String(w.hours));
        const selected = w.hours === current;
        return (
          <Link
            key={w.hours}
            href={`${pathname}?${next}`}
            role="radio"
            aria-checked={selected}
            scroll={false}
            className={`rounded-md px-3 py-1 text-sm ${selected ? "bg-hover font-semibold text-ink" : "text-ink-2 hover:text-ink"}`}
          >
            {w.label}
          </Link>
        );
      })}
    </div>
  );
}
