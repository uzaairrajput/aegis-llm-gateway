"use client";

import { useEffect } from "react";

export default function Error({ error, retry }: { error: unknown; retry: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div role="alert" className="rounded-xl border border-line bg-surface p-6">
      <p className="font-semibold text-ink">Something went wrong rendering this page.</p>
      <button type="button" onClick={() => retry()} className="mt-3 rounded-md border border-line px-3 py-1.5 text-sm text-ink hover:bg-hover">
        Try again
      </button>
    </div>
  );
}
