import { CanaryLeakError } from "../detectors/canary.js";
import { MAX_PLACEHOLDER_LENGTH, type PiiVault } from "../detectors/pii.js";

/**
 * Sits between upstream token deltas and the client.
 *
 * Two problems make naive per-chunk processing wrong:
 *  - a placeholder like "[EMAIL_1]" can arrive split across chunks ("[EMA" + "IL_1]"), and
 *  - a canary must be caught before any part of it reaches the client.
 *
 * So we hold back a small tail: enough to cover a partial canary (canary.length - 1 chars)
 * and any unclosed "[" that could still become a placeholder. Everything before that is safe to emit.
 */
export class StreamGuard {
  private pending = "";
  private readonly holdback: number;

  constructor(
    private readonly vault: PiiVault | null,
    private readonly canary: string | null,
  ) {
    this.holdback = canary ? canary.length - 1 : 0;
  }

  push(delta: string): string {
    this.pending += delta;
    this.assertNoCanary();

    let cut = Math.max(0, this.pending.length - this.holdback);
    if (this.vault && cut > 0) {
      // A "[" before the cut whose "]" is missing or after the cut may be a split placeholder.
      const open = this.pending.lastIndexOf("[", cut - 1);
      if (open !== -1) {
        const close = this.pending.indexOf("]", open);
        const straddles = close === -1 || close >= cut;
        if (straddles && this.pending.length - open <= MAX_PLACEHOLDER_LENGTH) cut = open;
      }
    }
    return this.emit(cut);
  }

  flush(): string {
    this.assertNoCanary();
    return this.emit(this.pending.length);
  }

  private emit(cut: number): string {
    const out = this.pending.slice(0, cut);
    this.pending = this.pending.slice(cut);
    return this.vault ? this.vault.rehydrate(out) : out;
  }

  private assertNoCanary() {
    if (this.canary && this.pending.includes(this.canary)) throw new CanaryLeakError();
  }
}
