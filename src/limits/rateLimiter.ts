interface Bucket {
  tokens: number;
  updatedAt: number;
}

/**
 * In-process token bucket per key. Allows short bursts up to the per-minute limit and refills
 * continuously. Single-instance only; a multi-replica deployment needs the Redis implementation.
 */
export class RateLimiter {
  private buckets = new Map<string, Bucket>();

  take(key: string, perMinute: number, now = Date.now()): { ok: true } | { ok: false; retryAfterSec: number } {
    const ratePerMs = perMinute / 60_000;
    const bucket = this.buckets.get(key) ?? { tokens: perMinute, updatedAt: now };
    bucket.tokens = Math.min(perMinute, bucket.tokens + (now - bucket.updatedAt) * ratePerMs);
    bucket.updatedAt = now;
    this.buckets.set(key, bucket);

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { ok: true };
    }
    return { ok: false, retryAfterSec: Math.ceil((1 - bucket.tokens) / ratePerMs / 1000) };
  }
}
