// In-memory rate limiter.

// Small in-process rate limiter. It is intentionally conservative and is a
// baseline, not a replacement for edge/WAF rate limiting in production.
const rateBuckets = new Map();

function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  const existing = rateBuckets.get(key);
  if (!existing || existing.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  existing.count += 1;
  return existing.count <= limit;
}

function clearRateLimit(key) {
  rateBuckets.delete(key);
}

module.exports = {
  rateBuckets,
  rateLimit,
  clearRateLimit,
};
