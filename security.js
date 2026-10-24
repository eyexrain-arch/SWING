/**
 * Security middleware: headers, origin check, client IP, in-process rate limiter.
 */

const { IS_PRODUCTION, SUPABASE_ORIGIN, TRUST_PROXY } = require('../config');

function isMutatingMethod(method) {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
}

function getClientIp(req) {
  if (TRUST_PROXY) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (forwarded) return forwarded;
  }
  return req.socket.remoteAddress || 'unknown';
}

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

function validateOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // same-origin form/fetches often omit Origin
  const host = req.headers.host;
  if (!host) return false;
  try {
    const originUrl = new URL(origin);
    const expectedProtocol = (IS_PRODUCTION || req.headers['x-forwarded-proto'] === 'https') ? 'https:' : 'http:';
    return originUrl.host === host && originUrl.protocol === expectedProtocol;
  } catch (_) {
    return false;
  }
}

function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: ${SUPABASE_ORIGIN}; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';`);
  if (IS_PRODUCTION || TRUST_PROXY) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
}

setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) {
    if (bucket.resetAt <= now) rateBuckets.delete(key);
  }
}, 5 * 60 * 1000).unref();

module.exports = {
  applySecurityHeaders,
  clearRateLimit,
  getClientIp,
  isMutatingMethod,
  rateLimit,
  validateOrigin,
};
