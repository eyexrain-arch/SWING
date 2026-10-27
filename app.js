// Request pipeline used by server.js.
const { applySecurityHeaders, getClientIp, isMutatingMethod, sendJSON, validateOrigin } = require('./lib/http');
const { rateLimit } = require('./lib/rateLimit');
const { dispatch } = require('./routes/index');

// Per-request pipeline: security headers -> origin check -> rate limit -> router.
async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const { pathname } = url;
  applySecurityHeaders(res);

  // Reject cross-site state-changing requests. SameSite=Strict is the second
  // layer, but defense in depth matters for a dating app holding private data.
  if (isMutatingMethod(req.method) && !validateOrigin(req)) {
    return sendJSON(res, 403, { error: 'Cross-site request blocked' });
  }

  const ip = getClientIp(req);
  const apiRequest = pathname.startsWith('/api/');
  if (apiRequest) {
    const authPaths = ['/api/login', '/api/register', '/api/forgot-password', '/api/reset-password'];
    const generalLimit = authPaths.includes(pathname) ? 10 : 120;
    const windowMs = 60 * 1000;
    const key = `${pathname}:${ip}`;
    if (!rateLimit(key, generalLimit, windowMs)) {
      return sendJSON(res, 429, { error: 'Too many requests. Please try again shortly.' }, { 'Retry-After': '60' });
    }
    // Extra, longer-window cap specifically on the two account-recovery
    // endpoints — they're the ones an attacker would use to spam codes or
    // brute-force a reset code, so they get a stricter per-IP ceiling on
    // top of the per-minute one above.
    if (pathname === '/api/forgot-password' || pathname === '/api/reset-password') {
      if (!rateLimit(`recovery:${ip}`, 8, 15 * 60 * 1000)) {
        return sendJSON(res, 429, { error: 'Too many requests. Please try again later.' });
      }
    }
  }

  try {
    return await dispatch(req, res, url, pathname);
  } catch (err) {
    console.error('Request error:', err && err.message ? err.message : 'unknown error',
      err && err.code ? `[code ${err.code}]` : '', err && err.hint ? `[hint ${err.hint}]` : '');
    sendJSON(res, 500, { error: 'Internal server error' });
  }
}

module.exports = {
  handleRequest,
};
