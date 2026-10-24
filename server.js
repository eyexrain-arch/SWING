/**
 * Swing — dating app server (entry point).
 *
 * This file only wires things together:
 *   src/config.js        environment + constants
 *   src/middleware/      security headers, rate limiting, auth guard, static files
 *   src/routes.js        URL -> handler table
 *   src/handlers/        one file per feature area (auth, profile, photos, discover, ...)
 *   src/services/        business logic and data access shared by handlers
 *   src/lib/             small pure helpers
 *   public/              the browser app (index.html, css/, js/)
 *
 * Storage: Supabase (Postgres for data, Storage bucket "photos" for images).
 */

const http = require('http');
const { PORT } = require('./src/config'); // loads + validates environment first
const { sendJSON } = require('./src/lib/http');
const { applySecurityHeaders, getClientIp, isMutatingMethod, rateLimit, validateOrigin } = require('./src/middleware/security');
const { handleRoute } = require('./src/routes');

const server = http.createServer(async (req, res) => {
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
    await handleRoute(req, res, url);
  } catch (err) {
    console.error('Request error:', err && err.message ? err.message : 'unknown error');
    sendJSON(res, 500, { error: 'Internal server error' });
  }
});

// Log-and-continue instead of letting one unexpected rejection/exception
// crash the whole process (which would drop every other user's in-flight
// request as a connection reset — an intermittent "Load failed" for
// everyone, not just whoever triggered the bug). This is a safety net,
// not a substitute for fixing the underlying bug if one of these fires.
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason && reason.message ? reason.message : reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err && err.message ? err.message : err);
});

server.listen(PORT, () => {
  console.log(`Swing running at http://localhost:${PORT}`);
});
