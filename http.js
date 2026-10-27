// Request/response helpers: body parsing, JSON replies, client IP, origin check, security headers.
const { IS_PRODUCTION, MAX_BODY_BYTES, SESSION_COOKIE, TRUST_PROXY } = require('../config');
const { getCookie } = require('./session');
const { SUPABASE_ORIGIN } = require('../supabase');

function readBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bytes = 0;
    let finished = false;
    req.on('data', chunk => {
      if (finished) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        finished = true;
        reject(new Error(`Request too large (max ${Math.floor(maxBytes / 1024)}KB)`));
        req.destroy();
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      if (finished) return;
      finished = true;
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (_) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', err => {
      if (!finished) { finished = true; reject(err); }
    });
  });
}

function sendJSON(res, status, obj, extraHeaders = {}) {
  const bodyStr = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(bodyStr),
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(bodyStr);
}

function getAuthToken(req) {
  const token = getCookie(req, SESSION_COOKIE);
  return token && token.length <= 256 ? token : null;
}

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

module.exports = {
  readBody,
  sendJSON,
  getAuthToken,
  isMutatingMethod,
  getClientIp,
  validateOrigin,
  applySecurityHeaders,
};
