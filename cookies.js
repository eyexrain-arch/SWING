/**
 * Session cookie helpers.
 */

const { COOKIE_SECURE, SESSION_COOKIE, SESSION_TTL_MS } = require('../config');

function cookieFlags(maxAgeSeconds) {
  const parts = [
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  if (COOKIE_SECURE) parts.push('Secure');
  return parts.join('; ');
}

function setSessionCookie(res, token, maxAgeSeconds = SESSION_TTL_MS / 1000) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token ? encodeURIComponent(token) : ''}; ${cookieFlags(maxAgeSeconds)}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', cookieFlags(0));
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

function getAuthToken(req) {
  const token = getCookie(req, SESSION_COOKIE);
  return token && token.length <= 256 ? token : null;
}

module.exports = {
  clearSessionCookie,
  getAuthToken,
  setSessionCookie,
};
