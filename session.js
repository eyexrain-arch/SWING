// Session tokens, cookies and the sessions table.
const crypto = require('crypto');
const { COOKIE_SECURE, SESSION_COOKIE, SESSION_RENEW_THRESHOLD_MS, SESSION_TTL_MS } = require('../config');
const { supabase } = require('../supabase');

function makeToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashSessionToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

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

// ⚠️ SCHEMA CHANGE — this table used to store the raw session token in a
// `token` column; it now stores a SHA-256 hash in `token_hash` instead (so
// a leaked DB dump can't be replayed as live sessions directly). This is a
// breaking change: deploying this file against the old schema will make
// every login/session check fail with "column token_hash does not exist".
// Run once, before deploying this file:
//   CREATE EXTENSION IF NOT EXISTS pgcrypto; -- provides digest()
//   ALTER TABLE sessions ADD COLUMN token_hash text;
//   UPDATE sessions SET token_hash = encode(digest(token, 'sha256'), 'hex');
//   ALTER TABLE sessions ALTER COLUMN token_hash SET NOT NULL;
//   ALTER TABLE sessions ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);
// The UPDATE backfills existing sessions so people don't get logged out by
// this migration. Once you've confirmed the app is running fine on
// token_hash (give it a few days), you can drop the now-unused column:
//   ALTER TABLE sessions DROP COLUMN token;
async function createSession(token, userId) {
  const tokenHash = hashSessionToken(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const { error } = await supabase.from('sessions').insert({ token_hash: tokenHash, user_id: userId, expires_at: expiresAt });
  if (error) throw error;
  return expiresAt;
}

async function getSessionUserId(token) {
  if (!token || token.length > 256) return null;
  const tokenHash = hashSessionToken(token);
  const { data, error } = await supabase
    .from('sessions').select('user_id, expires_at').eq('token_hash', tokenHash).maybeSingle();
  if (error) throw error;
  if (!data) return null;
  const expires = new Date(data.expires_at).getTime();
  if (!Number.isFinite(expires) || expires <= Date.now()) {
    await supabase.from('sessions').delete().eq('token_hash', tokenHash);
    return null;
  }
  if (expires - Date.now() < SESSION_RENEW_THRESHOLD_MS) {
    const newExpiry = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    await supabase.from('sessions').update({ expires_at: newExpiry }).eq('token_hash', tokenHash);
  }
  return data.user_id;
}

async function deleteSession(token) {
  if (!token) return;
  await supabase.from('sessions').delete().eq('token_hash', hashSessionToken(token));
}

module.exports = {
  makeToken,
  hashSessionToken,
  setSessionCookie,
  clearSessionCookie,
  getCookie,
  createSession,
  getSessionUserId,
  deleteSession,
};
