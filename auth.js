// Register, login, logout, forgot/reset password.
const crypto = require('crypto');
const { MAX_BIO_CHARS, MAX_COUNTRY_CHARS, MAX_LOCATION_CHARS, MAX_NAME_CHARS, MAX_TEXT_BYTES, VALID_GENDERS } = require('../config');
const { getAuthToken, readBody, sendJSON } = require('../lib/http');
const { classifyIdentity } = require('../lib/identity');
const { hashPassword, isValidPassword, verifyPassword } = require('../lib/password');
const { clearRateLimit, rateLimit } = require('../lib/rateLimit');
const { clearSessionCookie, createSession, deleteSession, makeToken, setSessionCookie } = require('../lib/session');
const { toOwnUser } = require('../lib/users');
const { parseTags } = require('../lib/util');
const { supabase } = require('../supabase');

// ⚠️ SCHEMA CHANGE — sign-in now accepts either an email or a phone number
// as the account identity, and forgot-password needs somewhere to store
// reset codes. Run this once, before deploying this file:
//   ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
//   ALTER TABLE users ADD COLUMN IF NOT EXISTS phone text UNIQUE;
//   CREATE TABLE IF NOT EXISTS password_resets (
//     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
//     user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//     code_hash text NOT NULL,
//     expires_at timestamptz NOT NULL,
//     created_at timestamptz NOT NULL DEFAULT now()
//   );
//   CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);
async function handleRegister(req, res) {
  const body = await readBody(req, MAX_TEXT_BYTES);
  const { name, identity, password, age, bio, location, country, gender, tags } = body;

  if (!name || !identity || !password) {
    return sendJSON(res, 400, { error: 'name, an email or phone number, and password are required' });
  }
  if (!isValidPassword(password)) {
    return sendJSON(res, 400, { error: 'Password must be at least 6 characters and include both letters and numbers' });
  }
  const cleanName = String(name).trim().replace(/\s+/g, ' ').slice(0, MAX_NAME_CHARS);
  if (!cleanName) {
    return sendJSON(res, 400, { error: 'A valid name is required' });
  }
  const id = classifyIdentity(identity);
  if (!id) {
    return sendJSON(res, 400, { error: 'Enter a valid email address or phone number' });
  }
  if (!gender || !VALID_GENDERS.includes(gender)) {
    return sendJSON(res, 400, { error: 'A valid gender selection is required' });
  }

  const { data: existing, error: existingErr } = await supabase
    .from('users').select('id').eq(id.field, id.value).maybeSingle();
  if (existingErr) throw existingErr;
  if (existing) {
    return sendJSON(res, 409, { error: `An account with that ${id.field === 'email' ? 'email' : 'phone number'} already exists` });
  }

  const { salt, hash } = await hashPassword(password);
  const { data: created, error: insertErr } = await supabase
    .from('users')
    .insert({
      name: cleanName,
      age: Number.isInteger(Number(age)) && Number(age) >= 18 && Number(age) <= 100 ? Number(age) : null,
      bio: String(bio || '').trim().slice(0, MAX_BIO_CHARS),
      location: String(location || '').trim().slice(0, MAX_LOCATION_CHARS),
      country: String(country || '').trim().slice(0, MAX_COUNTRY_CHARS),
      gender,
      tags: parseTags(tags),
      email: id.field === 'email' ? id.value : null,
      phone: id.field === 'phone' ? id.value : null,
      password_salt: salt,
      password_hash: hash,
    })
    .select()
    .single();
  if (insertErr) throw insertErr;

  const token = makeToken();
  await createSession(token, created.id);
  setSessionCookie(res, token);

  sendJSON(res, 201, { user: toOwnUser(created) });
}

async function handleLogin(req, res) {
  const body = await readBody(req, MAX_TEXT_BYTES);
  const { identity, password } = body;
  if (!identity || !password) {
    return sendJSON(res, 400, { error: 'An email/phone number and password are required' });
  }
  const id = classifyIdentity(identity);
  // Same generic error whether the identity is malformed, unknown, or the
  // password is wrong — never confirm or deny that an account exists.
  const genericFail = () => sendJSON(res, 401, { error: 'Invalid email/phone or password' });
  if (!id) return genericFail();

  // Per-identity brute-force lockout, on top of the per-IP rate limit
  // applied to every /api/login request. This catches slow, distributed
  // credential-stuffing attempts against one specific account that a
  // per-IP limit alone wouldn't.
  const lockKey = `loginfail:${id.field}:${id.value}`;
  if (!rateLimit(lockKey, 8, 15 * 60 * 1000)) {
    return sendJSON(res, 429, { error: 'Too many failed attempts. Please try again later.' });
  }

  const { data: user, error } = await supabase
    .from('users').select('*').eq(id.field, id.value).maybeSingle();
  if (error) throw error;
  if (!user || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
    return genericFail();
  }
  clearRateLimit(lockKey); // successful login — forget prior failures

  // Transparently upgrade legacy PBKDF2 hashes to scrypt after a successful
  // login, so existing users do not need to reset their passwords.
  if (!String(user.password_hash || '').startsWith('scrypt$')) {
    const upgraded = await hashPassword(password);
    await supabase.from('users').update({ password_salt: upgraded.salt, password_hash: upgraded.hash }).eq('id', user.id);
    user.password_salt = upgraded.salt;
    user.password_hash = upgraded.hash;
  }

  const token = makeToken();
  await createSession(token, user.id);
  setSessionCookie(res, token);
  sendJSON(res, 200, { user: toOwnUser(user) });
}

// No email/SMS provider is wired up yet, so the reset code is written to
// the server console instead of actually being emailed/texted. Everything
// else (hashed, time-limited, single-use codes; generic responses that
// never reveal whether an account exists; session invalidation on reset)
// is the real, production-shaped flow — swap in a provider call where
// noted below and this is done.
function hashResetCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

async function handleForgotPassword(req, res) {
  const body = await readBody(req, MAX_TEXT_BYTES);
  const id = classifyIdentity(body.identity);
  const generic = { ok: true, message: 'If an account exists for that email or phone number, a reset code has been sent.' };
  if (!id) return sendJSON(res, 200, generic); // never confirm/deny format validity either

  const { data: user, error } = await supabase
    .from('users').select('id').eq(id.field, id.value).maybeSingle();
  if (error) throw error;
  if (user) {
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    // Invalidate any earlier unused codes for this user first.
    await supabase.from('password_resets').delete().eq('user_id', user.id);
    const { error: insertErr } = await supabase.from('password_resets').insert({
      user_id: user.id, code_hash: hashResetCode(code), expires_at: expiresAt,
    });
    if (insertErr) throw insertErr;
    // TODO: send `code` via email/SMS provider instead of logging it.
    console.log(`[password reset] code for ${id.field} ${id.value}: ${code} (expires in 15 min)`);
  }
  sendJSON(res, 200, generic);
}

async function handleResetPassword(req, res) {
  const body = await readBody(req, MAX_TEXT_BYTES);
  const { identity, code, newPassword } = body;
  const id = classifyIdentity(identity);
  const genericFail = () => sendJSON(res, 400, { error: 'Invalid or expired code' });
  if (!id || !code || !newPassword) return genericFail();
  if (!isValidPassword(newPassword)) {
    return sendJSON(res, 400, { error: 'Password must be at least 6 characters and include both letters and numbers' });
  }

  const { data: user, error } = await supabase
    .from('users').select('id').eq(id.field, id.value).maybeSingle();
  if (error) throw error;
  if (!user) return genericFail();

  const { data: reset, error: resetErr } = await supabase
    .from('password_resets').select('*').eq('user_id', user.id).eq('code_hash', hashResetCode(String(code))).maybeSingle();
  if (resetErr) throw resetErr;
  if (!reset || new Date(reset.expires_at).getTime() <= Date.now()) return genericFail();

  const { salt, hash } = await hashPassword(newPassword);
  await supabase.from('users').update({ password_salt: salt, password_hash: hash }).eq('id', user.id);
  await supabase.from('password_resets').delete().eq('user_id', user.id);
  // Resetting a password is a strong signal something was wrong — sign the
  // account out everywhere so a compromised session can't linger.
  await supabase.from('sessions').delete().eq('user_id', user.id);

  sendJSON(res, 200, { ok: true });
}

async function handleLogout(req, res) {
  const token = getAuthToken(req);
  if (token) await deleteSession(token);
  clearSessionCookie(res);
  sendJSON(res, 200, { ok: true });
}

module.exports = {
  handleRegister,
  handleLogin,
  handleForgotPassword,
  handleResetPassword,
  handleLogout,
};
