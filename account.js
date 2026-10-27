// Me, change password, delete account.
const { MAX_TEXT_BYTES } = require('../config');
const { getAuthToken, readBody, sendJSON } = require('../lib/http');
const { hashPassword, isValidPassword, verifyPassword } = require('../lib/password');
const { removeFromPhotosBucket } = require('../lib/photoStorage');
const { clearRateLimit, rateLimit } = require('../lib/rateLimit');
const { clearSessionCookie, hashSessionToken } = require('../lib/session');
const { requireAuth, toOwnUser } = require('../lib/users');
const { supabase } = require('../supabase');

async function handleMe(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  sendJSON(res, 200, { user: toOwnUser(user) });
}

async function handleChangePassword(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const { currentPassword, newPassword } = body;
  if (!currentPassword || !newPassword) {
    return sendJSON(res, 400, { error: 'Current and new password are required' });
  }
  const lockKey = `pwdcheck:${user.id}`;
  if (!rateLimit(lockKey, 8, 15 * 60 * 1000)) {
    return sendJSON(res, 429, { error: 'Too many attempts. Please try again later.' });
  }
  if (!(await verifyPassword(currentPassword, user.password_salt, user.password_hash))) {
    return sendJSON(res, 401, { error: 'Current password is incorrect' });
  }
  clearRateLimit(lockKey);
  if (!isValidPassword(newPassword)) {
    return sendJSON(res, 400, { error: 'New password must be at least 6 characters and include both letters and numbers' });
  }
  const { salt, hash } = await hashPassword(newPassword);
  await supabase.from('users').update({ password_salt: salt, password_hash: hash }).eq('id', user.id);

  // Changing a password is a good moment to sign the account out everywhere
  // else, in case the old password was compromised — but keep the session
  // that just made this request alive so the person isn't logged out by
  // the very action they took.
  const currentToken = getAuthToken(req);
  const keepHash = currentToken ? hashSessionToken(currentToken) : null;
  const del = supabase.from('sessions').delete().eq('user_id', user.id);
  await (keepHash ? del.neq('token_hash', keepHash) : del);

  sendJSON(res, 200, { ok: true });
}

async function handleDeleteAccount(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const { password } = body;
  const lockKey = `pwdcheck:${user.id}`;
  if (!rateLimit(lockKey, 8, 15 * 60 * 1000)) {
    return sendJSON(res, 429, { error: 'Too many attempts. Please try again later.' });
  }
  if (!password || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
    return sendJSON(res, 401, { error: 'Password is incorrect' });
  }
  clearRateLimit(lockKey);

  // Clean up everything that references this account. Some of these tables
  // (password_resets, blocks, reports) are already set up with
  // ON DELETE CASCADE, but matches/messages/likes/sessions predate that
  // convention — deleting explicitly here works regardless of whether a
  // given table happens to cascade, rather than assuming.
  const { data: matches } = await supabase
    .from('matches').select('key').or(`user_id_1.eq.${user.id},user_id_2.eq.${user.id}`);
  const matchKeys = (matches || []).map(m => m.key);
  if (matchKeys.length) {
    await supabase.from('messages').delete().in('match_key', matchKeys);
    await supabase.from('matches').delete().in('key', matchKeys);
  }
  await supabase.from('likes').delete().or(`from_user_id.eq.${user.id},to_user_id.eq.${user.id}`);
  await supabase.from('blocks').delete().or(`blocker_id.eq.${user.id},blocked_id.eq.${user.id}`);
  await supabase.from('reports').delete().or(`reporter_id.eq.${user.id},reported_id.eq.${user.id}`);
  await supabase.from('password_resets').delete().eq('user_id', user.id);
  await supabase.from('sessions').delete().eq('user_id', user.id);

  // Best-effort — an orphaned Storage file isn't worth failing the deletion over.
  await removeFromPhotosBucket(user.photo_url);
  for (const url of (user.gallery_urls || [])) await removeFromPhotosBucket(url);

  await supabase.from('users').delete().eq('id', user.id);

  clearSessionCookie(res);
  sendJSON(res, 200, { ok: true });
}

module.exports = {
  handleMe,
  handleChangePassword,
  handleDeleteAccount,
};
