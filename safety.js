// Block, unblock, blocked list, report.
const { MAX_TEXT_BYTES } = require('../config');
const { readBody, sendJSON } = require('../lib/http');
const { requireAuth, toPublicUser } = require('../lib/users');
const { pairKey } = require('../lib/util');
const { supabase } = require('../supabase');

async function handleBlock(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const targetUserId = String(body.targetUserId || '').trim();
  if (!targetUserId || targetUserId === user.id) {
    return sendJSON(res, 400, { error: 'A valid other user is required' });
  }
  const { data: target } = await supabase.from('users').select('id').eq('id', targetUserId).maybeSingle();
  if (!target) return sendJSON(res, 404, { error: 'User not found' });

  const { error } = await supabase.from('blocks').upsert(
    { blocker_id: user.id, blocked_id: targetUserId },
    { onConflict: 'blocker_id,blocked_id' }
  );
  if (error) throw error;

  // Remove the social edges that could otherwise keep exposing the blocked
  // person through Likes/Matches/Discover. Existing messages are retained for
  // safety/audit purposes but become inaccessible through normal chat actions.
  await supabase.from('likes').delete().or(`and(from_user_id.eq.${user.id},to_user_id.eq.${targetUserId}),and(from_user_id.eq.${targetUserId},to_user_id.eq.${user.id})`);
  await supabase.from('matches').delete().eq('key', pairKey(user.id, targetUserId));

  sendJSON(res, 200, { blocked: true });
}

async function handleUnblock(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const targetUserId = String(body.targetUserId || '').trim();
  if (!targetUserId) return sendJSON(res, 400, { error: 'targetUserId is required' });
  const { error } = await supabase.from('blocks').delete().eq('blocker_id', user.id).eq('blocked_id', targetUserId);
  if (error) throw error;
  sendJSON(res, 200, { blocked: false });
}

// Powers the "Blocked Users" list in Settings → Privacy. Only ever returns
// people *this* user chose to block (not people who blocked them — that's
// intentionally invisible, same as most dating apps).
async function handleGetBlockedUsers(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { data: blockRows, error } = await supabase
    .from('blocks').select('blocked_id').eq('blocker_id', user.id);
  if (error) throw error;

  const blockedIds = (blockRows || []).map(b => b.blocked_id);
  if (!blockedIds.length) return sendJSON(res, 200, { blocked: [] });

  const { data: rows, error: usersErr } = await supabase
    .from('users').select('*').in('id', blockedIds);
  if (usersErr) throw usersErr;

  sendJSON(res, 200, { blocked: (rows || []).map(toPublicUser) });
}

async function handleReport(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const reportedUserId = String(body.reportedUserId || '').trim();
  const reason = String(body.reason || '').trim().slice(0, 80);
  const details = String(body.details || '').trim().slice(0, 1000);
  if (!reportedUserId || reportedUserId === user.id || !reason) {
    return sendJSON(res, 400, { error: 'reportedUserId and reason are required' });
  }
  const { data: target } = await supabase.from('users').select('id').eq('id', reportedUserId).maybeSingle();
  if (!target) return sendJSON(res, 404, { error: 'User not found' });
  const { error } = await supabase.from('reports').insert({
    reporter_id: user.id,
    reported_id: reportedUserId,
    reason,
    details: details || null,
  });
  if (error) throw error;
  sendJSON(res, 201, { reported: true });
}

module.exports = {
  handleBlock,
  handleUnblock,
  handleGetBlockedUsers,
  handleReport,
};
