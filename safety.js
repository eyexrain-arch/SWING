/**
 * Privacy / safety: block, unblock, blocked list, report.
 */

const { MAX_TEXT_BYTES } = require('../config');
const { supabase } = require('../supabase');
const { readBody, sendJSON } = require('../lib/http');
const { pairKey } = require('../lib/utils');
const { toPublicUser } = require('../services/serializers');
const { requireAuth } = require('../middleware/auth');

// ---------- Privacy / Safety controls ----------
// ⚠️ SCHEMA CHANGE — these two tables are new and aren't in the original
// setup SQL. Create them once, before deploying this file:
//   CREATE EXTENSION IF NOT EXISTS pgcrypto; -- provides gen_random_uuid()
//
//   CREATE TABLE blocks (
//     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
//     blocker_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//     blocked_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//     created_at timestamptz NOT NULL DEFAULT now(),
//     UNIQUE (blocker_id, blocked_id)
//   );
//   CREATE INDEX idx_blocks_blocked_id ON blocks(blocked_id);
//
//   CREATE TABLE reports (
//     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
//     reporter_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//     reported_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//     reason text NOT NULL,
//     details text,
//     created_at timestamptz NOT NULL DEFAULT now()
//   );
//
// The UNIQUE constraint on blocks is required for handleBlock's upsert
// below (onConflict: 'blocker_id,blocked_id') — without it, Postgres
// rejects the upsert with "no unique or exclusion constraint matching
// the ON CONFLICT specification".

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
  handleGetBlockedUsers,
  handleReport,
  handleUnblock,
};
