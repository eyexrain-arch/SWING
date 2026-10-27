// Discover, like, likes-you.
const { MAX_TEXT_BYTES } = require('../config');
const { getBlockedIdSet, isEligibleCandidate } = require('../lib/eligibility');
const { readBody, sendJSON } = require('../lib/http');
const { computeCompatibility } = require('../lib/questionnaire');
const { pushEventToUser } = require('../lib/sse');
const { requireAuth, toPublicUser } = require('../lib/users');
const { pairKey } = require('../lib/util');
const { supabase } = require('../supabase');

async function handleDiscover(req, res, query) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { data: swiped, error: swipedErr } = await supabase
    .from('likes').select('to_user_id').eq('from_user_id', user.id);
  if (swipedErr) throw swipedErr;
  const swipedIds = new Set((swiped || []).map(l => l.to_user_id));

  const blockedIds = await getBlockedIdSet(user.id);

  // select('*') here (rather than a hand-picked column list) is deliberate:
  // toPublicUser() already controls exactly what's exposed to the client,
  // so narrowing this query doesn't add any real safety, but it did cause a
  // real bug — a previous column allowlist here quietly omitted
  // `discoverable`/`show_location`, which silently broke both privacy
  // toggles (see toPublicUser and isEligibleCandidate above). Selecting
  // everything means a new column can never be forgotten here again.
  const { data: allUsers, error: usersErr } = await supabase.from('users').select('*');
  if (usersErr) throw usersErr;

  const countryFilter = (query.get('country') || '').trim().toLowerCase();

  const toCandidate = u => {
    const compat = computeCompatibility(user.questionnaire, u.questionnaire);
    return { ...toPublicUser(u), compatibility: compat ? compat.percent : null };
  };

  const eligibleUsers = (allUsers || [])
    .filter(u => isEligibleCandidate(user, u, blockedIds))
    .filter(u => !countryFilter || (u.country || '').toLowerCase().includes(countryFilter));

  // Users the current user can still act on (neither liked nor passed).
  const candidates = eligibleUsers
    .filter(u => !swipedIds.has(u.id))
    .map(toCandidate);

  // Profiles the current user already liked. These are intentionally returned
  // separately so Discover can show them without putting them back into the
  // swipe/like queue.
  const likedProfiles = eligibleUsers
    .filter(u => (swiped || []).some(l => l.to_user_id === u.id && l.direction === 'like'))
    .map(toCandidate);

  const now = Date.now();
  const cutoff48h = now - (48 * 60 * 60 * 1000);
  const viewerLocation = String(user.location || '').trim().toLowerCase();

  // The current user schema stores location as a text field rather than GPS
  // coordinates, so "nearby" means the same saved location/city for now.
  const nearbyProfiles = candidates
    .filter(c => viewerLocation && String(c.location || '').trim().toLowerCase() === viewerLocation)
    .slice(0, 20);

  const newProfiles = candidates
    .filter(c => {
      const created = new Date(c.createdAt || 0).getTime();
      return Number.isFinite(created) && created >= cutoff48h;
    })
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, 20);

  sendJSON(res, 200, { candidates, likedProfiles, nearbyProfiles, newProfiles });
}

async function handleLike(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const { targetUserId, direction } = body; // direction: 'like' | 'pass'

  if (targetUserId === user.id) {
    return sendJSON(res, 400, { error: 'You cannot like or pass yourself' });
  }

  if (!targetUserId || !['like', 'pass'].includes(direction)) {
    return sendJSON(res, 400, { error: 'targetUserId and direction (like|pass) are required' });
  }

  const { data: targetUser, error: targetErr } = await supabase
    .from('users').select('id').eq('id', targetUserId).maybeSingle();
  if (targetErr) throw targetErr;
  if (!targetUser) {
    return sendJSON(res, 404, { error: 'Target user not found' });
  }

  const { data: blocked } = await supabase
    .from('blocks')
    .select('id')
    .or(`and(blocker_id.eq.${user.id},blocked_id.eq.${targetUserId}),and(blocker_id.eq.${targetUserId},blocked_id.eq.${user.id})`)
    .limit(1);
  if (blocked && blocked.length) {
    return sendJSON(res, 403, { error: 'This interaction is unavailable.' });
  }

  const { error: upsertErr } = await supabase
    .from('likes')
    .upsert(
      { from_user_id: user.id, to_user_id: targetUserId, direction },
      { onConflict: 'from_user_id,to_user_id' }
    );
  if (upsertErr) throw upsertErr;

  let matched = false;
  let matchKey = null;

  if (direction === 'like') {
    const { data: reciprocal, error: recipErr } = await supabase
      .from('likes')
      .select('id')
      .eq('from_user_id', targetUserId)
      .eq('to_user_id', user.id)
      .eq('direction', 'like')
      .maybeSingle();
    if (recipErr) throw recipErr;

    if (reciprocal) {
      matchKey = pairKey(user.id, targetUserId);
      const { data: existingMatch, error: existingMatchErr } = await supabase
        .from('matches').select('key').eq('key', matchKey).maybeSingle();
      if (existingMatchErr) throw existingMatchErr;

      if (!existingMatch) {
        const { error: matchInsertErr } = await supabase
          .from('matches')
          .insert({ key: matchKey, user_id_1: user.id, user_id_2: targetUserId });
        if (matchInsertErr) throw matchInsertErr;
        matched = true;
        pushEventToUser(targetUserId, 'match', { matchKey, withUserId: user.id });
      }
    }
  }

  sendJSON(res, 200, { matched, matchKey });
}

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

async function handleLikesYou(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { data: myMatches, error: matchErr } = await supabase
    .from('matches').select('user_id_1, user_id_2')
    .or(`user_id_1.eq.${user.id},user_id_2.eq.${user.id}`);
  if (matchErr) throw matchErr;
  const matchedIds = new Set((myMatches || []).flatMap(m => [m.user_id_1, m.user_id_2]));

  const { data: likesToMe, error: likesErr } = await supabase
    .from('likes').select('from_user_id').eq('to_user_id', user.id).eq('direction', 'like');
  if (likesErr) throw likesErr;

  const admirerIds = (likesToMe || [])
    .map(l => l.from_user_id)
    .filter(id => !matchedIds.has(id));

  if (!admirerIds.length) {
    return sendJSON(res, 200, { admirers: [] });
  }

  // Blocking someone already deletes the underlying like row (see
  // handleBlock), so this normally isn't needed to hide them — but it's a
  // cheap, worthwhile safety net against any edge case where a like row
  // survives a block (e.g. ordering of operations, a future code path that
  // creates likes without going through handleLike).
  const blockedIds = await getBlockedIdSet(user.id);
  const visibleAdmirerIds = admirerIds.filter(id => !blockedIds.has(id));
  if (!visibleAdmirerIds.length) {
    return sendJSON(res, 200, { admirers: [] });
  }

  const { data: admirerRows, error: admirerErr } = await supabase
    .from('users').select('*').in('id', visibleAdmirerIds);
  if (admirerErr) throw admirerErr;

  sendJSON(res, 200, { admirers: (admirerRows || []).map(toPublicUser) });
}

module.exports = {
  handleDiscover,
  handleLike,
  handleLikesYou,
};
