/**
 * Discover and likes.
 */

const { MAX_TEXT_BYTES } = require('../config');
const { supabase } = require('../supabase');
const { readBody, sendJSON } = require('../lib/http');
const { pairKey } = require('../lib/utils');
const { pushEventToUser } = require('../services/sse');
const { computeCompatibility } = require('../services/questionnaire');
const { requireAuth } = require('../middleware/auth');

// ---------- Discover / Likes / Matches ----------

// Returns the set of user IDs that are blocked in either direction with
// the given user (they blocked someone, or someone blocked them). Shared
// by every place that lists other people to this user — Discover, the AI
// matchmaker's candidate pool, and Likes You — so a block can't be
// honored in some of them but not others.
async function getBlockedIdSet(userId) {
  const { data, error } = await supabase
    .from('blocks').select('blocker_id, blocked_id')
    .or(`blocker_id.eq.${userId},blocked_id.eq.${userId}`);
  if (error) throw error;
  const ids = new Set();
  for (const row of data || []) {
    ids.add(row.blocker_id === userId ? row.blocked_id : row.blocker_id);
  }
  return ids;
}

// Whether `other` is someone `viewer` should be shown at all — used by the
// real Discover feed's eligibility check (and formerly also by the AI
// matchmaker's candidate context, before that feature was replaced by
// Explore).
// NOTE: gender-only matching is now the fallback, not the whole rule — see
// below. Kept deliberately permissive for anyone who hasn't set an
// "interested in" preference yet: a "man" or "woman" viewer sees the other
// binary gender plus everyone outside the binary; anyone whose own gender
// isn't man/woman sees everyone. That's what runs until BOTH sides of a
// pair have set interested_in, so upgrading to real preferences never
// silently empties out someone's existing Discover feed.
function isBinaryGender(g) { return g === 'man' || g === 'woman'; }

// Buckets the full gender list down to the 3 categories interested_in is
// expressed in. Anyone outside the man/woman binary is bucketed as
// 'nonbinary' for matching purposes, regardless of which specific option
// they picked — interested_in intentionally doesn't get more granular than
// that.
function genderBucket(g) {
  if (g === 'man') return 'men';
  if (g === 'woman') return 'women';
  return 'nonbinary';
}

function isEligibleCandidate(viewer, other, blockedIds) {
  if (other.id === viewer.id) return false;
  if (other.discoverable === false) return false;
  if (blockedIds.has(other.id)) return false;

  const viewerPrefs = viewer.interested_in && viewer.interested_in.length ? viewer.interested_in : null;
  const otherPrefs = other.interested_in && other.interested_in.length ? other.interested_in : null;
  if (viewerPrefs && otherPrefs) {
    // Real mutual check: each side must want the other's gender bucket.
    return viewerPrefs.includes(genderBucket(other.gender)) && otherPrefs.includes(genderBucket(viewer.gender));
  }

  if (viewer.gender === 'man') return other.gender === 'woman' || !isBinaryGender(other.gender);
  if (viewer.gender === 'woman') return other.gender === 'man' || !isBinaryGender(other.gender);
  return true;
}

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

module.exports = {
  getBlockedIdSet,
  handleDiscover,
  handleLike,
};
