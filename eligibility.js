// Block lists and candidate eligibility rules for Discover.
const { supabase } = require('../supabase');

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

module.exports = {
  getBlockedIdSet,
  isEligibleCandidate,
};
