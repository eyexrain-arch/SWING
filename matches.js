/**
 * Likes You and Matches.
 */

const { supabase } = require('../supabase');
const { sendJSON } = require('../lib/http');
const { computeCompatibility } = require('../services/questionnaire');
const { toPublicUser } = require('../services/serializers');
const { getUserById } = require('../services/users');
const { requireAuth } = require('../middleware/auth');
const { getBlockedIdSet } = require('./discover');

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

async function handleMatches(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { data: matchRows, error: matchErr } = await supabase
    .from('matches').select('*')
    .or(`user_id_1.eq.${user.id},user_id_2.eq.${user.id}`);
  if (matchErr) throw matchErr;

  const results = [];
  for (const m of matchRows || []) {
    const otherId = m.user_id_1 === user.id ? m.user_id_2 : m.user_id_1;
    const other = await getUserById(otherId);

    const { data: convo, error: convoErr } = await supabase
      .from('messages').select('*').eq('match_key', m.key).order('created_at', { ascending: true });
    if (convoErr) throw convoErr;

    const lastMsg = convo && convo.length ? convo[convo.length - 1] : null;
    const unread = (convo || []).filter(msg => msg.to_user_id === user.id && !msg.read).length;
    const compat = other ? computeCompatibility(user.questionnaire, other.questionnaire) : null;

    results.push({
      matchKey: m.key,
      createdAt: m.created_at,
      user: other ? toPublicUser(other) : null,
      lastMessage: lastMsg ? { text: lastMsg.text, fromUserId: lastMsg.from_user_id, createdAt: lastMsg.created_at } : null,
      unread,
      compatibility: compat ? compat.percent : null,
      compatibilityReasons: compat ? compat.reasons : [],
    });
  }

  results.sort((a, b) => {
    const aTime = a.lastMessage ? a.lastMessage.createdAt : a.createdAt;
    const bTime = b.lastMessage ? b.lastMessage.createdAt : b.createdAt;
    return new Date(bTime) - new Date(aTime);
  });

  sendJSON(res, 200, { matches: results });
}

module.exports = {
  handleLikesYou,
  handleMatches,
};
