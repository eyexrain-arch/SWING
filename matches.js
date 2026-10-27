// Matches and chat messages.
const { MAX_MESSAGE_CHARS, MAX_TEXT_BYTES } = require('../config');
const { readBody, sendJSON } = require('../lib/http');
const { computeCompatibility } = require('../lib/questionnaire');
const { pushEventToUser } = require('../lib/sse');
const { getUserById, requireAuth, toPublicUser } = require('../lib/users');
const { supabase } = require('../supabase');

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

async function getMatchForUser(matchKey, userId) {
  const { data, error } = await supabase.from('matches').select('*').eq('key', matchKey).maybeSingle();
  if (error) throw error;
  if (!data) return null;
  if (data.user_id_1 !== userId && data.user_id_2 !== userId) return null;
  return data;
}

async function handleGetMessages(req, res, matchKey) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const match = await getMatchForUser(matchKey, user.id);
  if (!match) {
    return sendJSON(res, 404, { error: 'Match not found' });
  }

  const { data: convo, error } = await supabase
    .from('messages').select('*').eq('match_key', matchKey).order('created_at', { ascending: true });
  if (error) throw error;

  const { error: readErr } = await supabase
    .from('messages')
    .update({ read: true })
    .eq('match_key', matchKey)
    .eq('to_user_id', user.id)
    .eq('read', false);
  if (readErr) throw readErr;

  const messages = (convo || []).map(m => ({
    id: m.id,
    matchKey: m.match_key,
    fromUserId: m.from_user_id,
    toUserId: m.to_user_id,
    text: m.text,
    read: m.read,
    createdAt: m.created_at,
  }));

  sendJSON(res, 200, { messages });
}

async function handlePostMessage(req, res, matchKey) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const match = await getMatchForUser(matchKey, user.id);
  if (!match) {
    return sendJSON(res, 404, { error: 'Match not found' });
  }

  const body = await readBody(req, MAX_TEXT_BYTES);
  const { text } = body;
  if (typeof text !== 'string' || !text.trim()) {
    return sendJSON(res, 400, { error: 'text is required' });
  }
  if (text.trim().length > MAX_MESSAGE_CHARS) {
    return sendJSON(res, 400, { error: `Message must be ${MAX_MESSAGE_CHARS} characters or fewer` });
  }

  const toUserId = match.user_id_1 === user.id ? match.user_id_2 : match.user_id_1;

  const { data: blocked } = await supabase
    .from('blocks').select('id').or(`and(blocker_id.eq.${user.id},blocked_id.eq.${toUserId}),and(blocker_id.eq.${toUserId},blocked_id.eq.${user.id})`).limit(1);
  if (blocked && blocked.length) {
    return sendJSON(res, 403, { error: 'Messaging is unavailable for this match.' });
  }

  const { data: message, error } = await supabase
    .from('messages')
    .insert({ match_key: matchKey, from_user_id: user.id, to_user_id: toUserId, text: text.trim() })
    .select()
    .single();
  if (error) throw error;

  const publicMessage = {
    id: message.id,
    matchKey: message.match_key,
    fromUserId: message.from_user_id,
    toUserId: message.to_user_id,
    text: message.text,
    read: message.read,
    createdAt: message.created_at,
  };

  pushEventToUser(toUserId, 'message', publicMessage);

  sendJSON(res, 201, { message: publicMessage });
}

module.exports = {
  handleMatches,
  handleGetMessages,
  handlePostMessage,
};
