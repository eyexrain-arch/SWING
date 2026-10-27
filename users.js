// User row -> API shape mapping, user lookup and requireAuth.
const { getAuthToken, sendJSON } = require('./http');
const { computeProfileStrength } = require('./profileStrength');
const { buildQuizAnswersDisplay } = require('./questionnaire');
const { getSessionUserId } = require('./session');
const { supabase } = require('../supabase');

// Convert a Postgres users row (snake_case) into the shape the frontend expects (camelCase, no secrets)
function toPublicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    age: row.age,
    bio: row.bio || '',
    location: row.show_location === false ? '' : (row.location || ''),
    country: row.country || '',
    gender: row.gender || null,
    tags: row.tags || [],
    photoUrl: row.photo_url || null,
    galleryUrls: row.gallery_urls || [],
    createdAt: row.created_at,
    // Extended profile fields — collected in the post-signup "complete your
    // profile" step (or later from the Profile tab) and used by Discover
    // filters. All optional; null/empty means "not answered yet".
    languages: row.languages || [],
    // Sensitive lifestyle fields are intentionally NOT returned in the public
    // profile payload. Matching may use them server-side, but exposure should
    // be an explicit product choice rather than an accidental API side effect.
    datingIntentions: row.dating_intentions || [],
    // Prompts/Questions — up to 3 preset short-answer prompts the user picks
    // and answers, shown on their profile. Stored in users.prompts (jsonb
    // array of { question, answer }, default '[]'). Not in the original setup
    // SQL — add it once via:
    //   ALTER TABLE users ADD COLUMN prompts jsonb NOT NULL DEFAULT '[]';
    prompts: row.prompts || [],
    // Readable compatibility-quiz answers, shown on the person's profile
    // (e.g. on Discover cards) — separate from the questionnaire object
    // returned by toOwnUser, which is raw id->value pairs for editing.
    quizAnswers: buildQuizAnswersDisplay(row.questionnaire),
    verified: !!row.verified,
  };
}

// Same as toPublicUser, but also includes this person's own questionnaire
// answers — only ever sent back to that same person, never to anyone else.
function toOwnUser(row) {
  const pub = toPublicUser(row);
  const questionnaire = row.questionnaire || {};
  const profileData = { ...pub, questionnaire };
  const profileStrength = computeProfileStrength(profileData);
  return {
    ...pub,
    email: row.email || '',
    phone: row.phone || '',
    // Like email, these describe the account owner's own settings and
    // have no reason to be visible to anyone viewing this profile from
    // Discover/Matches/Likes-You — only toOwnUser() includes them.
    discoverable: row.discoverable !== false,
    showLocation: row.show_location !== false,
    // Private matching inputs — self-view only, see VALID_ORIENTATIONS above.
    // Deliberately absent from toPublicUser: nobody else's payload (Discover,
    // Matches, a profile someone else is viewing) ever includes these.
    orientation: row.orientation || null,
    interestedIn: row.interested_in || [],
    questionnaire,
    profileCompletion: profileStrength.percentage,
    profileStrength,
  };
}

async function getUserById(id) {
  const { data, error } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data;
}

async function getUserByToken(token) {
  const userId = await getSessionUserId(token);
  if (!userId) return null;
  return await getUserById(userId);
}

async function requireAuth(req, res) {
  const token = getAuthToken(req);
  const user = token ? await getUserByToken(token) : null;
  if (!user) {
    sendJSON(res, 401, { error: 'Not authenticated' });
    return null;
  }
  return user;
}

module.exports = {
  toPublicUser,
  toOwnUser,
  getUserById,
  getUserByToken,
  requireAuth,
};
