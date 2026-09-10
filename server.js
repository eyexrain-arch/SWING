// Swing — single-file Node.js dating app
// Storage: Supabase (Postgres for data, Storage bucket "photos" for images).
//
// SECURITY NOTE: this server uses the Supabase *service role* key, not the
// anon/publishable key. The service role key bypasses Row Level Security by
// design — that's intentional here, since this server is the only thing
// that talks to Supabase and it already enforces its own auth checks on
// every request. NEVER expose this key to the browser or commit it to
// source control — it only ever belongs in an environment variable on the
// server (e.g. Render's Environment tab).

const http = require('http');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const MAX_BODY_BYTES = 8 * 1024 * 1024; // 8MB — covers a base64-encoded photo
const PHOTOS_BUCKET = 'photos';

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables.');
  console.error('Set them before starting the server (see README).');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Swing AI chat assistant — optional. If you don't set this, the rest of
// the app works fine; only the "Swing AI" chat feature is disabled.
// Get a key at console.anthropic.com, then set it as an environment
// variable named ANTHROPIC_API_KEY (never put it in this file).
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ANTHROPIC_MODEL = 'claude-haiku-4-5-20251001';

// ---------- Helpers ----------

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  const check = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return check === hash;
}

function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Sessions are persisted in the "sessions" table (see README/setup SQL) so
// that logins survive server restarts/redeploys — an in-memory Map would
// wipe everyone's session on every restart.
async function createSession(token, userId) {
  const { error } = await supabase.from('sessions').insert({ token, user_id: userId });
  if (error) throw error;
}

async function getSessionUserId(token) {
  const { data, error } = await supabase
    .from('sessions').select('user_id').eq('token', token).maybeSingle();
  if (error) throw error;
  return data ? data.user_id : null;
}

async function deleteSession(token) {
  await supabase.from('sessions').delete().eq('token', token);
}

// ---------- Live updates (Server-Sent Events) ----------
// Maps a userId to the set of open SSE connections for that person
// (they might have the app open on more than one device/tab at once).
const sseClients = new Map(); // userId -> Set<res>

function addSseClient(userId, res) {
  if (!sseClients.has(userId)) sseClients.set(userId, new Set());
  sseClients.get(userId).add(res);
}

function removeSseClient(userId, res) {
  const set = sseClients.get(userId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) sseClients.delete(userId);
}

function pushEventToUser(userId, eventName, data) {
  const set = sseClients.get(userId);
  if (!set || !set.size) return;
  const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const clientRes of set) {
    try {
      clientRes.write(payload);
    } catch (e) {
      // connection likely already gone; it'll be cleaned up by its own 'close' handler
    }
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bytes = 0;
    req.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        reject(new Error('Upload too large (max 8MB)'));
        req.destroy();
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJSON(res, status, obj) {
  const bodyStr = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(bodyStr),
    'Cache-Control': 'no-store',
  });
  res.end(bodyStr);
}

function getAuthToken(req) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length);
}

function pairKey(id1, id2) {
  return [id1, id2].sort().join('::');
}

// Convert a Postgres users row (snake_case) into the shape the frontend expects (camelCase, no secrets)
function toPublicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    age: row.age,
    bio: row.bio || '',
    location: row.location || '',
    country: row.country || '',
    gender: row.gender || null,
    tags: row.tags || [],
    email: row.email,
    photoUrl: row.photo_url || null,
    galleryUrls: row.gallery_urls || [],
    createdAt: row.created_at,
    // Extended profile fields — collected in the post-signup "complete your
    // profile" step (or later from the Profile tab) and used by Discover
    // filters. All optional; null/empty means "not answered yet".
    languages: row.languages || [],
    education: row.education || '',
    heightCm: row.height_cm || null,
    exercise: row.exercise || '',
    drinking: row.drinking || '',
    smoking: row.smoking || '',
    religion: row.religion || '',
    political: row.political_views || '',
    children: row.children || '',
    wantsChildren: row.wants_children || '',
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

// Dynamic weighted profile strength. Each section earns only the portion of
// its weight represented by the user's actual completed data.
//
// IMPORTANT: Do not replace this with a hard-coded percentage. The score is
// recalculated every time the user's profile is returned from the server.
const PROFILE_STRENGTH_SECTIONS = [
  {
    key: 'profilePhoto',
    label: 'Profile photo',
    weight: 10,
    fields: [{ get: u => u.photoUrl }],
  },
  {
    key: 'nameAndAge',
    label: 'Name and age',
    weight: 10,
    fields: [{ get: u => u.name }, { get: u => u.age }],
  },
  {
    key: 'bio',
    label: 'Bio/About Me',
    weight: 10,
    fields: [{ get: u => u.bio }],
  },
  {
    key: 'locationAndQuiz',
    label: 'Location and compatibility quiz',
    weight: 20,
    fields: [
      { get: u => u.location },
      { get: u => u.questionnaire?.relationship_goal },
      { get: u => u.questionnaire?.wants_kids },
      { get: u => u.questionnaire?.personality },
      { get: u => u.questionnaire?.top_value },
      { get: u => u.questionnaire?.conflict_style },
      { get: u => u.questionnaire?.social_style },
      { get: u => u.questionnaire?.career_priority },
      { get: u => u.questionnaire?.communication_style },
      { get: u => u.questionnaire?.personal_space },
      { get: u => u.questionnaire?.lifestyle_pace },
      { get: u => u.questionnaire?.dealbreakers },
    ],
  },
  {
    key: 'interestsAndQuickInfo',
    label: 'Interests/Hobbies and quick info',
    weight: 10,
    fields: [
      { get: u => u.tags },
      { get: u => u.languages },
    ],
  },
  {
    key: 'lookingFor',
    label: 'Looking For',
    weight: 10,
    fields: [{ get: u => u.datingIntentions }],
  },
  {
    key: 'lifestyle',
    label: 'Lifestyle details',
    weight: 5,
    fields: [
      { get: u => u.education },
      { get: u => u.heightCm },
      { get: u => u.exercise },
      { get: u => u.drinking },
      { get: u => u.smoking },
      { get: u => u.religion },
      { get: u => u.political },
      { get: u => u.children },
      { get: u => u.wantsChildren },
    ],
  },
  {
    key: 'additionalPhotosOrVibe',
    label: 'Additional photos or my vibe',
    weight: 15,
    // My Vibes currently supports up to 3 additional photos. Each photo earns
    // one third of this section's weight, so 1/3/3 photos = 5/10/15 points.
    fields: [
      { get: u => Array.isArray(u.galleryUrls) ? u.galleryUrls[0] : null },
      { get: u => Array.isArray(u.galleryUrls) ? u.galleryUrls[1] : null },
      { get: u => Array.isArray(u.galleryUrls) ? u.galleryUrls[2] : null },
    ],
  },
  {
    key: 'prompts',
    label: 'Prompts/Questions',
    weight: 10,
    // Up to 3 preset prompts a user can pick and answer (see PROMPT_LIBRARY).
    // Each answered prompt earns one third of this section's weight, so
    // 1/2/3 answered = ~3.3/6.7/10 points.
    fields: [
      { get: u => Array.isArray(u.prompts) ? u.prompts[0] : null },
      { get: u => Array.isArray(u.prompts) ? u.prompts[1] : null },
      { get: u => Array.isArray(u.prompts) ? u.prompts[2] : null },
    ],
  },
];

function isProfileValueCompleted(value) {
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'boolean') return true;
  return value !== null && value !== undefined && String(value).trim().length > 0;
}

function computeProfileStrength(user) {
  const sectionScores = {};
  let total = 0;

  for (const section of PROFILE_STRENGTH_SECTIONS) {
    const completed = section.fields.reduce((count, field) => {
      let value;
      try { value = field.get(user); } catch (_) { value = null; }
      return count + (isProfileValueCompleted(value) ? 1 : 0);
    }, 0);

    const ratio = section.fields.length ? completed / section.fields.length : 0;
    const points = section.weight * ratio;
    sectionScores[section.key] = {
      label: section.label,
      weight: section.weight,
      completed,
      totalFields: section.fields.length,
      points: Math.round(points * 100) / 100,
    };
    total += points;
  }

  return {
    percentage: Math.min(100, Math.round(total)),
    sections: sectionScores,
  };
}

// Backwards-compatible name used by the existing profile UI/API.
function computeProfileCompletion(user) {
  return computeProfileStrength(user).percentage;
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

// Browsers' built-in EventSource API can't send custom headers, so the
// live-updates connection authenticates via a token in the URL instead.
async function handleStream(req, res, query) {
  const token = query.get('token');
  const user = token ? await getUserByToken(token) : null;
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'text/plain' });
    return res.end('Not authenticated');
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });
  res.write('retry: 3000\n\n');

  addSseClient(user.id, res);

  const heartbeat = setInterval(() => {
    try { res.write(': keep-alive\n\n'); } catch (e) { /* ignore */ }
  }, 20000);

  req.on('close', () => {
    clearInterval(heartbeat);
    removeSseClient(user.id, res);
  });
}

function parseTags(tags) {
  if (Array.isArray(tags)) return tags;
  if (tags) return String(tags).split(',').map(t => t.trim()).filter(Boolean);
  return [];
}

// ---------- Compatibility questionnaire ----------

const QUESTIONNAIRE = [
  {
    id: 'relationship_goal', type: 'single', question: 'What are you looking for?',
    options: [
      { value: 'long_term', label: 'Long-term relationship' },
      { value: 'marriage', label: 'Marriage' },
      { value: 'dating', label: 'Dating' },
      { value: 'friendship', label: 'Friendship' },
      { value: 'casual', label: 'Casual relationship' },
      { value: 'not_sure', label: 'Not sure yet' },
    ],
    matchPhrase: (label) => `want the same thing right now (${label.toLowerCase()})`,
  },
  {
    id: 'wants_kids', type: 'single', question: 'Do you want children someday?',
    options: [
      { value: 'yes', label: 'Yes' },
      { value: 'no', label: 'No' },
      { value: 'maybe', label: 'Maybe' },
      { value: 'have_kids', label: 'I already have kids' },
    ],
    matchPhrase: (label) => `feel the same about having kids`,
  },
  {
    id: 'personality', type: 'single', question: 'How would you describe your personality?',
    options: [
      { value: 'introvert', label: 'Introvert' },
      { value: 'extrovert', label: 'Extrovert' },
      { value: 'ambivert', label: 'A mix of both' },
    ],
    matchPhrase: (label) => `share a similar personality (${label.toLowerCase()})`,
  },
  {
    id: 'top_value', type: 'single', question: 'What matters most to you in a partner?',
    options: [
      { value: 'humor', label: 'Sense of humor' },
      { value: 'ambition', label: 'Ambition' },
      { value: 'kindness', label: 'Kindness' },
      { value: 'intelligence', label: 'Intelligence' },
      { value: 'loyalty', label: 'Loyalty' },
    ],
    matchPhrase: (label) => `value ${label.toLowerCase()} most in a partner`,
  },
  {
    id: 'conflict_style', type: 'single', question: 'How do you handle conflict?',
    options: [
      { value: 'talk_immediately', label: 'Talk it out right away' },
      { value: 'need_space', label: 'Need space, then talk' },
      { value: 'avoid', label: 'Tend to avoid it' },
      { value: 'direct', label: 'Direct and to the point' },
    ],
    matchPhrase: () => `handle conflict in a similar way`,
  },
  {
    id: 'social_style', type: 'single', question: 'How social are you?',
    options: [
      { value: 'go_out', label: 'Love going out' },
      { value: 'stay_in', label: 'Prefer staying in' },
      { value: 'balance', label: 'A balance of both' },
    ],
    matchPhrase: (label) => `have a similar social style (${label.toLowerCase()})`,
  },
  {
    id: 'career_priority', type: 'single', question: 'How important is career/ambition to you?',
    options: [
      { value: 'very', label: 'Very important' },
      { value: 'balanced', label: 'Important, but balanced' },
      { value: 'low', label: 'Not a big priority' },
    ],
    matchPhrase: () => `feel similarly about career priorities`,
  },
  {
    id: 'communication_style', type: 'single', question: 'How do you like to communicate?',
    options: [
      { value: 'texting', label: 'Texting throughout the day' },
      { value: 'meaningful', label: 'A few meaningful messages' },
      { value: 'calls', label: 'Prefer calls' },
      { value: 'in_person', label: 'Prefer in-person' },
    ],
    matchPhrase: () => `like to communicate the same way`,
  },
  {
    id: 'personal_space', type: 'single', question: 'How much personal space do you need?',
    options: [
      { value: 'lots', label: 'I need lots of alone time' },
      { value: 'together', label: 'I like togetherness most of the time' },
      { value: 'balanced', label: 'Balanced' },
    ],
    matchPhrase: () => `need a similar amount of personal space`,
  },
  {
    id: 'lifestyle_pace', type: 'single', question: 'What best describes your lifestyle?',
    options: [
      { value: 'homebody', label: 'Homebody' },
      { value: 'adventurous', label: 'Adventurous / loves to travel' },
      { value: 'fitness', label: 'Fitness-focused' },
      { value: 'balanced', label: 'A balance of everything' },
    ],
    matchPhrase: (label) => `share a similar lifestyle (${label.toLowerCase()})`,
  },
  {
    id: 'dealbreakers', type: 'multi', question: 'Any deal-breakers for you?',
    options: [
      { value: 'smoking', label: 'Smoking' },
      { value: 'heavy_drinking', label: 'Heavy drinking' },
      { value: 'diff_religion', label: 'Different religion' },
      { value: 'long_distance', label: 'Long distance' },
      { value: 'no_kids_wanted', label: "Doesn't want kids" },
      { value: 'none', label: 'No dealbreakers for me' },
    ],
  },
];

function validateQuestionnaireAnswers(answers) {
  const clean = {};
  for (const q of QUESTIONNAIRE) {
    const val = answers[q.id];
    if (val === undefined || val === null) continue;
    const validValues = q.options.map(o => o.value);
    if (q.type === 'single') {
      if (validValues.includes(val)) clean[q.id] = val;
    } else if (q.type === 'multi') {
      if (Array.isArray(val)) clean[q.id] = val.filter(v => validValues.includes(v));
    }
  }
  return clean;
}

// Turns a raw questionnaire answers object (question id -> value/values) into
// a readable list of { question, answer } for display on someone's profile.
// Only answered questions are included; unanswered ones are skipped.
function buildQuizAnswersDisplay(questionnaire) {
  if (!questionnaire) return [];
  const out = [];
  for (const q of QUESTIONNAIRE) {
    const val = questionnaire[q.id];
    if (val === undefined || val === null) continue;
    if (q.type === 'multi') {
      if (!Array.isArray(val) || !val.length) continue;
      const labels = val.map(v => (q.options.find(o => o.value === v) || {}).label).filter(Boolean);
      if (!labels.length) continue;
      out.push({ question: q.question, answer: labels.join(', ') });
    } else {
      const opt = q.options.find(o => o.value === val);
      if (!opt) continue;
      out.push({ question: q.question, answer: opt.label });
    }
  }
  return out;
}

// Compares two people's answers into a 0-100 score plus a few plain-English
// reasons they'd get along. (Raw answers are shown separately via
// buildQuizAnswersDisplay/toPublicUser — this function itself never leaks
// one person's specific answer through the other's "reasons".)
function computeCompatibility(a, b) {
  if (!a || !b || !Object.keys(a).length || !Object.keys(b).length) return null;

  let totalWeight = 0;
  let matchWeight = 0;
  const reasons = [];

  for (const q of QUESTIONNAIRE) {
    const av = a[q.id];
    const bv = b[q.id];
    if (av === undefined || bv === undefined) continue;

    if (q.type === 'single') {
      totalWeight += 1;
      if (av === bv) {
        matchWeight += 1;
        const label = (q.options.find(o => o.value === av) || {}).label || av;
        reasons.push(`You both ${q.matchPhrase(label)}`);
      }
    } else if (q.type === 'multi') {
      const setA = new Set(Array.isArray(av) ? av : []);
      const setB = new Set(Array.isArray(bv) ? bv : []);
      if (!setA.size && !setB.size) continue;
      totalWeight += 1;
      const union = new Set([...setA, ...setB]);
      const intersection = [...setA].filter(x => setB.has(x));
      const overlap = union.size ? intersection.length / union.size : 1;
      matchWeight += overlap;
    }
  }

  if (totalWeight === 0) return null;
  const percent = Math.round((matchWeight / totalWeight) * 100);
  return { percent, reasons: reasons.slice(0, 4) };
}

// ---------- Auth ----------

async function handleRegister(req, res) {
  const body = await readBody(req);
  const { name, email, password, age, bio, location, country, gender, tags } = body;

  if (!name || !email || !password) {
    return sendJSON(res, 400, { error: 'name, email, and password are required' });
  }
  if (password.length < 6) {
    return sendJSON(res, 400, { error: 'password must be at least 6 characters' });
  }
  if (!gender || !['man', 'woman', 'other'].includes(gender)) {
    return sendJSON(res, 400, { error: 'gender is required (man, woman, or other)' });
  }

  const { data: existing, error: existingErr } = await supabase
    .from('users').select('id').eq('email', email.toLowerCase()).maybeSingle();
  if (existingErr) throw existingErr;
  if (existing) {
    return sendJSON(res, 409, { error: 'An account with that email already exists' });
  }

  const { salt, hash } = hashPassword(password);
  const { data: created, error: insertErr } = await supabase
    .from('users')
    .insert({
      name,
      age: age || null,
      bio: bio || '',
      location: location || '',
      country: country || '',
      gender,
      tags: parseTags(tags),
      email: email.toLowerCase(),
      password_salt: salt,
      password_hash: hash,
    })
    .select()
    .single();
  if (insertErr) throw insertErr;

  const token = makeToken();
  await createSession(token, created.id);

  sendJSON(res, 201, { token, user: toOwnUser(created) });
}

async function handleLogin(req, res) {
  const body = await readBody(req);
  const { email, password } = body;
  if (!email || !password) {
    return sendJSON(res, 400, { error: 'email and password are required' });
  }

  const { data: user, error } = await supabase
    .from('users').select('*').eq('email', (email || '').toLowerCase()).maybeSingle();
  if (error) throw error;
  if (!user || !verifyPassword(password, user.password_salt, user.password_hash)) {
    return sendJSON(res, 401, { error: 'Invalid email or password' });
  }

  const token = makeToken();
  await createSession(token, user.id);
  sendJSON(res, 200, { token, user: toOwnUser(user) });
}

async function handleMe(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  sendJSON(res, 200, { user: toOwnUser(user) });
}

async function handleLogout(req, res) {
  const token = getAuthToken(req);
  if (token) await deleteSession(token);
  sendJSON(res, 200, { ok: true });
}

async function handleUpdateProfile(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req);
  const updates = {};
  if (body.name !== undefined) updates.name = body.name;
  if (body.age !== undefined) updates.age = body.age || null;
  if (body.bio !== undefined) updates.bio = body.bio;
  if (body.location !== undefined) updates.location = body.location;
  if (body.country !== undefined) updates.country = body.country;
  if (body.gender !== undefined && ['man', 'woman', 'other'].includes(body.gender)) updates.gender = body.gender;
  if (body.tags !== undefined) updates.tags = parseTags(body.tags);

  // Extended profile fields (see PROFILE_COMPLETION_FIELDS / matchesFilters
  // on the frontend). Each is validated against the same option lists used
  // by the "complete your profile" screen and the Discover filter panel, so
  // stored values always line up with what the filters check against.
  const ONE_WORD_SCALE = ['never', 'sometimes', 'often'];
  if (body.languages !== undefined) {
    updates.languages = Array.isArray(body.languages)
      ? body.languages.map(l => String(l).trim()).filter(Boolean).slice(0, 10)
      : [];
  }
  if (body.education !== undefined && ['', 'high_school', 'undergrad', 'postgrad', 'phd'].includes(body.education)) {
    updates.education = body.education;
  }
  if (body.heightCm !== undefined) {
    const h = parseInt(body.heightCm, 10);
    updates.height_cm = (Number.isFinite(h) && h >= 100 && h <= 250) ? h : null;
  }
  if (body.exercise !== undefined && ['', ...ONE_WORD_SCALE].includes(body.exercise)) updates.exercise = body.exercise;
  if (body.drinking !== undefined && ['', ...ONE_WORD_SCALE].includes(body.drinking)) updates.drinking = body.drinking;
  if (body.smoking !== undefined && ['', ...ONE_WORD_SCALE].includes(body.smoking)) updates.smoking = body.smoking;
  if (body.religion !== undefined && ['', 'christian', 'muslim', 'hindu', 'buddhist', 'jewish', 'spiritual', 'agnostic', 'atheist', 'other'].includes(body.religion)) {
    updates.religion = body.religion;
  }
  if (body.political !== undefined && ['', 'liberal', 'moderate', 'conservative', 'not_political', 'other'].includes(body.political)) {
    updates.political_views = body.political;
  }
  if (body.children !== undefined && ['', 'has', 'none', 'unspecified'].includes(body.children)) updates.children = body.children;
  if (body.wantsChildren !== undefined && ['', 'yes', 'no', 'maybe'].includes(body.wantsChildren)) updates.wants_children = body.wantsChildren;
  if (body.datingIntentions !== undefined) {
    const allowed = ['casual', 'relationship', 'marriage', 'friendship', 'not_sure'];
    updates.dating_intentions = Array.isArray(body.datingIntentions)
      ? body.datingIntentions.filter(v => allowed.includes(v))
      : [];
  }

  const { data: updated, error } = await supabase
    .from('users').update(updates).eq('id', user.id).select().single();
  if (error) throw error;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

// ---------- Profile prompts ("Prompts/Questions") ----------
// A short list of preset prompts a user can pick and answer (Hinge-style),
// stored in users.prompts (jsonb array of { question, answer }). See the
// column-add note near toPublicUser() above.
const PROMPT_LIBRARY = [
  'My simple pleasures are...',
  'Together, we could...',
  'The way to win me over is...',
  'A life goal of mine is...',
  'My most controversial opinion is...',
  'A typical Sunday for me looks like...',
  "I'm looking for someone who...",
  'Two truths and a lie about me...',
];
const MAX_PROMPTS = 3;
const MAX_PROMPT_ANSWER_LEN = 300;

function validatePrompts(input) {
  if (!Array.isArray(input)) return [];
  const seen = new Set();
  const clean = [];
  for (const p of input) {
    if (!p || typeof p !== 'object') continue;
    const question = String(p.question || '').trim();
    const answer = String(p.answer || '').trim().slice(0, MAX_PROMPT_ANSWER_LEN);
    if (!PROMPT_LIBRARY.includes(question) || !answer || seen.has(question)) continue;
    seen.add(question);
    clean.push({ question, answer });
    if (clean.length >= MAX_PROMPTS) break;
  }
  return clean;
}

async function handleGetPrompts(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  sendJSON(res, 200, { library: PROMPT_LIBRARY, answers: user.prompts || [] });
}

async function handleUpdatePrompts(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req);
  const clean = validatePrompts(body.prompts);

  const { data: updated, error } = await supabase
    .from('users').update({ prompts: clean }).eq('id', user.id).select().single();
  if (error) throw error;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

async function handleGetQuestionnaire(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  sendJSON(res, 200, { questions: QUESTIONNAIRE, answers: user.questionnaire || {} });
}

async function handleSubmitQuestionnaire(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req);
  const clean = validateQuestionnaireAnswers(body.answers || {});

  const { data: updated, error } = await supabase
    .from('users').update({ questionnaire: clean }).eq('id', user.id).select().single();
  if (error) throw error;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

// ---------- Photo upload ----------
// "My Vibes" gallery: up to 3 extra photos per user, stored in the
// users.gallery_urls column (jsonb array of public Storage URLs, default
// '[]'). This column isn't in the original setup SQL — add it once via:
//   ALTER TABLE users ADD COLUMN gallery_urls jsonb NOT NULL DEFAULT '[]';
// The 3-photo cap is enforced here in the handlers below, but that only
// protects against a single request at a time. For a hard guarantee against
// two simultaneous uploads sneaking past the limit, also add:
//   ALTER TABLE users ADD CONSTRAINT gallery_urls_max_3
//     CHECK (jsonb_array_length(gallery_urls) <= 3);

const ALLOWED_IMAGE_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
};

// Shared by the single profile photo and the My Vibes gallery photos.
function decodeImageDataUrl(photo) {
  if (!photo || typeof photo !== 'string') return { error: 'photo (base64 data URL) is required' };
  const match = photo.match(/^data:(image\/[a-zA-Z+]+);base64,(.+)$/);
  if (!match) return { error: 'photo must be a base64 image data URL' };
  const mimeType = match[1];
  const base64Data = match[2];
  const ext = ALLOWED_IMAGE_TYPES[mimeType];
  if (!ext) return { error: 'Unsupported image type. Use JPEG, PNG, WEBP, or GIF.' };
  const buffer = Buffer.from(base64Data, 'base64');
  if (buffer.length > MAX_BODY_BYTES) return { error: 'Image too large (max 8MB)' };
  return { mimeType, ext, buffer };
}

async function uploadToPhotosBucket(userId, tag, decoded) {
  const filename = `${userId}-${tag}-${Date.now()}.${decoded.ext}`;
  const { error: uploadErr } = await supabase.storage
    .from(PHOTOS_BUCKET)
    .upload(filename, decoded.buffer, { contentType: decoded.mimeType, upsert: true });
  if (uploadErr) throw uploadErr;
  const { data: urlData } = supabase.storage.from(PHOTOS_BUCKET).getPublicUrl(filename);
  return urlData.publicUrl;
}

// Best-effort cleanup of a replaced/deleted gallery photo. Never throws —
// a failure here shouldn't fail the request, it just leaves an orphaned
// file in Storage.
async function removeFromPhotosBucket(url) {
  if (!url) return;
  try {
    const marker = `/object/public/${PHOTOS_BUCKET}/`;
    const idx = url.indexOf(marker);
    if (idx === -1) return;
    const path = url.slice(idx + marker.length);
    await supabase.storage.from(PHOTOS_BUCKET).remove([path]);
  } catch (e) {
    // ignore — orphaned storage object, not worth failing the request over
  }
}

async function handleUploadPhoto(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 413, { error: err.message });
  }

  const decoded = decodeImageDataUrl(body.photo);
  if (decoded.error) return sendJSON(res, 400, { error: decoded.error });

  const photoUrl = await uploadToPhotosBucket(user.id, 'profile', decoded);

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ photo_url: photoUrl }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

// ---------- My Vibes gallery (up to 3 photos) ----------

async function handleAddGalleryPhoto(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const galleryUrls = user.gallery_urls || [];
  if (galleryUrls.length >= 3) {
    return sendJSON(res, 400, { error: 'You can upload up to 3 My Vibes photos.' });
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 413, { error: err.message });
  }

  const decoded = decodeImageDataUrl(body.photo);
  if (decoded.error) return sendJSON(res, 400, { error: decoded.error });

  const photoUrl = await uploadToPhotosBucket(user.id, 'vibes', decoded);

  // Re-read the row right before writing so two near-simultaneous uploads
  // can't both slip past the length check above (still not fully atomic
  // without the DB CHECK constraint noted above, but this narrows the gap).
  const fresh = await getUserById(user.id);
  const freshUrls = fresh.gallery_urls || [];
  if (freshUrls.length >= 3) {
    await removeFromPhotosBucket(photoUrl);
    return sendJSON(res, 400, { error: 'You can upload up to 3 My Vibes photos.' });
  }
  const newUrls = [...freshUrls, photoUrl];

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ gallery_urls: newUrls }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

async function handleReplaceGalleryPhoto(req, res, indexStr) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const index = parseInt(indexStr, 10);
  if (!Number.isInteger(index) || index < 0 || index > 2) {
    return sendJSON(res, 400, { error: 'Invalid photo slot' });
  }
  const galleryUrls = user.gallery_urls || [];
  if (index >= galleryUrls.length) {
    return sendJSON(res, 400, { error: 'That photo slot is empty' });
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 413, { error: err.message });
  }

  const decoded = decodeImageDataUrl(body.photo);
  if (decoded.error) return sendJSON(res, 400, { error: decoded.error });

  const photoUrl = await uploadToPhotosBucket(user.id, 'vibes', decoded);

  const oldUrl = galleryUrls[index];
  const newUrls = galleryUrls.slice();
  newUrls[index] = photoUrl;

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ gallery_urls: newUrls }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  await removeFromPhotosBucket(oldUrl);
  sendJSON(res, 200, { user: toOwnUser(updated) });
}

async function handleDeleteGalleryPhoto(req, res, indexStr) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const index = parseInt(indexStr, 10);
  if (!Number.isInteger(index) || index < 0 || index > 2) {
    return sendJSON(res, 400, { error: 'Invalid photo slot' });
  }
  const galleryUrls = user.gallery_urls || [];
  if (index >= galleryUrls.length) {
    return sendJSON(res, 400, { error: 'That photo slot is already empty' });
  }

  const removedUrl = galleryUrls[index];
  const newUrls = galleryUrls.slice();
  newUrls.splice(index, 1);

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ gallery_urls: newUrls }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  await removeFromPhotosBucket(removedUrl);
  sendJSON(res, 200, { user: toOwnUser(updated) });
}

async function handleReorderGalleryPhotos(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 413, { error: err.message });
  }

  const galleryUrls = user.gallery_urls || [];
  const from = parseInt(body.from, 10);
  const to = parseInt(body.to, 10);
  if (
    !Number.isInteger(from) || !Number.isInteger(to) ||
    from < 0 || from >= galleryUrls.length || to < 0 || to >= galleryUrls.length
  ) {
    return sendJSON(res, 400, { error: 'Invalid photo positions' });
  }

  const newUrls = galleryUrls.slice();
  const [moved] = newUrls.splice(from, 1);
  newUrls.splice(to, 0, moved);

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ gallery_urls: newUrls }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

// ---------- Discover / Likes / Matches ----------

async function handleDiscover(req, res, query) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const { data: swiped, error: swipedErr } = await supabase
    .from('likes').select('to_user_id').eq('from_user_id', user.id);
  if (swipedErr) throw swipedErr;
  const swipedIds = new Set((swiped || []).map(l => l.to_user_id));

  const { data: allUsers, error: usersErr } = await supabase.from('users').select('*');
  if (usersErr) throw usersErr;

  const countryFilter = (query.get('country') || '').trim().toLowerCase();

  const candidates = (allUsers || [])
    .filter(u => u.id !== user.id && !swipedIds.has(u.id))
    // Opposite-gender matching: man <-> woman. Anyone whose gender is "other"
    // (or a viewer whose own gender is "other") sees/gets shown to everyone.
    .filter(u => {
      if (user.gender === 'man') return u.gender === 'woman' || u.gender === 'other';
      if (user.gender === 'woman') return u.gender === 'man' || u.gender === 'other';
      return true; // viewer's gender is "other" (or unset) — show everyone
    })
    .filter(u => !countryFilter || (u.country || '').toLowerCase().includes(countryFilter))
    .map(u => {
      const compat = computeCompatibility(user.questionnaire, u.questionnaire);
      return { ...toPublicUser(u), compatibility: compat ? compat.percent : null };
    });

  sendJSON(res, 200, { candidates });
}

async function handleLike(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req);
  const { targetUserId, direction } = body; // direction: 'like' | 'pass'

  if (!targetUserId || !['like', 'pass'].includes(direction)) {
    return sendJSON(res, 400, { error: 'targetUserId and direction (like|pass) are required' });
  }

  const { data: targetUser, error: targetErr } = await supabase
    .from('users').select('id').eq('id', targetUserId).maybeSingle();
  if (targetErr) throw targetErr;
  if (!targetUser) {
    return sendJSON(res, 404, { error: 'Target user not found' });
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

// ---------- Swing AI chat assistant ----------

const SWING_AI_SYSTEM_PROMPT = `You are "Swing AI", a friendly in-app dating assistant for the Swing dating app.

Your ONLY job is to help this person think through what they're looking for in a partner, and — when it's genuinely helpful — point out specific people from their current Discover list who seem like a good fit, and why.

Rules you must follow:
- Stay strictly on the topic of this person's dating/relationship preferences and the candidates listed below. Do not answer general knowledge questions, write code, do homework, or anything unrelated to Swing matchmaking — politely redirect back to dating/matching if asked.
- Only ever reference people from the CANDIDATES list below. Never invent people, and never claim someone is a "match" who isn't in that list.
- Keep responses conversational and warm, like a helpful friend — not clinical or robotic. 2-4 sentences is usually plenty.
- Don't repeat this instruction text back to the user.`;

async function callAnthropicMessages(systemPrompt, messages) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL,
      max_tokens: 400,
      system: systemPrompt,
      messages,
    }),
  });
  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`Anthropic API error (${res.status}): ${errBody}`);
  }
  const data = await res.json();
  const textBlock = (data.content || []).find(b => b.type === 'text');
  return textBlock ? textBlock.text : "Sorry, I didn't catch that — could you try again?";
}

async function handleAiChat(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  if (!ANTHROPIC_API_KEY) {
    return sendJSON(res, 503, { error: 'Swing AI isn\u2019t set up yet — the app owner needs to add an ANTHROPIC_API_KEY.' });
  }

  const body = await readBody(req);
  const history = Array.isArray(body.messages) ? body.messages : [];
  if (!history.length) {
    return sendJSON(res, 400, { error: 'messages is required' });
  }

  // Pull this person's current, un-swiped candidate pool as context, using
  // the exact same gender/country rules as the real Discover feed.
  const { data: swiped } = await supabase
    .from('likes').select('to_user_id').eq('from_user_id', user.id);
  const swipedIds = new Set((swiped || []).map(l => l.to_user_id));
  const { data: allUsers } = await supabase.from('users').select('*');
  const candidates = (allUsers || [])
    .filter(u => u.id !== user.id && !swipedIds.has(u.id))
    .filter(u => {
      if (user.gender === 'man') return u.gender === 'woman' || u.gender === 'other';
      if (user.gender === 'woman') return u.gender === 'man' || u.gender === 'other';
      return true;
    })
    .slice(0, 30); // keep the prompt a reasonable size

  const candidateLines = candidates.map(c => {
    const bits = [`${c.name}${c.age ? ', ' + c.age : ''}`];
    if (c.location) bits.push(c.location);
    if (c.bio) bits.push(`bio: "${c.bio}"`);
    if (c.tags && c.tags.length) bits.push(`interests: ${c.tags.join(', ')}`);
    return `- ${bits.join(' | ')}`;
  }).join('\n');

  const systemPrompt = `${SWING_AI_SYSTEM_PROMPT}\n\nCANDIDATES currently available to this person:\n${candidateLines || '(no candidates available right now)'}`;

  const anthropicMessages = history
    .filter(m => m.role === 'user' || m.role === 'assistant')
    .map(m => ({ role: m.role, content: String(m.content || '').slice(0, 2000) }))
    .slice(-20); // cap conversation length sent per request

  try {
    const reply = await callAnthropicMessages(systemPrompt, anthropicMessages);
    sendJSON(res, 200, { reply });
  } catch (err) {
    console.error('Swing AI error:', err.message);
    sendJSON(res, 502, { error: 'Swing AI had trouble responding. Try again in a moment.' });
  }
}

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

  const { data: admirerRows, error: admirerErr } = await supabase
    .from('users').select('*').in('id', admirerIds);
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

// ---------- Messages ----------

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

  const body = await readBody(req);
  const { text } = body;
  if (!text || !text.trim()) {
    return sendJSON(res, 400, { error: 'text is required' });
  }

  const toUserId = match.user_id_1 === user.id ? match.user_id_2 : match.user_id_1;

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

// ---------- Frontend ----------

const FRONTEND_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, interactive-widget=resizes-content" />
<title>Swing — Meet someone worth staying for</title>
<meta name="description" content="Swing is a dating app to meet real people nearby. Sign up free, discover matches, and start chatting." />
<meta property="og:title" content="Swing — Meet someone worth staying for" />
<meta property="og:description" content="Sign up free, discover matches, and start chatting on Swing." />
<meta property="og:type" content="website" />
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Playball&family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --maroon-950: #33071f;
    --maroon-800: #4a0d2b;
    --maroon-700: #611038;
    --pink-500: #ec4c7e;
    --pink-600: #d63868;
    --pink-100: #ffe3ec;
    --cream: #fbf3ef;
    --card: #ffffff;
    --ink: #2a1620;
    --muted: #8c7a83;
    --gold: #e3a13f;
    --violet: #8b5cf6;
    --border: #f0e4e0;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: 'Poppins', sans-serif; background: var(--cream); color: var(--ink); }
  .logo-font { font-family: 'Playball', cursive; }
  button { font-family: inherit; cursor: pointer; touch-action: manipulation; -webkit-tap-highlight-color: transparent; }
  input, textarea { font-family: inherit; }

  #auth-screen {
    min-height: 100vh; position: relative; overflow: hidden;
    background:
      radial-gradient(circle at 75% 15%, rgba(236,76,126,0.35), transparent 45%),
      linear-gradient(155deg, #1a0e2e 0%, #3d1230 35%, #7a2545 60%, #c65a4f 80%, #e8926b 100%);
    display: flex; flex-direction: column;
  }
  .landing-map {
    position: absolute; top: 0; left: 0; right: 0; height: 55%; opacity: 0.35; pointer-events: none; z-index: 2;
  }
  .landing-couples {
    position: absolute; inset: 0; z-index: 1; pointer-events: none;
  }
  .landing-body {
    position: relative; z-index: 3; flex: 1; display: flex; align-items: center; justify-content: center;
    gap: 60px; padding: 60px 60px 40px; flex-wrap: wrap;
  }
  .landing-left { max-width: 460px; color: #fff; }
  .landing-brand { display: flex; align-items: center; gap: 10px; font-size: 26px; font-weight: 600; margin-bottom: 28px; }
  .landing-brand .logo-font { font-size: 30px; }
  .landing-kicker { color: var(--pink-500); font-weight: 700; font-size: 12.5px; letter-spacing: 1.5px; margin-bottom: 12px; }
  .landing-headline { font-size: clamp(24px, 3.4vw, 42px); line-height: 1.15; margin: 0 0 16px; font-weight: 700; }
  .landing-headline span { color: var(--pink-500); }
  .landing-sub { color: #e8d5db; font-size: 15px; line-height: 1.6; margin-bottom: 32px; max-width: 380px; }
  .landing-features { display: flex; gap: 26px; flex-wrap: wrap; }
  .landing-feature { text-align: center; max-width: 100px; }
  .landing-feature .ico {
    width: 44px; height: 44px; border-radius: 50%; background: rgba(255,255,255,0.12);
    display: flex; align-items: center; justify-content: center; font-size: 18px; margin: 0 auto 8px;
  }
  .landing-feature .label { font-size: 12px; color: #e8d5db; line-height: 1.3; }

  .auth-card { width: 100%; max-width: 380px; background: var(--card); border-radius: 20px; padding: 36px 32px; box-shadow: 0 25px 70px rgba(0,0,0,0.45); max-height: 90vh; overflow-y: auto; flex-shrink: 0; }
  .auth-card .logo-font { font-size: 40px; color: var(--pink-600); display: block; text-align: center; margin-bottom: 4px; }
  .auth-sub { text-align: center; color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .auth-tabs { display: flex; background: var(--pink-100); border-radius: 10px; padding: 4px; margin-bottom: 20px; }
  .auth-tabs button { flex: 1; border: none; background: transparent; padding: 9px; border-radius: 8px; font-size: 13px; font-weight: 600; color: var(--muted); }
  .auth-tabs button.active { background: var(--pink-600); color: white; }
  .auth-card input, .auth-card textarea, .auth-card select { width: 100%; padding: 12px 14px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 12px; font-size: 14px; outline: none; }
  .auth-card textarea { resize: vertical; min-height: 60px; }
  .auth-card input:focus, .auth-card textarea:focus { border-color: var(--pink-500); }
  .auth-submit { width: 100%; padding: 13px; border: none; border-radius: 10px; background: var(--pink-600); color: white; font-weight: 600; font-size: 14px; margin-top: 4px; }
  .auth-submit:hover { background: var(--pink-500); }
  .auth-error { color: var(--pink-600); font-size: 13px; margin-bottom: 10px; text-align: center; }
  .field-hint { font-size: 11.5px; color: var(--muted); margin: -6px 0 12px 2px; }

  .landing-footer {
    position: relative; z-index: 2; margin: 0 24px 24px; background: rgba(15,6,16,0.55); backdrop-filter: blur(6px);
    border-radius: 16px; padding: 18px 28px; display: flex; align-items: center; justify-content: space-between;
    gap: 20px; flex-wrap: wrap; color: #fff;
  }
  .landing-footer .globe-line { display: flex; align-items: center; gap: 8px; font-size: 14.5px; font-weight: 600; }
  .landing-footer .globe-line b { color: var(--pink-500); }
  .landing-footer .sub-line { color: #d8bfc7; font-size: 12.5px; }
  .landing-footer .join-badge {
    display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.08); padding: 8px 16px;
    border-radius: 20px; font-size: 12.5px; color: #f6dbe7;
  }

  @media (max-width: 900px) {
    .landing-body { flex-direction: column; padding: 32px 20px 20px; gap: 28px; }
    .landing-left { text-align: center; max-width: 100%; }
    .landing-brand { justify-content: center; }
    .landing-sub { margin-left: auto; margin-right: auto; }
    .landing-features { justify-content: center; }
    .auth-card { width: 100%; max-width: 380px; padding: 28px 24px; }
    .landing-footer { flex-direction: column; text-align: center; margin: 0 16px 16px; padding: 16px 20px; }
  }

  @media (max-width: 400px) {
    .landing-sub { font-size: 13.5px; }
    .landing-features { gap: 16px; }
    .landing-feature { max-width: 80px; }
  }

  #dashboard { display: none; min-height: 100vh; }
  #dashboard.visible { display: flex; }

  #questionnaire-screen {
    display: none; min-height: 100vh; align-items: center; justify-content: center;
    background: radial-gradient(circle at 30% 20%, var(--maroon-700), var(--maroon-950) 70%);
    padding: 24px;
  }
  #questionnaire-screen.visible { display: flex; }
  .q-card { width: 100%; max-width: 480px; background: white; border-radius: 22px; padding: 32px; box-shadow: 0 25px 70px rgba(0,0,0,0.4); }
  .q-header { text-align: center; margin-bottom: 20px; }
  .q-header .logo-font { font-size: 28px; color: var(--pink-600); }
  .q-header .q-kicker { font-weight: 700; color: var(--pink-600); font-size: 12px; letter-spacing: 1px; margin-top: 4px; display: inline-flex; align-items: center; gap: 5px; }
  .q-progress { font-size: 12px; color: var(--muted); text-align: center; margin-bottom: 6px; }
  .q-progress-bar { height: 5px; background: var(--border); border-radius: 4px; overflow: hidden; margin-bottom: 20px; }
  .q-progress-fill { height: 100%; background: var(--pink-600); transition: width 0.25s ease; }
  .q-title { font-size: 19px; margin: 0 0 4px; text-align: center; }
  .q-hint { text-align: center; font-size: 12px; color: var(--muted); margin-bottom: 14px; }
  .q-options { display: flex; flex-direction: column; gap: 10px; margin: 16px 0 24px; }
  .q-option {
    display: flex; align-items: center; justify-content: space-between; text-align: left;
    padding: 13px 16px; border: 1.5px solid var(--border); border-radius: 12px; background: white;
    font-size: 14px; font-weight: 500; color: var(--ink); cursor: pointer;
  }
  .q-option.selected { border-color: var(--pink-600); background: var(--pink-100); color: var(--pink-600); }
  .q-option .check { color: var(--pink-600); font-weight: 700; }
  .q-actions { display: flex; justify-content: space-between; align-items: center; }
  .q-actions button { border: none; padding: 12px 24px; border-radius: 10px; font-weight: 600; font-size: 14px; cursor: pointer; }
  #q-back-btn { background: var(--cream); color: var(--ink); }
  #q-next-btn { background: var(--pink-600); color: white; }
  .q-skip { display: block; text-align: center; margin-top: 16px; font-size: 12.5px; color: var(--muted); background: none; border: none; cursor: pointer; text-decoration: underline; }

  #details-screen {
    display: none; min-height: 100vh; align-items: center; justify-content: center;
    background: radial-gradient(circle at 30% 20%, var(--maroon-700), var(--maroon-950) 70%);
    padding: 24px;
  }
  #details-screen.visible { display: flex; }
  .details-body { max-height: 50vh; overflow-y: auto; padding: 2px 4px 2px 0; margin-bottom: 18px; }
  .details-body .filter-section { padding: 14px 0; }
  .details-body .filter-section:first-child { padding-top: 0; }
  #details-save-btn { background: linear-gradient(135deg, var(--pink-500), var(--pink-600)); color: white; border: none; padding: 13px 24px; border-radius: 10px; font-weight: 700; font-size: 14px; cursor: pointer; width: 100%; }

  .compat-badge {
    display: inline-flex; align-items: center; gap: 4px; background: rgba(236,76,126,0.9); color: white;
    font-size: 11.5px; font-weight: 700; padding: 4px 10px; border-radius: 20px;
  }
  .compat-panel { background: var(--pink-100); border-radius: 14px; padding: 14px 16px; margin: 0 0 12px; }
  .compat-panel .compat-percent { font-weight: 700; color: var(--pink-600); font-size: 15px; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }
  .compat-panel ul { margin: 0; padding-left: 18px; font-size: 12.5px; color: var(--ink); line-height: 1.6; }

  .sidebar { width: clamp(220px, 18vw, 300px); flex-shrink: 0; background: linear-gradient(180deg, var(--maroon-800), var(--maroon-950)); color: #f6dbe7; padding: 28px 20px; display: flex; flex-direction: column; }
  .sidebar .brand .logo-font { font-size: 34px; color: #fff; display: flex; align-items: center; gap: 6px; }
  .sidebar .tagline { font-size: 12.5px; color: #d8a9bd; line-height: 1.4; margin: 6px 0 28px; }
  .nav-item { display: flex; align-items: center; gap: 13px; padding: 14px 16px; border-radius: 12px; color: #f3d5e0; font-size: 15.5px; font-weight: 800; margin-bottom: 6px; border: none; background: transparent; width: 100%; text-align: left; letter-spacing: 0.1px; transition: background 0.15s ease, color 0.15s ease, transform 0.15s ease; }
  .nav-item .icon { width: 22px; text-align: center; display: inline-flex; align-items: center; justify-content: center; }
  .nav-item .icon svg { width: 21px; height: 21px; stroke-width: 2.8; }
  .nav-item .badge { margin-left: auto; background: rgba(255,255,255,0.2); color: #fff; font-size: 12px; padding: 3px 10px; border-radius: 20px; font-weight: 800; }
  .nav-item.active { background: linear-gradient(90deg, var(--pink-600), #b3245a); color: #fff; box-shadow: 0 8px 20px rgba(179,36,90,0.45); transform: translateX(2px); }
  .nav-item.active .icon svg { stroke-width: 3; }
  .nav-item.active .badge { background: rgba(255,255,255,0.3); }
  .nav-item:hover:not(.active) { background: rgba(255,255,255,0.1); color: #fff; }

  .sidebar-spacer { flex: 1; }
  .premium-card { background: linear-gradient(135deg, var(--pink-600), #b3245a); border-radius: 16px; padding: 16px; margin-bottom: 14px; color: white; }
  .premium-card .title { font-weight: 700; font-size: 14.5px; margin-bottom: 2px; }
  .premium-card .desc { font-size: 12px; opacity: 0.9; }
  .me-row { display: flex; align-items: center; gap: 10px; padding: 10px; border-radius: 12px; background: rgba(255,255,255,0.06); }
  .me-avatar { width: 38px; height: 38px; border-radius: 50%; background: var(--pink-500); color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 14px; flex-shrink: 0; }
  .me-row .name { font-size: 13.5px; font-weight: 600; color: #fff; }
  .me-row .link { font-size: 11.5px; color: #d8a9bd; background: none; border: none; padding: 0; cursor: pointer; }

  .main { flex: 1; padding: 28px 32px; overflow-x: hidden; }
  .topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 22px; gap: 20px; }
  .topbar h1 { font-size: 26px; margin: 0; }
  .search-box { flex: 1; max-width: 380px; display: flex; align-items: center; gap: 8px; background: white; border: 1px solid var(--border); border-radius: 12px; padding: 10px 14px; color: var(--muted); font-size: 13.5px; }
  .top-actions { display: flex; align-items: center; gap: 14px; }
  .icon-btn { width: 38px; height: 38px; border-radius: 50%; border: none; background: white; display: flex; align-items: center; justify-content: center; position: relative; font-size: 16px; }
  .icon-btn .dot { position: absolute; top: -3px; right: -3px; background: var(--pink-600); color: white; font-size: 10px; font-weight: 700; min-width: 16px; height: 16px; border-radius: 8px; display: flex; align-items: center; justify-content: center; padding: 0 3px; }
  /* Settings control — matches the app's pastel-pink premium look */
  .icon-btn#profile-settings-btn {
    width: 44px;
    height: 44px;
    min-width: 44px;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--border);
    background: var(--pink-100);
    color: var(--pink-600);
    border-radius: 14px;
    box-shadow: 0 3px 10px rgba(214,56,104,0.12);
    -webkit-tap-highlight-color: transparent;
    cursor: pointer;
    transition: transform .16s ease, box-shadow .16s ease, background .16s ease, color .16s ease, border-color .16s ease;
  }
  .icon-btn#profile-settings-btn span {
    font-size: 20px;
    line-height: 1;
    transition: transform .35s ease;
  }
  .icon-btn#profile-settings-btn:hover {
    background: linear-gradient(135deg, var(--pink-500), var(--pink-600));
    color: white;
    border-color: transparent;
    box-shadow: 0 6px 16px rgba(214,56,104,0.32);
    transform: translateY(-1px);
  }
  .icon-btn#profile-settings-btn:hover span {
    transform: rotate(45deg);
  }
  .icon-btn#profile-settings-btn:active {
    transform: scale(.94);
    box-shadow: 0 2px 8px rgba(214,56,104,0.25);
  }
  .icon-btn#profile-settings-btn:focus-visible {
    outline: 3px solid rgba(214,56,104,.22);
    outline-offset: 2px;
  }
  @media (max-width: 640px) {
    .icon-btn#profile-settings-btn {
      width: 42px;
      height: 42px;
      min-width: 42px;
      border-radius: 13px;
    }
  }
  .top-avatar { width: 38px; height: 38px; border-radius: 50%; background: var(--pink-500); color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; }

  .content-grid { display: flex; gap: 24px; align-items: flex-start; }
  .discover-col { flex: 1; min-width: 0; }
  .side-col { width: clamp(260px, 21vw, 360px); flex-shrink: 0; }
  .view-panel { display: none; }
  .view-panel.visible { display: block; }

  .filter-tabs { display: flex; gap: 8px; margin-bottom: 18px; }
  .filter-tabs button { display: flex; align-items: center; gap: 6px; border: 1px solid var(--border); background: white; padding: 9px 16px; border-radius: 20px; font-size: 13.5px; font-weight: 500; color: var(--muted); }
  .filter-tabs button.active { background: var(--maroon-800); color: white; border-color: var(--maroon-800); }

  .swipe-card { background: white; border-radius: 22px; overflow: hidden; box-shadow: 0 10px 40px rgba(75,20,45,0.1); }
  .swipe-photo { position: relative; aspect-ratio: 4 / 5; background-size: cover; background-position: center; display: flex; flex-direction: column; justify-content: flex-end; }
  .swipe-photo::after { content: ''; position: absolute; inset: 0; background: linear-gradient(180deg, transparent 40%, rgba(20,5,12,0.75) 100%); }
  .photo-tag { position: absolute; top: 16px; left: 16px; background: rgba(0,0,0,0.45); color: white; font-size: 12px; padding: 5px 12px; border-radius: 20px; z-index: 2; display: inline-flex; align-items: center; gap: 5px; }
  .swipe-details { position: relative; z-index: 2; padding: 20px 22px; color: white; }
  .swipe-details .name-row { display: flex; align-items: center; gap: 8px; font-size: 26px; font-weight: 700; }
  .swipe-details .meta { display: flex; gap: 14px; font-size: 12.5px; opacity: 0.9; margin: 4px 0 10px; }
  .swipe-details .meta span { display: inline-flex; align-items: center; gap: 4px; }
  .swipe-details .bio { font-size: 13.5px; opacity: 0.95; margin-bottom: 12px; max-width: 480px; }
  .tag-pills { display: flex; gap: 8px; flex-wrap: wrap; }
  .tag-pills span { background: rgba(255,255,255,0.18); backdrop-filter: blur(4px); padding: 5px 12px; border-radius: 20px; font-size: 12px; }
  .empty-state { background: white; border-radius: 22px; padding: 60px 30px; text-align: center; color: var(--muted); }

  /* ---------- Discover card — About Me / Interests / My Vibes panel ---------- */
  .swipe-card-body { padding: 20px 22px 22px; display: flex; flex-direction: column; gap: 18px; }
  .swipe-section-title { display: flex; align-items: center; gap: 9px; margin-bottom: 10px; font-size: 14px; font-weight: 700; color: var(--ink); }
  .swipe-section-title .icon-circle { width: 28px; height: 28px; border-radius: 50%; background: var(--pink-100); color: var(--pink-600); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .swipe-section-text { margin: 0; font-size: 13.5px; line-height: 1.6; color: var(--ink); opacity: 0.85; white-space: pre-wrap; }
  .swipe-section-text.empty { opacity: 0.5; font-style: italic; }
  .swipe-vibes-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .swipe-vibes-thumb { aspect-ratio: 1; border-radius: 12px; overflow: hidden; background: var(--cream); }
  .swipe-vibes-thumb img { width: 100%; height: 100%; object-fit: cover; display: block; }

  .swipe-actions { display: flex; justify-content: center; align-items: center; gap: 18px; padding: 22px 0 6px; }
  .swipe-actions button { border: none; border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }
  .act-pass { width: 62px; height: 62px; background: white; color: #d8536b; font-size: 24px; }
  .act-like { width: 62px; height: 62px; background: linear-gradient(135deg, var(--pink-500), var(--pink-600)); color: white; font-size: 24px; }
  .swipe-hint { text-align: center; font-size: 12.5px; color: var(--muted); }

  .side-card { background: white; border-radius: 18px; padding: 18px; margin-bottom: 18px; }
  .side-card .side-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
  .side-card .side-head h3 { font-size: 16px; margin: 0; }
  .side-card .side-head a, .side-card .side-head .text-link { font-size: 12.5px; color: var(--pink-600); text-decoration: none; font-weight: 500; cursor: pointer; background: none; border: none; padding: 0; font-family: inherit; }
  .side-card .side-head .text-link:hover, .side-card .side-head a:hover { text-decoration: underline; }

  .match-avatars { display: flex; gap: 14px; flex-wrap: wrap; }
  .match-avatar-wrap { text-align: center; cursor: pointer; }
  .match-avatar { width: 56px; height: 56px; border-radius: 50%; border: 2.5px solid var(--pink-500); position: relative; display: flex; align-items: center; justify-content: center; color: white; font-weight: 700; font-size: 16px; }
  .match-avatar .heart-badge { position: absolute; bottom: -2px; right: -2px; width: 18px; height: 18px; border-radius: 50%; background: var(--pink-600); color: white; font-size: 9px; display: flex; align-items: center; justify-content: center; border: 2px solid white; }
  .match-avatar-wrap .mname { font-size: 11.5px; margin-top: 6px; color: var(--ink); }
  .muted-note { color: var(--muted); font-size: 13px; }

  .msg-item { display: flex; gap: 10px; padding: 10px 0; border-bottom: 1px solid var(--border); cursor: pointer; }
  .msg-item:last-child { border-bottom: none; }
  .msg-avatar { width: 40px; height: 40px; border-radius: 50%; color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; flex-shrink: 0; }
  .msg-body { flex: 1; min-width: 0; }
  .msg-top { display: flex; justify-content: space-between; font-size: 13px; }
  .msg-top .mname { font-weight: 600; }
  .msg-top .time { color: var(--muted); font-size: 11px; }
  .msg-preview { font-size: 12px; color: var(--muted); display: flex; justify-content: space-between; gap: 6px; }
  .msg-preview .text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .unread-dot { background: var(--pink-600); color: white; font-size: 10px; font-weight: 700; width: 16px; height: 16px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }

  .promo-card { background: linear-gradient(135deg, var(--pink-100), #ffd3e2); border-radius: 18px; padding: 20px; }
  .promo-card h4 { margin: 0 0 6px; font-size: 15.5px; }
  .promo-card p { font-size: 12.5px; color: #7a5a66; margin: 0 0 14px; line-height: 1.5; }
  .promo-card button { background: var(--maroon-800); color: white; border: none; padding: 10px 18px; border-radius: 10px; font-size: 13px; font-weight: 600; }

  /* Chat view */
  .chat-panel { background: white; border-radius: 22px; display: flex; flex-direction: column; height: clamp(480px, calc(100dvh - 160px), 760px); }
  .chat-header { display: flex; align-items: center; gap: 12px; padding: 16px 20px; border-bottom: 1px solid var(--border); }
  .chat-header .back-btn { background: var(--cream); border: none; width: 34px; height: 34px; border-radius: 50%; font-size: 15px; }
  .chat-messages { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 10px; }
  .bubble { max-width: 65%; padding: 10px 14px; border-radius: 16px; font-size: 13.5px; line-height: 1.4; }
  .bubble.mine { align-self: flex-end; background: var(--pink-600); color: white; border-bottom-right-radius: 4px; }
  .bubble.theirs { align-self: flex-start; background: var(--cream); color: var(--ink); border-bottom-left-radius: 4px; }
  .chat-input-row { display: flex; gap: 10px; padding: 16px 20px; border-top: 1px solid var(--border); }
  .chat-input-row input { flex: 1; min-width: 0; padding: 11px 14px; border: 1px solid var(--border); border-radius: 10px; outline: none; font-size: 13.5px; }
  .chat-input-row button { background: var(--pink-600); color: white; border: none; padding: 0 18px; border-radius: 10px; font-weight: 600; font-size: 13px; flex-shrink: 0; white-space: nowrap; }

  /* Likes You grid */
  .admirer-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 14px; }
  .admirer-card { background: white; border-radius: 16px; padding: 16px; text-align: center; }
  .admirer-card .match-avatar { margin: 0 auto 8px; }
  .admirer-card .aname { font-weight: 600; font-size: 13.5px; }
  .admirer-card button { margin-top: 10px; width: 100%; padding: 8px; border: none; border-radius: 8px; background: var(--pink-600); color: white; font-size: 12.5px; font-weight: 600; }

  /* Profile view */
  .profile-form { background: white; border-radius: clamp(14px, 3vw, 18px); padding: clamp(18px, 5vw, 24px); width: 100%; max-width: min(480px, 100%); }
  .profile-form label { display: block; font-size: 12.5px; font-weight: 600; color: var(--muted); margin-bottom: 4px; }
  .profile-form input, .profile-form textarea, .profile-form select { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 14px; font-size: 14px; box-sizing: border-box; }
  .profile-form textarea { resize: vertical; min-height: 70px; }
  .profile-form button { background: var(--pink-600); color: white; border: none; padding: 11px 20px; border-radius: 10px; font-weight: 600; font-size: 13.5px; }

  /* ---------- Profile view (redesign) ---------- */
  .profile-view { width: 100%; max-width: min(480px, 100%); display: flex; flex-direction: column; gap: clamp(14px, 3vw, 18px); }
  .profile-header-card {
    background: var(--card); border-radius: clamp(18px, 4vw, 26px);
    padding: clamp(20px, 5vw, 28px) clamp(16px, 5vw, 24px) clamp(18px, 4vw, 24px);
    box-shadow: 0 12px 32px rgba(214,56,104,0.08); text-align: center;
    position: relative; animation: profileFadeIn 0.35s ease;
  }
  @keyframes profileFadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
  .profile-header-topbar { display: flex; justify-content: flex-end; margin-bottom: -4px; }
  .profile-settings-icon-btn {
    width: 36px; height: 36px; border-radius: 50%; border: none; background: var(--cream);
    color: var(--muted); display: flex; align-items: center; justify-content: center;
    transition: background 0.2s ease, color 0.2s ease, transform 0.2s ease;
  }
  .profile-settings-icon-btn:hover { background: var(--pink-100); color: var(--pink-600); transform: rotate(20deg); }
  .profile-photo-wrap { position: relative; width: clamp(84px, 22vw, 108px); height: clamp(84px, 22vw, 108px); margin: 0 auto 14px; }
  .profile-photo-wrap .match-avatar {
    width: 100%; height: 100%; font-size: clamp(26px, 7vw, 34px); border: 3px solid var(--pink-100);
    box-shadow: 0 8px 24px rgba(214,56,104,0.18);
  }
  .profile-photo-camera-btn {
    position: absolute; bottom: 0; right: 0; width: 34px; height: 34px; border-radius: 50%;
    background: linear-gradient(135deg, var(--pink-500), var(--pink-600)); color: white; border: 3px solid white;
    display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 10px rgba(214,56,104,0.35);
    transition: transform 0.2s ease;
  }
  .profile-photo-camera-btn:hover { transform: scale(1.08); }
  .profile-name-row { display: flex; align-items: center; justify-content: center; gap: 6px; }
  .profile-name-row h2 { margin: 0; font-size: clamp(18px, 4.5vw, 21px); font-weight: 700; color: var(--ink); letter-spacing: -0.2px; }
  .profile-verified-badge {
    width: 19px; height: 19px; border-radius: 50%; background: linear-gradient(135deg, var(--pink-500), var(--violet));
    color: white; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;
  }
  .profile-meta-line { font-size: 13.5px; color: var(--muted); font-weight: 500; margin: 4px 0 0; }
  .profile-tagline { font-size: 13.5px; color: var(--ink); opacity: 0.75; margin: 8px 0 0; line-height: 1.5; }
  .profile-edit-btn {
    width: 100%; margin-top: 16px; padding: 14px; border: none; border-radius: 14px;
    background: linear-gradient(135deg, var(--pink-500), var(--pink-600)); color: white;
    font-weight: 700; font-size: 14.5px; box-shadow: 0 8px 20px rgba(214,56,104,0.28);
    display: flex; align-items: center; justify-content: center; gap: 8px;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
  }
  .profile-edit-btn:hover { transform: translateY(-1px); box-shadow: 0 10px 24px rgba(214,56,104,0.36); }
  .about-card {
    background: var(--card); border-radius: clamp(16px, 4vw, 22px); padding: clamp(16px, 5vw, 22px) clamp(16px, 5vw, 24px);
    box-shadow: 0 12px 32px rgba(214,56,104,0.06); animation: profileFadeIn 0.4s ease;
  }
  .about-card-header { display: flex; align-items: center; gap: 9px; margin-bottom: 12px; }
  .about-card-header .icon-circle {
    width: 30px; height: 30px; border-radius: 50%; background: var(--pink-100); color: var(--pink-600);
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  }
  .about-card-header h3 { margin: 0; font-size: 15px; font-weight: 700; color: var(--ink); }
  .about-card-text { margin: 0; font-size: 14px; line-height: 1.7; color: var(--ink); opacity: 0.85; white-space: pre-wrap; }
  .about-card-text.empty { opacity: 0.5; font-style: italic; }
  .profile-edit-header { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
  .profile-edit-back-btn {
    width: 34px; height: 34px; border-radius: 50%; border: 1px solid var(--border); background: var(--cream);
    color: var(--ink); display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  }
  .profile-edit-header h3 { margin: 0; font-size: 16px; font-weight: 700; color: var(--ink); }
  .interests-chips { display: flex; flex-wrap: wrap; gap: 8px; }
  .interest-chip {
    background: var(--pink-100); color: var(--pink-600); font-size: 12.5px; font-weight: 600;
    padding: 7px 14px; border-radius: 999px; white-space: nowrap; line-height: 1.2;
  }
  .quick-info-card-text.empty, .interests-empty-note { font-size: 13px; color: var(--muted); font-style: italic; margin: 0; }

  /* ---------- About Me / I'm looking for — pill chips ---------- */
  .about-pills-grid { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }
  .about-pills-grid:first-child { margin-top: 0; }
  .about-pill {
    display: inline-flex; align-items: center; gap: 9px; background: var(--cream);
    color: var(--ink); font-size: 14px; font-weight: 600; padding: 11px 18px;
    border-radius: 999px; line-height: 1.2; white-space: nowrap;
  }
  .about-pill .icon-circle { width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; color: var(--ink); background: none; }
  .about-card-edit-link { font-size: 12.5px; color: var(--pink-600); font-weight: 700; background: none; border: none; padding: 0; cursor: pointer; font-family: inherit; }
  .about-card-edit-link:hover { text-decoration: underline; }

  /* ---------- Legacy quick-info (kept for any old references) ---------- */
  .quick-info-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 16px 12px; }
  @media (max-width: 480px) { .quick-info-grid { grid-template-columns: repeat(2, 1fr); } }
  .quick-info-item { display: flex; align-items: flex-start; gap: 9px; min-width: 0; }
  .quick-info-item .icon-circle { width: 30px; height: 30px; border-radius: 50%; background: var(--pink-100); color: var(--pink-600); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .quick-info-item .qi-text { display: flex; flex-direction: column; min-width: 0; }
  .quick-info-item .qi-label { font-size: 10px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 1px; }
  .quick-info-item .qi-value { font-size: 13px; font-weight: 600; color: var(--ink); overflow-wrap: break-word; }

  /* ---------- My Vibes gallery ---------- */
  .vibes-counter { font-size: 12px; font-weight: 700; color: var(--muted); }
  .vibes-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  .vibes-slot {
    position: relative; aspect-ratio: 3 / 4; border-radius: 16px; overflow: hidden;
    background: var(--cream); border: none; padding: 0;
  }
  .vibes-slot img {
    width: 100%; height: 100%; object-fit: cover; display: block;
    transition: transform 0.3s ease, opacity 0.3s ease; opacity: 0; background: var(--border);
  }
  .vibes-slot img.loaded { opacity: 1; }
  .vibes-slot:hover img, .vibes-slot:active img { transform: scale(1.05); }
  .vibes-slot-empty {
    border: 2px dashed var(--border); display: flex; align-items: center; justify-content: center;
    flex-direction: column; gap: 6px; color: var(--muted); cursor: pointer;
    transition: border-color 0.2s ease, color 0.2s ease, background 0.2s ease;
  }
  .vibes-slot-empty:hover { border-color: var(--pink-500); color: var(--pink-600); background: var(--pink-100); }
  .vibes-slot-actions { position: absolute; top: 7px; right: 7px; display: flex; gap: 6px; z-index: 2; }
  .vibes-slot-actions button {
    width: 28px; height: 28px; border-radius: 50%; background: rgba(255,255,255,0.94); color: var(--pink-600);
    border: none; display: flex; align-items: center; justify-content: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.18); transition: transform 0.15s ease;
  }
  .vibes-slot-actions button:hover, .vibes-slot-actions button:active { transform: scale(0.92); background: white; }
  .vibes-slot-loading {
    position: absolute; inset: 0; background: rgba(255,255,255,0.8);
    display: flex; align-items: center; justify-content: center; z-index: 3;
  }
  .vibes-spinner {
    width: 22px; height: 22px; border: 3px solid var(--pink-100); border-top-color: var(--pink-600);
    border-radius: 50%; animation: vibesSpin 0.7s linear infinite;
  }
  @keyframes vibesSpin { to { transform: rotate(360deg); } }
  .vibes-status { font-size: 11.5px; color: var(--muted); margin-top: 10px; min-height: 14px; }

  /* ---------- Prompts ---------- */
  .prompt-view-card { background: var(--cream); border-radius: 14px; padding: 14px 16px; margin-bottom: 10px; }
  .prompt-view-card:last-child { margin-bottom: 0; }
  .prompt-view-question { font-size: 12px; font-weight: 700; color: var(--pink-600); margin-bottom: 5px; }
  .prompt-view-answer { font-size: 13.5px; line-height: 1.5; color: var(--ink); white-space: pre-wrap; }
  .prompt-edit-row { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
  .prompt-edit-row select {
    padding: 9px 12px; border-radius: 10px; border: 1px solid var(--border); background: white;
    font-size: 13px; font-family: inherit;
  }
  .prompt-edit-row textarea {
    padding: 9px 12px; border-radius: 10px; border: 1px solid var(--border); background: white;
    font-size: 13px; font-family: inherit; min-height: 56px; resize: vertical;
  }
  @media (max-width: 560px) {
    .vibes-grid {
      display: flex; grid-template-columns: none; overflow-x: auto; scroll-snap-type: x mandatory;
      padding-bottom: 4px; margin: 0 -2px; -webkit-overflow-scrolling: touch;
    }
    .vibes-slot { flex: 0 0 auto; width: clamp(120px, 42vw, 170px); scroll-snap-align: start; }
  }
  .vibes-slot-actions button + button { margin-left: 0; }
  .vibes-grid-view { grid-template-columns: repeat(3, 1fr); }
  .vibes-grid-view .vibes-slot-view { cursor: default; }
  .quick-info-card-text { margin: 0; }
  .edit-vibes-section { margin: 4px 0 16px; padding-top: 14px; border-top: 1px solid var(--border); }
  .save-note { font-size: 12.5px; color: #4caf7a; margin-left: 10px; }

  .app-footer { display: flex; justify-content: space-between; align-items: center; margin-top: 26px; padding-top: 18px; border-top: 1px solid var(--border); font-size: 12px; color: var(--muted); }
  .app-footer .links { display: flex; gap: 18px; }

  .mobile-nav { display: none; }

  @media (max-width: 1000px) { .side-col { display: none; } }
  @media (max-width: 720px) {
    .sidebar { display: none; }
    .main { padding: 14px 14px 84px; }

    /* ---------- Bottom nav: compact, icon-only, outline/filled toggle ---------- */
    .mobile-nav {
      display: flex; position: fixed; bottom: 0; left: 0; right: 0; z-index: 50;
      background: #ffffff; border-top: 1px solid var(--border);
      box-shadow: 0 -1px 12px rgba(42,22,32,0.05);
      padding-bottom: env(safe-area-inset-bottom, 0px);
      transition: background 0.2s ease, border-color 0.2s ease;
    }
    .mobile-nav-item {
      flex: 1; height: 56px; border: none; background: transparent; padding: 0;
      display: flex; align-items: center; justify-content: center;
      color: #b3a2ab; position: relative; -webkit-tap-highlight-color: transparent;
      transition: color 0.18s ease, transform 0.18s ease;
    }
    .mobile-nav-item:active { transform: scale(0.9); }
    .mobile-nav-item .icon { display: flex; width: 44px; height: 44px; align-items: center; justify-content: center; }
    .mobile-nav-item .icon svg { width: 23px; height: 23px; transition: opacity 0.15s ease; }
    .mobile-nav-item .icon-filled { display: none; }
    .mobile-nav-item.active { color: var(--pink-600); }
    .mobile-nav-item.active .icon-outline { display: none; }
    .mobile-nav-item.active .icon-filled { display: block; }
    .mobile-nav-item .nav-dot {
      position: absolute; bottom: 5px; left: 50%; transform: translateX(-50%) scale(0.4);
      width: 4px; height: 4px; border-radius: 50%; background: var(--pink-600);
      opacity: 0; transition: opacity 0.18s ease, transform 0.18s ease;
    }
    .mobile-nav-item.active:not(.mobile-nav-fab) .nav-dot { opacity: 1; transform: translateX(-50%) scale(1); }
    .mobile-nav-item .mnav-badge {
      position: absolute; top: 4px; right: calc(50% - 20px); background: var(--pink-600); color: white;
      font-size: 9px; font-weight: 800; min-width: 14px; height: 14px; border-radius: 7px;
      display: flex; align-items: center; justify-content: center; padding: 0 3px;
    }
    .mobile-nav-fab {
      position: relative;
    }
    .mobile-nav-fab .icon {
      position: relative; top: -14px; width: 50px; height: 50px; border-radius: 50%;
      background: linear-gradient(155deg, var(--pink-500), var(--pink-600));
      color: white; box-shadow: 0 6px 16px rgba(179,36,90,0.4);
    }
    .mobile-nav-fab .icon svg { width: 21px; height: 21px; }
    .mobile-nav-fab .icon-filled { display: block; }
    .mobile-nav-fab .icon-outline { display: none; }
    @media (prefers-color-scheme: dark) {
      .mobile-nav { background: #17181c; border-top-color: rgba(255,255,255,0.08); box-shadow: 0 -1px 16px rgba(0,0,0,0.35); }
      .mobile-nav-item { color: #6e7079; }
      .mobile-nav-item.active { color: #ff6f93; }
      .mobile-nav-item.active .nav-dot { background: #ff6f93; }
    }
    @media (prefers-reduced-motion: reduce) {
      .mobile-nav-item, .mobile-nav-item .icon svg, .mobile-nav-item .nav-dot { transition: none; }
    }
    .chat-panel { height: calc(100vh - 200px); height: calc(100dvh - 200px); }
    .chat-input-row { padding-bottom: calc(16px + env(safe-area-inset-bottom, 0px)); }
    body.chat-open .mobile-nav { display: none; }
    body.chat-open .main { padding-bottom: 14px; }
    body.chat-open .topbar { display: none; }
    body.chat-open .chat-panel { height: calc(100vh - 32px); height: calc(100dvh - 32px); }
    input, textarea, select { font-size: 16px !important; }
    .topbar { flex-wrap: wrap; row-gap: 10px; }
    .topbar h1 { font-size: 21px; }
    .search-box { order: 3; flex-basis: 100%; max-width: none; }
    .content-grid { gap: 16px; }
    .swipe-photo { aspect-ratio: 4 / 5; min-height: 0; }
    .chat-input-row button, .profile-form button, .admirer-card button { min-height: 44px; }
    .swipe-actions button, .icon-btn, .back-btn, .nav-item, .mobile-nav-item { min-height: 44px; }
  }

  /* ---------- Filter system ---------- */
  .icon-btn.filter-btn.has-active { color: var(--pink-600); }
  .filter-overlay {
    position: fixed; inset: 0; background: rgba(20,5,12,0.45); z-index: 200;
    opacity: 0; pointer-events: none; transition: opacity 0.25s ease;
  }
  .filter-overlay.open { opacity: 1; pointer-events: auto; }

  .filter-panel {
    position: fixed; left: 0; right: 0; bottom: 0; z-index: 201;
    background: var(--card); border-radius: 20px 20px 0 0;
    max-height: 86vh; display: flex; flex-direction: column;
    box-shadow: 0 -12px 40px rgba(20,5,12,0.25);
    transform: translateY(100%); transition: transform 0.32s cubic-bezier(.32,.72,0,1);
  }
  .filter-panel.open { transform: translateY(0); }

  .filter-panel-handle { width: 36px; height: 4px; border-radius: 3px; background: var(--border); margin: 10px auto 2px; flex-shrink: 0; }

  .filter-panel-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 20px 12px; border-bottom: 1px solid var(--border); flex-shrink: 0;
  }
  .filter-panel-header h2 { margin: 0; font-size: 17px; }
  .filter-panel-close {
    width: 32px; height: 32px; border-radius: 50%; border: none; background: var(--cream);
    color: var(--muted); display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  }

  .filter-panel-body { overflow-y: auto; padding: 4px 20px 20px; flex: 1; -webkit-overflow-scrolling: touch; }

  .filter-section { padding: 18px 0; border-bottom: 1px solid var(--border); }
  .filter-section:last-child { border-bottom: none; }
  .filter-section-title { font-size: 12px; font-weight: 800; letter-spacing: 0.3px; color: var(--pink-600); margin: 0 0 14px; }

  .filter-field { margin-bottom: 16px; }
  .filter-field:last-child { margin-bottom: 0; }
  .filter-field-label { display: flex; align-items: center; justify-content: space-between; font-size: 13px; font-weight: 600; color: var(--ink); margin-bottom: 8px; }
  .filter-field-label .val { font-weight: 700; color: var(--pink-600); }

  .filter-chips { display: flex; flex-wrap: wrap; gap: 8px; }
  .filter-chip {
    border: 1.5px solid var(--border); background: white; color: var(--ink);
    padding: 9px 15px; border-radius: 999px; font-size: 13px; font-weight: 600;
    min-height: 38px; display: inline-flex; align-items: center; transition: all 0.15s ease;
  }
  .filter-chip:active { transform: scale(0.96); }
  .filter-chip.selected { background: linear-gradient(135deg, var(--pink-500), var(--pink-600)); border-color: var(--pink-600); color: white; }

  .filter-input, .filter-select {
    width: 100%; padding: 11px 13px; border: 1.5px solid var(--border); border-radius: 10px;
    font-size: 13.5px; font-family: inherit; color: var(--ink); background: white; outline: none;
  }
  .filter-input:focus, .filter-select:focus { border-color: var(--pink-500); }

  .filter-toggle-row { display: flex; align-items: center; justify-content: space-between; }
  .filter-toggle-row .filter-field-label { margin-bottom: 0; }
  .filter-switch { position: relative; width: 44px; height: 26px; border-radius: 13px; background: #e6dde1; border: none; flex-shrink: 0; transition: background 0.2s ease; }
  .filter-switch::after { content: ''; position: absolute; top: 3px; left: 3px; width: 20px; height: 20px; border-radius: 50%; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.25); transition: transform 0.2s ease; }
  .filter-switch.on { background: var(--pink-600); }
  .filter-switch.on::after { transform: translateX(18px); }

  .dual-range { position: relative; height: 32px; margin-top: 4px; }
  .dual-range .track { position: absolute; top: 14px; left: 0; right: 0; height: 4px; border-radius: 2px; background: var(--border); }
  .dual-range .fill { position: absolute; top: 14px; height: 4px; border-radius: 2px; background: var(--pink-600); }
  .dual-range input[type="range"] {
    position: absolute; top: 6px; left: 0; width: 100%; margin: 0; height: 20px;
    background: transparent; pointer-events: none; -webkit-appearance: none; appearance: none;
  }
  .dual-range input[type="range"]::-webkit-slider-thumb {
    pointer-events: auto; -webkit-appearance: none; appearance: none;
    width: 18px; height: 18px; border-radius: 50%; background: var(--pink-600);
    border: 2.5px solid white; box-shadow: 0 1px 5px rgba(20,5,12,0.35); cursor: pointer; margin-top: -7px;
  }
  .dual-range input[type="range"]::-moz-range-thumb {
    pointer-events: auto; width: 18px; height: 18px; border-radius: 50%; background: var(--pink-600);
    border: 2.5px solid white; box-shadow: 0 1px 5px rgba(20,5,12,0.35); cursor: pointer;
  }
  .dual-range input[type="range"]::-webkit-slider-runnable-track { background: transparent; height: 4px; }
  .dual-range input[type="range"]::-moz-range-track { background: transparent; height: 4px; }

  .single-range { display: flex; align-items: center; gap: 12px; margin-top: 4px; }
  .single-range input[type="range"] { flex: 1; accent-color: var(--pink-600); height: 20px; }

  .filter-panel-footer {
    display: flex; gap: 10px; padding: 14px 20px; border-top: 1px solid var(--border); flex-shrink: 0;
    padding-bottom: calc(14px + env(safe-area-inset-bottom, 0px));
  }
  .filter-reset-btn, .filter-apply-btn {
    flex: 1; border: none; border-radius: 12px; padding: 13px; font-size: 14px; font-weight: 700;
    min-height: 46px; font-family: inherit;
  }
  .filter-reset-btn { background: var(--cream); color: var(--ink); }
  .filter-apply-btn { background: linear-gradient(135deg, var(--pink-500), var(--pink-600)); color: white; display: flex; align-items: center; justify-content: center; gap: 6px; }

  @media (min-width: 721px) {
    .filter-panel {
      left: auto; top: 0; right: 0; bottom: 0; width: 400px; max-height: none;
      border-radius: 0; box-shadow: -14px 0 40px rgba(20,5,12,0.18);
      transform: translateX(100%); transition: transform 0.32s cubic-bezier(.32,.72,0,1);
    }
    .filter-panel.open { transform: translateX(0); }
    .filter-panel-handle { display: none; }
    .filter-panel-header { padding-top: 20px; }
  }

  @media (prefers-reduced-motion: reduce) {
    .filter-overlay, .filter-panel, .filter-chip, .filter-switch, .filter-switch::after { transition: none; }
  }

  /* ---------- Settings panel ---------- */
  .settings-overlay {
    position: fixed; inset: 0; background: rgba(20,5,12,0.45); z-index: 210;
    opacity: 0; pointer-events: none; transition: opacity 0.25s ease;
  }
  .settings-overlay.open { opacity: 1; pointer-events: auto; }
  .settings-panel {
    position: fixed; top: 0; right: 0; bottom: 0; z-index: 211;
    width: min(440px, 100vw); background: var(--card); color: var(--ink);
    box-shadow: -12px 0 40px rgba(20,5,12,0.22);
    transform: translateX(100%); transition: transform 0.3s cubic-bezier(.32,.72,0,1);
    display: flex; flex-direction: column;
  }
  .settings-panel.open { transform: translateX(0); }
  .settings-header { display:flex; align-items:center; gap:12px; padding:18px 20px; border-bottom:1px solid var(--border); flex-shrink:0; }
  .settings-header h2 { margin:0; font-size:19px; flex:1; }
  .settings-close { width:34px; height:34px; border:0; border-radius:50%; background:var(--cream); color:var(--muted); display:flex; align-items:center; justify-content:center; }
  .settings-body { overflow-y:auto; padding:16px 16px 28px; }
  .settings-section { margin-bottom:20px; }
  .settings-section-title { margin:0 4px 8px; font-size:11px; font-weight:800; letter-spacing:1px; color:var(--muted); }
  .settings-card { background:var(--card); border:1px solid var(--border); border-radius:16px; overflow:hidden; }
  .settings-row { width:100%; min-height:58px; padding:12px 14px; display:flex; align-items:center; gap:12px; border:0; border-bottom:1px solid var(--border); background:transparent; color:var(--ink); text-align:left; font:inherit; }
  .settings-row:last-child { border-bottom:0; }
  .settings-row.clickable { cursor:pointer; }
  .settings-row.clickable:hover { background:var(--cream); }
  .settings-icon { width:34px; height:34px; border-radius:10px; background:var(--cream); color:var(--pink-600); display:flex; align-items:center; justify-content:center; flex-shrink:0; }
  .settings-copy { min-width:0; flex:1; }
  .settings-label { display:block; font-size:13.5px; font-weight:650; }
  .settings-desc { display:block; margin-top:2px; font-size:11.5px; color:var(--muted); line-height:1.4; }
  .settings-chevron { color:var(--muted); font-size:18px; }
  .settings-value { color:var(--muted); font-size:12px; max-width:150px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .settings-choice-row { display:flex; gap:7px; padding:12px 14px; border-bottom:1px solid var(--border); }
  .settings-choice-row:last-child { border-bottom:0; }
  .settings-choice { flex:1; border:1px solid var(--border); background:var(--card); color:var(--muted); border-radius:10px; padding:9px 6px; font-size:12px; font-weight:650; }
  .settings-choice.active { border-color:var(--pink-600); background:var(--pink-100); color:var(--pink-600); }
  .settings-toggle { width:42px; height:24px; border:0; border-radius:14px; background:var(--border); padding:3px; position:relative; flex-shrink:0; }
  .settings-toggle::after { content:''; position:absolute; top:3px; left:3px; width:18px; height:18px; border-radius:50%; background:white; box-shadow:0 1px 3px rgba(0,0,0,.18); transition:transform .2s ease; }
  .settings-toggle.active { background:var(--pink-600); }
  .settings-toggle.active::after { transform:translateX(18px); }
  .settings-danger { color:#c6284d; }
  .settings-note { margin:8px 4px 0; font-size:11px; color:var(--muted); line-height:1.45; }
  body.settings-dark {
    --cream:#15161a; --card:#202126; --ink:#f4f1f3; --muted:#aaa5ab; --border:#35363d; --pink-100:#3b202b;
  }
  body.settings-dark .q-option, body.settings-dark .settings-choice { background:var(--card); color:var(--ink); }
  body.settings-dark .icon-btn, body.settings-dark .search-box { background:var(--card); }
  body.settings-dark .icon-btn#profile-settings-btn {
    background: rgba(255,255,255,.07);
    border-color: rgba(255,255,255,.10);
    color: #f2f2f5;
    box-shadow: 0 2px 8px rgba(0,0,0,.18);
  }
  body.settings-dark .icon-btn#profile-settings-btn:hover {
    background: rgba(255,255,255,.11);
    color: #ff8db7;
    border-color: rgba(255,255,255,.14);
  }
  body.settings-dark .settings-row.clickable:hover { background:#292a30; }
  /* ---------- Dark/system theme coverage ---------- */
  body.settings-dark {
    background: var(--cream);
    color: var(--ink);
  }
  body.settings-dark .main-content,
  body.settings-dark .content-area,
  body.settings-dark .profile-view,
  body.settings-dark .profile-form,
  body.settings-dark .side-card,
  body.settings-dark .swipe-card,
  body.settings-dark .empty-state,
  body.settings-dark .admirer-card,
  body.settings-dark .chat-panel,
  body.settings-dark .q-card,
  body.settings-dark .settings-card {
    background: var(--card);
    color: var(--ink);
  }
  body.settings-dark .q-option,
  body.settings-dark .filter-chip,
  body.settings-dark .filter-tabs button,
  body.settings-dark .filter-field input,
  body.settings-dark .filter-field select,
  body.settings-dark .filter-field textarea,
  body.settings-dark input,
  body.settings-dark textarea,
  body.settings-dark select,
  body.settings-dark .search-box,
  body.settings-dark .icon-btn {
    background: var(--card);
    color: var(--ink);
    border-color: var(--border);
  }
  body.settings-dark input::placeholder,
  body.settings-dark textarea::placeholder { color: var(--muted); }
  body.settings-dark .profile-label,
  body.settings-dark .field-label,
  body.settings-dark .form-label,
  body.settings-dark .section-title,
  body.settings-dark .card-title,
  body.settings-dark .profile-name,
  body.settings-dark .profile-meta,
  body.settings-dark .profile-bio,
  body.settings-dark .swipe-section-text,
  body.settings-dark .empty-state h3,
  body.settings-dark .empty-state p,
  body.settings-dark .chat-header,
  body.settings-dark .chat-input-row input,
  body.settings-dark .msg-item,
  body.settings-dark .match-item,
  body.settings-dark .vibes-slot {
    color: var(--ink);
  }
  body.settings-dark .muted,
  body.settings-dark .hint,
  body.settings-dark .subtext,
  body.settings-dark .profile-location,
  body.settings-dark .profile-detail,
  body.settings-dark .profile-field-value,
  body.settings-dark .filter-section-title,
  body.settings-dark .filter-field-label,
  body.settings-dark .settings-desc,
  body.settings-dark .settings-section-title,
  body.settings-dark .settings-note,
  body.settings-dark .settings-value {
    color: var(--muted);
  }
  body.settings-dark .nav-item:not(.active),
  body.settings-dark .nav-item:not(.active) span { color: #d8d3d7; }
  body.settings-dark .topbar h1,
  body.settings-dark .topbar,
  body.settings-dark .profile-header,
  body.settings-dark .filter-panel,
  body.settings-dark .settings-panel { color: var(--ink); }
  body.settings-dark .filter-panel,
  body.settings-dark .settings-panel { background: var(--card); }
  body.settings-dark .filter-panel-header,
  body.settings-dark .settings-header,
  body.settings-dark .filter-section,
  body.settings-dark .settings-row { border-color: var(--border); }
  body.settings-dark .filter-panel-close,
  body.settings-dark .settings-close,
  body.settings-dark .settings-icon { background: #292a30; color: var(--ink); }
  body.settings-dark .filter-tabs button.active { color: white; }
  body.settings-dark .settings-choice { color: var(--muted); }
  body.settings-dark .settings-choice.active { color: var(--pink-500); }
  body.settings-dark .settings-row.clickable:hover { background: #292a30; }
  body.settings-dark .msg-item[style*="background:white"],
  body.settings-dark .msg-item[style*="background: white"] { background: var(--card) !important; color: var(--ink) !important; }
  body.settings-dark .settings-danger { color: #ff7b9d; }

  @media (max-width: 600px) {
    .settings-panel { width:100vw; }
  }

</style>
</head>
<body>

<div id="auth-screen">
  <svg class="landing-couples" viewBox="0 0 1000 1000" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <symbol id="couple-icon" viewBox="0 0 100 120">
        <path d="M16,118 C16,72 24,42 38,42 C52,42 60,72 60,118 Z" fill="currentColor" opacity="0.92"/>
        <circle cx="38" cy="26" r="16" fill="currentColor" opacity="0.92"/>
        <path d="M40,118 C40,70 48,38 62,38 C76,38 84,70 84,118 Z" fill="currentColor" opacity="0.72"/>
        <circle cx="62" cy="22" r="16" fill="currentColor" opacity="0.72"/>
      </symbol>
    </defs>
    <use href="#couple-icon" x="700" y="30" width="260" height="310" style="color:#f4b8ca" opacity="0.55"/>
    <use href="#couple-icon" x="30" y="640" width="190" height="230" style="color:#e8926b" opacity="0.5"/>
    <use href="#couple-icon" x="230" y="700" width="170" height="200" style="color:#d63868" opacity="0.45"/>
    <use href="#couple-icon" x="770" y="400" width="210" height="250" style="color:#e0b48a" opacity="0.5"/>
    <use href="#couple-icon" x="790" y="680" width="190" height="230" style="color:#ec4c7e" opacity="0.45"/>
    <use href="#couple-icon" x="450" y="740" width="180" height="210" style="color:#f0b79a" opacity="0.4"/>
  </svg>

  <svg class="landing-map" viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
    <g fill="none" stroke="rgba(255,255,255,0.5)" stroke-width="1" stroke-dasharray="1 4">
      <path d="M50,150 Q200,80 350,140 T650,120"/>
      <path d="M100,200 Q300,220 500,160 T750,180"/>
    </g>
    <g fill="#ec4c7e">
      <circle cx="50" cy="150" r="3"/>
      <circle cx="350" cy="140" r="3"/>
      <circle cx="650" cy="120" r="3"/>
      <circle cx="100" cy="200" r="3"/>
      <circle cx="500" cy="160" r="3"/>
      <circle cx="750" cy="180" r="3"/>
    </g>
  </svg>

  <div class="landing-body">
    <div class="landing-left">
      <div class="landing-brand"><span class="logo-font">Swing</span> <span class="brand-heart"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></span></div>
      <div class="landing-kicker">MEET • MATCH • CONNECT</div>
      <h1 class="landing-headline">Meet someone worth <span>staying for.</span></h1>
      <p class="landing-sub">Swing helps you find real connections with people who get you.</p>
      <div class="landing-features">
        <div class="landing-feature"><div class="ico"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></div><div class="label">Meaningful Matches</div></div>
        <div class="landing-feature"><div class="ico"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 3l7 3v5.5c0 4.6-3 7.8-7 9.5-4-1.7-7-4.9-7-9.5V6l7-3Z"/></svg></div><div class="label">Safe &amp; Private</div></div>
        <div class="landing-feature"><div class="ico"><svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></div><div class="label">Built for real connections</div></div>
      </div>
    </div>

    <div class="auth-card">
      <span class="logo-font">swing</span>
      <div class="auth-sub">Meet someone worth staying for.</div>
      <div class="auth-tabs">
        <button id="tab-login" class="active" onclick="setAuthMode('login')">Log in</button>
        <button id="tab-register" onclick="setAuthMode('register')">Sign up</button>
      </div>
      <div id="auth-error" class="auth-error" style="display:none;"></div>
      <form id="auth-form">
        <input id="f-name" name="name" placeholder="Name" style="display:none;" />
        <input id="f-age" name="age" type="number" placeholder="Age" min="18" style="display:none;" />
        <select id="f-gender" name="gender" style="display:none;">
          <option value="">I am a...</option>
          <option value="man">Man</option>
          <option value="woman">Woman</option>
          <option value="other">Other</option>
        </select>
        <input id="f-country" name="country" placeholder="Country (e.g. Philippines)" style="display:none;" />
        <input id="f-location" name="location" placeholder="Location (e.g. Manila, Philippines)" style="display:none;" />
        <textarea id="f-bio" name="bio" placeholder="Short bio" style="display:none;"></textarea>
        <input id="f-tags" name="tags" placeholder="Interests, comma separated (e.g. Coffee, Hiking)" style="display:none;" />
        <input id="f-email" name="email" type="email" placeholder="Email" required />
        <input id="f-password" name="password" type="password" placeholder="Password" required />
        <button type="submit" class="auth-submit" id="auth-submit-btn">Log in</button>
      </form>
    </div>
  </div>

  <div class="landing-footer">
    <div>
      <div class="globe-line"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.7 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3Z"/></svg> Connect around <b>the world.</b></div>
      <div class="sub-line">No matter where you are, real connections are everywhere.</div>
    </div>
    <div class="join-badge"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> New here? Be one of the first to join.</div>
  </div>

</div>

<div id="questionnaire-screen">
  <div class="q-card">
    <div class="q-header">
      <div class="logo-font">swing</div>
      <div class="q-kicker"><svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> COMPATIBILITY QUESTIONNAIRE</div>
    </div>
    <div id="questionnaire-body"></div>
    <div class="q-actions">
      <button id="q-back-btn" onclick="goBackQuestion()">Back</button>
      <button id="q-next-btn" onclick="goNextQuestion()">Next</button>
    </div>
    <button class="q-skip" onclick="skipQuestionnaire()">Skip for now</button>
  </div>
</div>

<div id="details-screen">
  <div class="q-card" style="max-width:540px;">
    <div class="q-header">
      <div class="logo-font">swing</div>
      <div class="q-kicker"><svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> COMPLETE YOUR PROFILE</div>
    </div>
    <h3 class="q-title">A few more details</h3>
    <div class="q-hint">Optional — but profiles with more details get better matches</div>
    <div class="q-progress-bar"><div class="q-progress-fill" id="details-progress-fill" style="width:0%;"></div></div>

    <div class="details-body" id="details-form-body">

      <div class="filter-section">
        <p class="filter-section-title">LANGUAGES</p>
        <div class="filter-field">
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="languages" data-value="English">English</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Tagalog">Tagalog</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Spanish">Spanish</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Mandarin">Mandarin</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Japanese">Japanese</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Korean">Korean</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="French">French</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">PROFILE</p>
        <div class="filter-field">
          <label class="filter-field-label" for="d-education">Education</label>
          <select class="filter-select" id="d-education">
            <option value="">Prefer not to say</option>
            <option value="high_school">High school</option>
            <option value="undergrad">Undergrad</option>
            <option value="postgrad">Postgrad</option>
            <option value="phd">PhD</option>
          </select>
        </div>
        <div class="filter-field">
          <div class="filter-field-label">Height <span class="val" id="d-height-val">170 cm</span></div>
          <div class="single-range"><input type="range" id="d-height" min="140" max="210" value="170" oninput="onDetailsHeightInput()" /></div>
        </div>
        <div class="filter-field">
          <div class="filter-field-label">Exercise</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="exercise" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="exercise" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="exercise" data-value="often">Often</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">LIFESTYLE</p>
        <div class="filter-field">
          <div class="filter-field-label">Drinking</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="drinking" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="drinking" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="drinking" data-value="often">Often</button>
          </div>
        </div>
        <div class="filter-field">
          <div class="filter-field-label">Smoking</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="smoking" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="smoking" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="smoking" data-value="often">Often</button>
          </div>
        </div>
        <div class="filter-field">
          <label class="filter-field-label" for="d-religion">Religion</label>
          <select class="filter-select" id="d-religion">
            <option value="">Prefer not to say</option>
            <option value="christian">Christian</option>
            <option value="muslim">Muslim</option>
            <option value="hindu">Hindu</option>
            <option value="buddhist">Buddhist</option>
            <option value="jewish">Jewish</option>
            <option value="spiritual">Spiritual</option>
            <option value="agnostic">Agnostic</option>
            <option value="atheist">Atheist</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="filter-field">
          <label class="filter-field-label" for="d-political">Political views</label>
          <select class="filter-select" id="d-political">
            <option value="">Prefer not to say</option>
            <option value="liberal">Liberal</option>
            <option value="moderate">Moderate</option>
            <option value="conservative">Conservative</option>
            <option value="not_political">Not political</option>
            <option value="other">Other</option>
          </select>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">FAMILY</p>
        <div class="filter-field">
          <div class="filter-field-label">Children</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="children" data-value="has">Has children</button>
            <button type="button" class="filter-chip" data-group="children" data-value="none">Doesn't have children</button>
            <button type="button" class="filter-chip" data-group="children" data-value="unspecified">Prefer not to say</button>
          </div>
        </div>
        <div class="filter-field">
          <div class="filter-field-label">Wants children</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="wantsChildren" data-value="yes">Yes</button>
            <button type="button" class="filter-chip" data-group="wantsChildren" data-value="no">No</button>
            <button type="button" class="filter-chip" data-group="wantsChildren" data-value="maybe">Maybe</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">DATING</p>
        <div class="filter-field">
          <div class="filter-field-label">Dating intentions</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="casual">Casual</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="relationship">Relationship</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="marriage">Marriage</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="friendship">Friendship</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="not_sure">Not sure</button>
          </div>
        </div>
      </div>

    </div>

    <button id="details-save-btn" onclick="saveDetailsScreen()">Save & continue</button>
    <button class="q-skip" onclick="skipDetailsScreen()">Skip for now</button>
  </div>
</div>

<div id="dashboard">
  <aside class="sidebar">
    <div class="brand"><div class="logo-font">swing <span class="brand-heart"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></span></div></div>
    <div class="tagline">Meet someone worth<br/>staying for.</div>

    <button class="nav-item active" data-view="discover" onclick="switchView('discover')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v9a1 1 0 0 0 1 1H9a1 1 0 0 0 1-1v-4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v4a1 1 0 0 0 1 1h2.5a1 1 0 0 0 1-1v-9"/></svg></span> Discover</button>
    <button class="nav-item" data-view="matches" onclick="switchView('matches')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 11.5a8.4 8.4 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.4 8.4 0 0 1-3.8-.9L3 21l1.9-5.7a8.4 8.4 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6A8.4 8.4 0 0 1 12.5 3h.5a8.48 8.48 0 0 1 8 8v.5Z"/></svg></span> Matches <span class="badge" id="nav-matches-count" style="display:none;">0</span></button>
    <button class="nav-item" data-view="likes" onclick="switchView('likes')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 2.5 15 9l7 .9-5.1 4.8L18.2 21 12 17.4 5.8 21l1.3-6.3L2 9.9 9 9z"/></svg></span> Likes You <span class="badge" id="nav-likes-count">0</span></button>
    <button class="nav-item" data-view="ai" onclick="switchView('ai')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></span> Swing AI</button>
    <button class="nav-item" data-view="profile" onclick="switchView('profile')" aria-label="Profile"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="3.6"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/></svg></span> Profile</button>

    <div class="sidebar-spacer"></div>

    <div class="premium-card">
      <div class="title"><svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M3 8.5 7 11l5-7 5 7 4-2.5-1.6 10.5H4.6L3 8.5Z"/></svg> Go Premium</div>
      <div class="desc">Unlock all features</div>
    </div>
    <div class="me-row">
      <div class="me-avatar" id="me-avatar">?</div>
      <div>
        <div class="name" id="me-name">—</div>
        <button class="link" onclick="switchView('profile')">View my profile</button>
      </div>
    </div>
  </aside>

  <main class="main">
    <div class="topbar">
      <h1 id="view-title">Discover</h1>
      <div class="search-box"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M20 20l-4.8-4.8"/></svg> <input id="country-search" placeholder="Search by country..." style="border:none;outline:none;background:transparent;font-size:13.5px;width:100%;color:var(--ink);" /></div>
      <div class="top-actions">
        <button class="icon-btn filter-btn" id="filter-trigger-btn" onclick="openFilterPanel()" aria-label="Filters" title="Filters" aria-haspopup="dialog" aria-expanded="false">
          <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><line x1="4" y1="6" x2="20" y2="6"/><circle cx="9" cy="6" r="2.1" fill="white" stroke="currentColor"/><line x1="4" y1="12" x2="20" y2="12"/><circle cx="16" cy="12" r="2.1" fill="white" stroke="currentColor"/><line x1="4" y1="18" x2="20" y2="18"/><circle cx="11" cy="18" r="2.1" fill="white" stroke="currentColor"/></svg>
          <span class="dot" id="filter-badge" style="display:none;">0</span>
        </button>
        <button class="icon-btn" id="profile-settings-btn" onclick="openProfileSettings()" aria-label="Settings" title="Settings" style="display:none;">
          <span aria-hidden="true">⚙️</span>
        </button>
        <div class="top-avatar" id="top-avatar">?</div>
      </div>
    </div>

    <div class="content-grid">
      <div class="discover-col">

        <div class="view-panel visible" id="panel-discover">
          <div class="filter-tabs"><button class="active" type="button"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg> For You</button></div>
          <div id="swipe-card"></div>
          <div class="swipe-actions">
            <button class="act-pass" onclick="swipeAction('pass')" aria-label="Pass" title="Pass"><svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg></button>
            <button class="act-like" onclick="swipeAction('like')" aria-label="Like" title="Like"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></button>
          </div>
          <div class="swipe-hint" id="swipe-hint"></div>
        </div>

        <div class="view-panel" id="panel-matches">
          <div id="matches-full-list"></div>
        </div>

        <div class="view-panel" id="panel-chat">
          <div class="chat-panel">
            <div class="chat-header">
              <button class="back-btn" onclick="switchView('matches')" aria-label="Back to matches"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M19 12H5M11 6l-6 6 6 6"/></svg></button>
              <div class="msg-avatar" id="chat-avatar" style="width:36px;height:36px;font-size:12px;"></div>
              <div style="font-weight:600;" id="chat-name"></div>
            </div>
            <div id="chat-compat-panel"></div>
            <div class="chat-messages" id="chat-messages"></div>
            <div class="chat-input-row">
              <input id="chat-input" placeholder="Type a message..." />
              <button onclick="sendMessage()">Send</button>
            </div>
          </div>
        </div>

        <div class="view-panel" id="panel-likes">
          <div class="admirer-grid" id="admirer-grid"></div>
        </div>

        <div class="view-panel" id="panel-ai">
          <div class="chat-panel">
            <div class="chat-header">
              <button class="back-btn" onclick="switchView('discover')" aria-label="Back to discover"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M19 12H5M11 6l-6 6 6 6"/></svg></button>
              <div class="msg-avatar" style="width:36px;height:36px;font-size:16px;background:linear-gradient(135deg,var(--pink-500),var(--violet));"><svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></div>
              <div style="font-weight:600;">Swing AI</div>
            </div>
            <div class="chat-messages" id="ai-chat-messages"></div>
            <div class="chat-input-row">
              <button id="ai-mic-btn" onclick="toggleVoiceInput()" style="background:var(--cream);color:var(--pink-600);border:none;width:42px;border-radius:10px;font-size:16px;flex-shrink:0;" aria-label="Voice input" title="Voice input"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3"/></svg></button>
              <input id="ai-chat-input" placeholder="Tell Swing AI what you're looking for..." />
              <button onclick="sendAiMessage()">Send</button>
            </div>
          </div>
        </div>

        <div class="view-panel" id="panel-profile">

          <!-- ===== View mode ===== -->
          <div class="profile-view" id="profile-view-mode">
            <div class="profile-header-card">
              <div class="profile-photo-wrap">
                <div class="match-avatar" id="ph-photo-preview"></div>
                <button type="button" class="profile-photo-camera-btn" onclick="document.getElementById('p-photo-input').click()" aria-label="Change photo" title="Change photo">
                  <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 8h3l1.5-2h7L17 8h3a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1Z"/><circle cx="12" cy="13" r="3.4"/></svg>
                </button>
                <input type="file" id="p-photo-input" accept="image/png,image/jpeg,image/webp,image/gif" style="display:none;" onchange="handlePhotoSelect(event)" />
              </div>
              <div id="photo-upload-status" style="font-size:11.5px;color:var(--muted);margin-top:2px;"></div>

              <div class="profile-name-row">
                <h2 id="ph-name">—</h2>
                <span class="profile-verified-badge" id="ph-verified-badge" style="display:none;" title="Verified">
                  <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 12l5 5L20 6"/></svg>
                </span>
              </div>
              <div class="profile-meta-line" id="ph-meta">&nbsp;</div>
              <p class="profile-tagline" id="ph-tagline"></p>

              <button type="button" class="profile-edit-btn" onclick="enterProfileEditMode()">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                Edit Profile
              </button>
            </div>

            <div class="about-card">
              <div class="about-card-header" style="justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:9px;">
                  <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="3.4"/><path d="M4.8 20a7.2 7.2 0 0 1 14.4 0"/></svg></span>
                  <h3>About Me</h3>
                </div>
                <button type="button" class="about-card-edit-link" onclick="showDetailsScreen('profile')">Edit</button>
              </div>
              <p class="about-card-text" id="ph-bio-text">—</p>
              <div class="about-pills-grid" id="ph-about-pills"></div>
            </div>

            <div class="about-card">
              <div class="about-card-header">
                <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></span>
                <h3>Interests</h3>
              </div>
              <div class="interests-chips" id="ph-interests-chips"></div>
            </div>

            <div class="about-card">
              <div class="about-card-header" style="justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:9px;">
                  <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg></span>
                  <h3>I'm looking for</h3>
                </div>
                <button type="button" class="about-card-edit-link" onclick="showDetailsScreen('profile')">Edit</button>
              </div>
              <div class="about-pills-grid" id="ph-lookingfor-pills"></div>
            </div>

            <div class="about-card">
              <div class="about-card-header" style="justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:9px;">
                  <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="3" y="4" width="18" height="15" rx="2.5"/><circle cx="8.5" cy="9.5" r="1.6"/><path d="M21 15.5 15.5 11 6 19"/></svg></span>
                  <h3>My Vibes</h3>
                </div>
                <span class="vibes-counter" id="ph-vibes-counter">0/3 photos</span>
              </div>
              <div class="vibes-grid vibes-grid-view" id="ph-vibes-grid"></div>
            </div>

            <div class="about-card">
              <div class="about-card-header">
                <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></span>
                <h3>Prompts</h3>
              </div>
              <div id="ph-prompts-list"></div>
            </div>

            <div class="about-card">
              <button type="button" onclick="showQuestionnaire('profile')" style="background:var(--cream);color:var(--ink);border:1px solid var(--border);width:100%;padding:11px;border-radius:10px;font-weight:600;font-size:13.5px;"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> Compatibility Quiz</button>
            </div>
          </div>

          <!-- ===== Edit mode ===== -->
          <div class="profile-form" id="profile-edit-mode" style="display:none;">
            <div class="profile-edit-header">
              <button type="button" class="profile-edit-back-btn" onclick="exitProfileEditMode()" aria-label="Back" title="Back">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M15 5l-7 7 7 7"/></svg>
              </button>
              <h3>Edit Profile</h3>
            </div>
            <label>Name</label><input id="p-name" />
            <label>Age</label><input id="p-age" type="number" min="18" />
            <label>Gender</label>
            <select id="p-gender">
              <option value="man">Man</option>
              <option value="woman">Woman</option>
              <option value="other">Other</option>
            </select>
            <label>Country</label><input id="p-country" />
            <label>Location</label><input id="p-location" />
            <label>Bio</label><textarea id="p-bio"></textarea>
            <label>Interests (comma separated)</label><input id="p-tags" />

            <div class="edit-vibes-section">
              <div class="about-card-header" style="justify-content:space-between;margin-bottom:10px;">
                <span style="font-size:12.5px;font-weight:600;color:var(--muted);">My Vibes</span>
                <span class="vibes-counter" id="vibes-counter">0/3 photos</span>
              </div>
              <div class="vibes-grid" id="vibes-grid"></div>
              <div class="vibes-status" id="vibes-status"></div>
              <input type="file" id="vibes-photo-input" accept="image/png,image/jpeg,image/webp,image/gif" style="display:none;" onchange="handleVibesPhotoSelect(event)" />
            </div>

            <div class="edit-prompts-section">
              <div class="about-card-header" style="justify-content:space-between;margin-bottom:10px;">
                <span style="font-size:12.5px;font-weight:600;color:var(--muted);">Prompts</span>
                <span class="vibes-counter" id="prompts-counter">0/3 answered</span>
              </div>
              <div id="prompts-edit-rows"></div>
              <button type="button" onclick="savePrompts()" style="background:var(--cream);color:var(--ink);border:1px solid var(--border);width:100%;padding:10px;border-radius:10px;font-weight:600;font-size:13px;margin-top:4px;">Save prompts</button>
              <div class="vibes-status" id="prompts-status"></div>
            </div>

            <button onclick="saveProfile()">Save changes</button>
            <span class="save-note" id="save-note" style="display:none;">Saved!</span>
          </div>
        </div>

      </div>


      <div class="side-col">
        <div class="side-card">
          <div class="side-head"><h3>Matches</h3><button type="button" class="text-link" onclick="switchView('matches')">See all</button></div>
          <div class="match-avatars" id="matches-list"></div>
        </div>
        <div class="side-card">
          <div class="side-head"><h3>Messages</h3><button type="button" class="text-link" onclick="switchView('matches')">See all</button></div>
          <div id="messages-list"></div>
        </div>
        <div class="promo-card">
          <h4>Get more with Swing Premium</h4>
          <p>Unlimited likes, see who likes you, boost profile & more!</p>
          <button type="button" onclick="alert('Swing Premium is launching soon — thanks for your interest!')"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M3 8.5 7 11l5-7 5 7 4-2.5-1.6 10.5H4.6L3 8.5Z"/></svg> Upgrade Now</button>
        </div>
      </div>
    </div>

    <div class="app-footer">
      <div>© 2026 Swing</div>
      <div class="links"><a href="#">About</a><a href="#">Safety</a><a href="#">Help</a><a href="#">Privacy</a><a href="#">Terms</a></div>
    </div>
  </main>

  <nav class="mobile-nav" aria-label="Primary">
    <button class="mobile-nav-item active" data-view="discover" onclick="switchView('discover')" aria-label="Discover" aria-current="page">
      <span class="icon">
        <svg class="icon-outline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v9a1 1 0 0 0 1 1H9a1 1 0 0 0 1-1v-4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v4a1 1 0 0 0 1 1h2.5a1 1 0 0 0 1-1v-9"/></svg>
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><path d="M12 3.2 3 11.2v1.3h2.2V20a1 1 0 0 0 1 1H10v-6.2h4V21h3.8a1 1 0 0 0 1-1v-7.5H21v-1.3z"/></svg>
      </span>
      <span class="nav-dot"></span>
    </button>
    <button class="mobile-nav-item" data-view="matches" onclick="switchView('matches')" aria-label="Messages">
      <span class="icon">
        <svg class="icon-outline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 11.5a8.4 8.4 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.4 8.4 0 0 1-3.8-.9L3 21l1.9-5.7a8.4 8.4 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6A8.4 8.4 0 0 1 12.5 3h.5a8.48 8.48 0 0 1 8 8v.5Z"/></svg>
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><path d="M12.5 2.5h-.5A9 9 0 0 0 3 11.5a8.9 8.9 0 0 0 .9 4L2 21.5l6.2-1.8a8.9 8.9 0 0 0 3.8.9 9 9 0 0 0 9-9v-.5a9 9 0 0 0-8.5-8.6z"/></svg>
      </span>
      <span class="nav-dot"></span>
      <span class="mnav-badge" id="mnav-messages-count" style="display:none;"></span>
    </button>
    <button class="mobile-nav-item mobile-nav-fab" data-view="ai" onclick="switchView('ai')" aria-label="Swing AI">
      <span class="icon">
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg>
      </span>
    </button>
    <button class="mobile-nav-item" data-view="likes" onclick="switchView('likes')" aria-label="Likes you">
      <span class="icon">
        <svg class="icon-outline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 2.5 15 9l7 .9-5.1 4.8L18.2 21 12 17.4 5.8 21l1.3-6.3L2 9.9 9 9z"/></svg>
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><path d="M12 2.5 15 9l7 .9-5.1 4.8L18.2 21 12 17.4 5.8 21l1.3-6.3L2 9.9 9 9z"/></svg>
      </span>
      <span class="nav-dot"></span>
      <span class="mnav-badge" id="mnav-likes-count" style="display:none;"></span>
    </button>
    <button class="mobile-nav-item" data-view="profile" onclick="switchView('profile')" aria-label="Profile">
      <span class="icon">
        <svg class="icon-outline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="3.6"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/></svg>
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><circle cx="12" cy="7.8" r="4"/><path d="M3.8 20.6c.7-4.4 4-7.1 8.2-7.1s7.5 2.7 8.2 7.1a1 1 0 0 1-1 1.2H4.8a1 1 0 0 1-1-1.2z"/></svg>
      </span>
      <span class="nav-dot"></span>
    </button>
  </nav>

  <div class="filter-overlay" id="filter-overlay" onclick="closeFilterPanel()"></div>
  <div class="settings-overlay" id="settings-overlay" onclick="closeProfileSettings()"></div>
  <aside class="settings-panel" id="settings-panel" role="dialog" aria-modal="true" aria-labelledby="settings-panel-title" aria-hidden="true">
    <div class="settings-header">
      <h2 id="settings-panel-title">Settings</h2>
      <button class="settings-close" onclick="closeProfileSettings()" aria-label="Close settings">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="settings-body">
      <div class="settings-section">
        <p class="settings-section-title">ACCOUNT</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="closeProfileSettings(); enterProfileEditMode();">
            <span class="settings-icon">✎</span><span class="settings-copy"><span class="settings-label">Edit profile</span><span class="settings-desc">Update your bio, interests, lifestyle and dating intentions.</span></span><span class="settings-chevron">›</span>
          </button>
          <div class="settings-row">
            <span class="settings-icon">@</span><span class="settings-copy"><span class="settings-label">Email</span><span class="settings-desc">Your sign-in email</span></span><span class="settings-value" id="settings-email">—</span>
          </div>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">DISCOVERY</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="closeProfileSettings(); openFilterPanel();">
            <span class="settings-icon">⌘</span><span class="settings-copy"><span class="settings-label">Discovery filters</span><span class="settings-desc">Control who appears in Discover. These are also used by Swing AI when supported.</span></span><span class="settings-chevron">›</span>
          </button>
          <button class="settings-row clickable" type="button" onclick="resetFiltersFromSettings()">
            <span class="settings-icon">↺</span><span class="settings-copy"><span class="settings-label">Reset filters</span><span class="settings-desc">Return Discover preferences to their defaults.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">APPEARANCE</p>
        <div class="settings-card">
          <div class="settings-row">
            <span class="settings-icon">◐</span><span class="settings-copy"><span class="settings-label">Theme</span><span class="settings-desc">Choose how Swing looks on this device.</span></span>
          </div>
          <div class="settings-choice-row">
            <button type="button" class="settings-choice" data-theme-choice="system" onclick="setSwingTheme('system')">System</button>
            <button type="button" class="settings-choice" data-theme-choice="light" onclick="setSwingTheme('light')">Light</button>
            <button type="button" class="settings-choice" data-theme-choice="dark" onclick="setSwingTheme('dark')">Dark</button>
          </div>
          <button class="settings-row clickable" type="button" onclick="toggleReducedMotion()">
            <span class="settings-icon">≈</span><span class="settings-copy"><span class="settings-label">Reduce motion</span><span class="settings-desc">Minimize animations and transitions.</span></span><span class="settings-toggle" id="settings-motion-toggle" aria-hidden="true"></span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">SESSION</p>
        <div class="settings-card">
          <button class="settings-row clickable settings-danger" type="button" onclick="logoutFromSettings()">
            <span class="settings-icon">⇥</span><span class="settings-copy"><span class="settings-label">Log out</span><span class="settings-desc">Sign out of Swing on this device.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>
      <p class="settings-note">Settings marked for this device are stored locally in your browser. Account and profile data remain managed by your Swing account.</p>
    </div>
  </aside>

  <div class="filter-panel" id="filter-panel" role="dialog" aria-modal="true" aria-labelledby="filter-panel-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="filter-panel-title">Filters</h2>
      <button class="filter-panel-close" onclick="closeFilterPanel()" aria-label="Close filters"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg></button>
    </div>

    <div class="filter-panel-body">

      <div class="filter-section">
        <p class="filter-section-title">BASIC</p>

        <div class="filter-field">
          <div class="filter-field-label">Show me</div>
          <div class="filter-chips" id="f-showme-chips">
            <button type="button" class="filter-chip" data-group="showMe" data-value="men">Men</button>
            <button type="button" class="filter-chip" data-group="showMe" data-value="women">Women</button>
            <button type="button" class="filter-chip" data-group="showMe" data-value="nonbinary">Non-binary</button>
            <button type="button" class="filter-chip" data-group="showMe" data-value="everyone">Everyone</button>
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Age <span class="val" id="f-age-val">18 – 60</span></div>
          <div class="dual-range">
            <div class="track"></div>
            <div class="fill" id="f-age-fill"></div>
            <input type="range" id="f-age-min" min="18" max="80" value="18" oninput="onDualRangeInput('age', this)" />
            <input type="range" id="f-age-max" min="18" max="80" value="60" oninput="onDualRangeInput('age', this)" />
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Distance <span class="val" id="f-distance-val">Up to 100 km</span></div>
          <div class="single-range">
            <input type="range" id="f-distance" min="1" max="500" value="100" oninput="onSingleRangeInput('distance')" />
          </div>
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-country">Country</label>
          <input class="filter-input" id="f-country" type="text" placeholder="e.g. Philippines" />
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-city">City</label>
          <input class="filter-input" id="f-city" type="text" placeholder="e.g. Manila" />
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Languages</div>
          <div class="filter-chips" id="f-languages-chips">
            <button type="button" class="filter-chip" data-group="languages" data-value="English">English</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Tagalog">Tagalog</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Spanish">Spanish</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Mandarin">Mandarin</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Japanese">Japanese</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Korean">Korean</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="French">French</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">PROFILE</p>

        <div class="filter-field filter-toggle-row">
          <label class="filter-field-label" for="f-verified">Verified profiles</label>
          <button type="button" class="filter-switch" id="f-verified" onclick="toggleSwitch('verified')"></button>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Interests</div>
          <div class="filter-chips" id="f-interests-chips">
            <button type="button" class="filter-chip" data-group="interests" data-value="travel">Travel</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="music">Music</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="fitness">Fitness</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="foodie">Foodie</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="movies">Movies</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="gaming">Gaming</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="art">Art</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="pets">Pets</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="reading">Reading</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="outdoors">Outdoors</button>
          </div>
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-education">Education</label>
          <select class="filter-select" id="f-education">
            <option value="">Any</option>
            <option value="high_school">High school</option>
            <option value="undergrad">Undergrad</option>
            <option value="postgrad">Postgrad</option>
            <option value="phd">PhD</option>
          </select>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Height (cm) <span class="val" id="f-height-val">140 – 210</span></div>
          <div class="dual-range">
            <div class="track"></div>
            <div class="fill" id="f-height-fill"></div>
            <input type="range" id="f-height-min" min="140" max="210" value="140" oninput="onDualRangeInput('height', this)" />
            <input type="range" id="f-height-max" min="140" max="210" value="210" oninput="onDualRangeInput('height', this)" />
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Exercise</div>
          <div class="filter-chips" id="f-exercise-chips">
            <button type="button" class="filter-chip" data-group="exercise" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="exercise" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="exercise" data-value="often">Often</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">LIFESTYLE</p>

        <div class="filter-field">
          <div class="filter-field-label">Drinking</div>
          <div class="filter-chips" id="f-drinking-chips">
            <button type="button" class="filter-chip" data-group="drinking" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="drinking" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="drinking" data-value="often">Often</button>
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Smoking</div>
          <div class="filter-chips" id="f-smoking-chips">
            <button type="button" class="filter-chip" data-group="smoking" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="smoking" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="smoking" data-value="often">Often</button>
          </div>
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-religion">Religion</label>
          <select class="filter-select" id="f-religion">
            <option value="">Any</option>
            <option value="christian">Christian</option>
            <option value="muslim">Muslim</option>
            <option value="hindu">Hindu</option>
            <option value="buddhist">Buddhist</option>
            <option value="jewish">Jewish</option>
            <option value="spiritual">Spiritual</option>
            <option value="agnostic">Agnostic</option>
            <option value="atheist">Atheist</option>
            <option value="other">Other</option>
          </select>
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-political">Political views</label>
          <select class="filter-select" id="f-political">
            <option value="">Any</option>
            <option value="liberal">Liberal</option>
            <option value="moderate">Moderate</option>
            <option value="conservative">Conservative</option>
            <option value="not_political">Not political</option>
            <option value="other">Other</option>
          </select>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">FAMILY</p>

        <div class="filter-field">
          <div class="filter-field-label">Children</div>
          <div class="filter-chips" id="f-children-chips">
            <button type="button" class="filter-chip" data-group="children" data-value="has">Has children</button>
            <button type="button" class="filter-chip" data-group="children" data-value="none">Doesn't have children</button>
            <button type="button" class="filter-chip" data-group="children" data-value="unspecified">Prefer not to say</button>
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Wants children</div>
          <div class="filter-chips" id="f-wantschildren-chips">
            <button type="button" class="filter-chip" data-group="wantsChildren" data-value="yes">Yes</button>
            <button type="button" class="filter-chip" data-group="wantsChildren" data-value="no">No</button>
            <button type="button" class="filter-chip" data-group="wantsChildren" data-value="maybe">Maybe</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">DATING</p>

        <div class="filter-field">
          <div class="filter-field-label">Dating intentions</div>
          <div class="filter-chips" id="f-intentions-chips">
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="casual">Casual</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="relationship">Relationship</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="marriage">Marriage</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="friendship">Friendship</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="not_sure">Not sure</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">ACTIVITY</p>

        <div class="filter-field filter-toggle-row">
          <label class="filter-field-label" for="f-online">Online now</label>
          <button type="button" class="filter-switch" id="f-online" onclick="toggleSwitch('onlineNow')"></button>
        </div>

        <div class="filter-field filter-toggle-row">
          <label class="filter-field-label" for="f-new">New here</label>
          <button type="button" class="filter-switch" id="f-new" onclick="toggleSwitch('newHere')"></button>
        </div>
      </div>

    </div>

    <div class="filter-panel-footer">
      <button type="button" class="filter-reset-btn" onclick="resetFilters()">Reset all</button>
      <button type="button" class="filter-apply-btn" onclick="applyFiltersAndClose()">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20 6 9 17l-5-5"/></svg>
        Apply filters
      </button>
    </div>
  </div>
</div>

<script>
const PALETTE = ['#ec4c7e','#8b5cf6','#e3a13f','#3fa5e3','#4caf7a','#d63868'];
function colorFor(name) { let h=0; for (const c of (name||'?')) h = (h*31 + c.charCodeAt(0)) % PALETTE.length; return PALETTE[h]; }
function initials(name) { return (name || '?').trim().charAt(0).toUpperCase(); }
function avatarStyleAttr(u) {
  if (u && u.photoUrl) return \`background-image:url('\${u.photoUrl}');background-size:cover;background-position:center;color:transparent;\`;
  return \`background:\${colorFor(u && u.name)};\`;
}
function avatarInitials(u) {
  return (u && u.photoUrl) ? '' : initials(u && u.name);
}
function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'now';
  if (mins < 60) return mins + 'm';
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h';
  return Math.floor(hrs / 24) + 'd';
}

// ---------- Discover filters ----------
// NOTE: the profile schema (see toPublicUser on the server) currently only
// stores name/age/bio/location/country/gender/tags/photoUrl/createdAt.
// Filters below that map to a real field (showMe, age, country, city,
// interests, newHere) actually narrow the candidate pool. Filters with no
// backing field yet (distance, languages, verified, education, height,
// exercise, drinking, smoking, religion, political, children,
// wantsChildren, datingIntentions, onlineNow) are fully wired up in the UI
// and persist/count as "active", but matchesFilters() intentionally treats
// them as pass-through until those fields exist on the user profile —
// see the single spot to extend once the schema grows.
const FILTER_DEFAULTS = {
  showMe: 'everyone',
  ageMin: 18, ageMax: 60,
  distance: 100,
  country: '', city: '',
  languages: [],
  verified: false,
  interests: [],
  education: '',
  heightMin: 140, heightMax: 210,
  exercise: '',
  drinking: '', smoking: '', religion: '', political: '',
  children: '', wantsChildren: '',
  datingIntentions: [],
  onlineNow: false, newHere: false,
};
const CHIP_GROUPS = {
  showMe: 'single', languages: 'multi', interests: 'multi', exercise: 'single',
  drinking: 'single', smoking: 'single', children: 'single', wantsChildren: 'single',
  datingIntentions: 'multi',
};
function loadStoredFilters() {
  try {
    const saved = JSON.parse(localStorage.getItem('swing_filters') || 'null');
    if (saved && typeof saved === 'object') return Object.assign(JSON.parse(JSON.stringify(FILTER_DEFAULTS)), saved);
  } catch (e) { /* ignore corrupt storage */ }
  return JSON.parse(JSON.stringify(FILTER_DEFAULTS));
}

let state = {
  token: localStorage.getItem('swing_token') || null,
  user: null,
  candidates: [],
  allCandidates: [],
  filters: loadStoredFilters(),
  details: defaultDetails(),
  detailsOrigin: null,
  matches: [],
  admirers: [],
  activeChat: null,
  eventSource: null,
  aiChatHistory: [],
  aiVoiceRecognition: null,
  aiVoiceListening: false,
};

async function api(pathName, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
  const res = await fetch(pathName, { ...options, headers, cache: 'no-store' });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// ---------- Auth ----------
let authMode = 'login';
function setAuthMode(mode) {
  authMode = mode;
  document.getElementById('tab-login').classList.toggle('active', mode === 'login');
  document.getElementById('tab-register').classList.toggle('active', mode === 'register');
  ['f-name','f-age','f-gender','f-country','f-location','f-bio','f-tags'].forEach(id => {
    document.getElementById(id).style.display = mode === 'register' ? 'block' : 'none';
  });
  document.getElementById('f-gender').required = mode === 'register';
  document.getElementById('auth-submit-btn').textContent = mode === 'register' ? 'Sign up' : 'Log in';
  document.getElementById('auth-error').style.display = 'none';
}

function showError(msg) {
  const el = document.getElementById('auth-error');
  el.textContent = msg;
  el.style.display = 'block';
}

document.getElementById('auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('f-email').value;
  const password = document.getElementById('f-password').value;

  try {
    let data;
    let justRegistered = false;
    if (authMode === 'register') {
      const name = document.getElementById('f-name').value;
      const age = document.getElementById('f-age').value;
      const gender = document.getElementById('f-gender').value;
      const country = document.getElementById('f-country').value;
      const location = document.getElementById('f-location').value;
      const bio = document.getElementById('f-bio').value;
      const tags = document.getElementById('f-tags').value;
      if (!gender) { return showError('Please select a gender.'); }
      data = await api('/api/register', { method: 'POST', body: JSON.stringify({ name, email, password, age, gender, country, location, bio, tags }) });
      justRegistered = true;
    } else {
      data = await api('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
    }
    localStorage.setItem('swing_token', data.token);
    state.token = data.token;
    state.user = data.user;
    if (justRegistered) {
      document.getElementById('auth-screen').style.display = 'none';
      await showQuestionnaire('signup');
    } else {
      await enterDashboard();
    }
  } catch (err) {
    showError(err.message);
  }
});

async function logout() {
  if (state.eventSource) state.eventSource.close();
  if (state.aiVoiceRecognition) state.aiVoiceRecognition.stop();
  document.body.classList.remove('chat-open');
  try { await api('/api/logout', { method: 'POST' }); } catch (e) { /* best-effort */ }
  localStorage.removeItem('swing_token');
  state = { token: null, user: null, candidates: [], matches: [], admirers: [], activeChat: null, eventSource: null, aiChatHistory: [], aiVoiceRecognition: null, aiVoiceListening: false };
  document.getElementById('dashboard').classList.remove('visible');
  document.getElementById('auth-screen').style.display = 'flex';
}

// ---------- Dashboard ----------

function updateMeAvatars() {
  document.getElementById('me-name').textContent = state.user.name;
  const meAv = document.getElementById('me-avatar');
  meAv.textContent = avatarInitials(state.user);
  meAv.setAttribute('style', avatarStyleAttr(state.user));
  const topAv = document.getElementById('top-avatar');
  topAv.textContent = avatarInitials(state.user);
  topAv.setAttribute('style', avatarStyleAttr(state.user));
}

async function enterDashboard() {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('dashboard').classList.add('visible');
  updateMeAvatars();

  await Promise.all([loadDiscover(), loadMatches(), loadAdmirers()]);
  switchView('discover');

  connectLiveUpdates();
}

function connectLiveUpdates() {
  if (state.eventSource) state.eventSource.close();

  const es = new EventSource('/api/stream?token=' + encodeURIComponent(state.token));
  state.eventSource = es;

  es.addEventListener('message', (e) => {
    const msg = JSON.parse(e.data);
    if (state.activeChat === msg.matchKey) {
      loadChatMessages(msg.matchKey);
    } else {
      loadMatches();
    }
  });

  es.addEventListener('match', () => {
    loadMatches();
  });

  // If the connection drops, the browser retries automatically — but as an
  // extra safety net, refresh matches/messages the moment we reconnect in
  // case anything was missed while disconnected.
  es.addEventListener('open', () => {
    loadMatches();
  });
}

// Cached once instead of re-querying the DOM on every single nav click —
// on slower environments (notably in-app browsers like Instagram/WhatsApp's
// WebView) repeated full-document querySelectorAll calls are a real source
// of perceptible tap lag.
let _viewPanels = null;
let _navItems = null;
let _mobileNavItems = null;

function switchView(view) {
  if (!_viewPanels) _viewPanels = document.querySelectorAll('.view-panel');
  if (!_navItems) _navItems = document.querySelectorAll('.nav-item');
  if (!_mobileNavItems) _mobileNavItems = document.querySelectorAll('.mobile-nav-item');

  state.activeChat = null;
  document.body.classList.remove('chat-open');
  _viewPanels.forEach(p => p.classList.remove('visible'));
  _navItems.forEach(n => n.classList.toggle('active', n.dataset.view === view));
  _mobileNavItems.forEach(n => {
    const isActive = n.dataset.view === view;
    n.classList.toggle('active', isActive);
    if (n.classList.contains('mobile-nav-fab')) return;
    if (isActive) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
  });
  const titles = { discover: 'Discover', matches: 'Messages', likes: 'Likes You', ai: 'Swing AI', profile: 'My Profile' };
  document.getElementById('view-title').textContent = titles[view] || 'Discover';

  // On the Profile tab there's nothing to search or filter, so swap the
  // country search box and filter button out for a settings button instead.
  const isProfile = view === 'profile';
  document.querySelector('.search-box').style.display = isProfile ? 'none' : '';
  document.getElementById('filter-trigger-btn').style.display = isProfile ? 'none' : '';
  document.getElementById('profile-settings-btn').style.display = isProfile ? '' : 'none';

  if (view === 'discover') { document.getElementById('panel-discover').classList.add('visible'); renderSwipeCard(); }
  else if (view === 'matches') { document.getElementById('panel-matches').classList.add('visible'); renderMatchesFull(); }
  else if (view === 'likes') { document.getElementById('panel-likes').classList.add('visible'); renderAdmirers(); }
  else if (view === 'ai') { document.getElementById('panel-ai').classList.add('visible'); renderAiChat(); document.body.classList.add('chat-open'); }
  else if (view === 'profile') { document.getElementById('panel-profile').classList.add('visible'); fillProfileForm(); }
}

// ---------- Discover ----------

async function loadDiscover(country) {
  const q = country !== undefined ? country : (document.getElementById('country-search').value || '');
  const url = '/api/discover' + (q.trim() ? '?country=' + encodeURIComponent(q.trim()) : '');
  const data = await api(url);
  state.allCandidates = data.candidates;
  state.candidates = state.allCandidates.filter(c => matchesFilters(c, state.filters));
}

// Fields that now have a real column on the user profile (filled in via
// the post-signup "complete your profile" screen or the Profile tab) are
// checked here for real. verified/onlineNow/distance still have no backing
// data (verified needs an admin flag, onlineNow needs presence tracking,
// distance needs geolocation) so they remain pass-through until those exist.
function matchesFilters(c, f) {
  if (f.showMe && f.showMe !== 'everyone') {
    const wanted = { men: 'man', women: 'woman', nonbinary: 'other' }[f.showMe];
    if (wanted && c.gender !== wanted) return false;
  }
  if (typeof c.age === 'number') {
    if (c.age < f.ageMin || c.age > f.ageMax) return false;
  }
  if (f.country && f.country.trim()) {
    if (!(c.country || '').toLowerCase().includes(f.country.trim().toLowerCase())) return false;
  }
  if (f.city && f.city.trim()) {
    if (!(c.location || '').toLowerCase().includes(f.city.trim().toLowerCase())) return false;
  }
  if (f.interests && f.interests.length) {
    const tags = (c.tags || []).map(t => String(t).toLowerCase());
    if (!f.interests.some(i => tags.includes(i.toLowerCase()))) return false;
  }
  if (f.languages && f.languages.length) {
    const langs = (c.languages || []).map(l => String(l).toLowerCase());
    if (!f.languages.some(l => langs.includes(l.toLowerCase()))) return false;
  }
  if (f.education && c.education && f.education !== c.education) return false;
  if (typeof c.heightCm === 'number') {
    if (c.heightCm < f.heightMin || c.heightCm > f.heightMax) return false;
  }
  if (f.exercise && c.exercise && f.exercise !== c.exercise) return false;
  if (f.drinking && c.drinking && f.drinking !== c.drinking) return false;
  if (f.smoking && c.smoking && f.smoking !== c.smoking) return false;
  if (f.religion && c.religion && f.religion !== c.religion) return false;
  if (f.political && c.political && f.political !== c.political) return false;
  if (f.children && c.children && f.children !== c.children) return false;
  if (f.wantsChildren && c.wantsChildren && f.wantsChildren !== c.wantsChildren) return false;
  if (f.datingIntentions && f.datingIntentions.length) {
    const theirs = c.datingIntentions || [];
    if (theirs.length && !f.datingIntentions.some(i => theirs.includes(i))) return false;
  }
  if (f.newHere) {
    if (!c.createdAt) return false;
    const days = (Date.now() - new Date(c.createdAt).getTime()) / 86400000;
    if (days > 30) return false;
  }
  return true;
}

function countActiveFilters(f) {
  let n = 0;
  if (f.showMe !== FILTER_DEFAULTS.showMe) n++;
  if (f.ageMin !== FILTER_DEFAULTS.ageMin || f.ageMax !== FILTER_DEFAULTS.ageMax) n++;
  if (f.distance !== FILTER_DEFAULTS.distance) n++;
  if (f.country.trim()) n++;
  if (f.city.trim()) n++;
  if (f.languages.length) n++;
  if (f.verified) n++;
  if (f.interests.length) n++;
  if (f.education) n++;
  if (f.heightMin !== FILTER_DEFAULTS.heightMin || f.heightMax !== FILTER_DEFAULTS.heightMax) n++;
  if (f.exercise) n++;
  if (f.drinking) n++;
  if (f.smoking) n++;
  if (f.religion) n++;
  if (f.political) n++;
  if (f.children) n++;
  if (f.wantsChildren) n++;
  if (f.datingIntentions.length) n++;
  if (f.onlineNow) n++;
  if (f.newHere) n++;
  return n;
}

function updateFilterBadge() {
  const n = countActiveFilters(state.filters);
  const badge = document.getElementById('filter-badge');
  const btn = document.getElementById('filter-trigger-btn');
  if (n > 0) { badge.textContent = n; badge.style.display = 'flex'; btn.classList.add('has-active'); }
  else { badge.style.display = 'none'; btn.classList.remove('has-active'); }
}

function syncChipSelectedStatesIn(container, target) {
  container.querySelectorAll('.filter-chip').forEach(chip => {
    const group = chip.dataset.group, val = chip.dataset.value;
    const mode = CHIP_GROUPS[group];
    const current = target[group];
    const active = mode === 'multi' ? current.includes(val) : current === val;
    chip.classList.toggle('selected', active);
  });
}
function syncChipSelectedStates() {
  syncChipSelectedStatesIn(document.getElementById('filter-panel'), state.filters);
}
function attachChipDelegation(container, getTarget, onChange) {
  if (!container) return;
  container.addEventListener('click', (e) => {
    const chip = e.target.closest('.filter-chip');
    if (!chip) return;
    const group = chip.dataset.group;
    const val = chip.dataset.value;
    const mode = CHIP_GROUPS[group];
    const target = getTarget();
    if (mode === 'multi') {
      const arr = target[group];
      const idx = arr.indexOf(val);
      if (idx > -1) arr.splice(idx, 1); else arr.push(val);
    } else {
      target[group] = (target[group] === val) ? (group === 'showMe' ? 'everyone' : '') : val;
    }
    syncChipSelectedStatesIn(container, target);
    if (onChange) onChange();
  });
}

function refreshDualRangeVisual(key) {
  const minEl = document.getElementById('f-' + key + '-min');
  const maxEl = document.getElementById('f-' + key + '-max');
  const lo = parseInt(minEl.min, 10), hi = parseInt(minEl.max, 10);
  const minV = parseInt(minEl.value, 10), maxV = parseInt(maxEl.value, 10);
  const pctMin = ((minV - lo) / (hi - lo)) * 100;
  const pctMax = ((maxV - lo) / (hi - lo)) * 100;
  document.getElementById('f-' + key + '-fill').style.left = pctMin + '%';
  document.getElementById('f-' + key + '-fill').style.width = Math.max(0, pctMax - pctMin) + '%';
  document.getElementById('f-' + key + '-val').textContent = minV + ' – ' + maxV;
}

function onDualRangeInput(key, changedEl) {
  const minEl = document.getElementById('f-' + key + '-min');
  const maxEl = document.getElementById('f-' + key + '-max');
  let minV = parseInt(minEl.value, 10), maxV = parseInt(maxEl.value, 10);
  if (minV > maxV) {
    if (changedEl === minEl) { maxV = minV; maxEl.value = maxV; }
    else { minV = maxV; minEl.value = minV; }
  }
  refreshDualRangeVisual(key);
  if (key === 'age') { state.filters.ageMin = minV; state.filters.ageMax = maxV; }
  if (key === 'height') { state.filters.heightMin = minV; state.filters.heightMax = maxV; }
}

function onSingleRangeInput(key) {
  const el = document.getElementById('f-' + key);
  const v = parseInt(el.value, 10);
  state.filters[key] = v;
  if (key === 'distance') document.getElementById('f-distance-val').textContent = 'Up to ' + v + ' km';
}

function toggleSwitch(key) {
  state.filters[key] = !state.filters[key];
  const idMap = { verified: 'f-verified', onlineNow: 'f-online', newHere: 'f-new' };
  document.getElementById(idMap[key]).classList.toggle('on', state.filters[key]);
}

function syncFilterControlsFromState() {
  const f = state.filters;
  syncChipSelectedStates();

  document.getElementById('f-age-min').value = f.ageMin;
  document.getElementById('f-age-max').value = f.ageMax;
  refreshDualRangeVisual('age');

  document.getElementById('f-height-min').value = f.heightMin;
  document.getElementById('f-height-max').value = f.heightMax;
  refreshDualRangeVisual('height');

  document.getElementById('f-distance').value = f.distance;
  document.getElementById('f-distance-val').textContent = 'Up to ' + f.distance + ' km';

  document.getElementById('f-country').value = f.country;
  document.getElementById('f-city').value = f.city;
  document.getElementById('f-education').value = f.education;
  document.getElementById('f-religion').value = f.religion;
  document.getElementById('f-political').value = f.political;

  document.getElementById('f-verified').classList.toggle('on', f.verified);
  document.getElementById('f-online').classList.toggle('on', f.onlineNow);
  document.getElementById('f-new').classList.toggle('on', f.newHere);
}

function recomputeAndRenderCandidates() {
  state.candidates = state.allCandidates.filter(c => matchesFilters(c, state.filters));
  if (document.getElementById('panel-discover').classList.contains('visible')) renderSwipeCard();
}

function openFilterPanel() {
  syncFilterControlsFromState();
  document.getElementById('filter-overlay').classList.add('open');
  document.getElementById('filter-panel').classList.add('open');
  document.getElementById('filter-panel').setAttribute('aria-hidden', 'false');
  document.getElementById('filter-trigger-btn').setAttribute('aria-expanded', 'true');
  document.body.style.overflow = 'hidden';
}

function closeFilterPanel() {
  document.getElementById('filter-overlay').classList.remove('open');
  document.getElementById('filter-panel').classList.remove('open');
  document.getElementById('filter-panel').setAttribute('aria-hidden', 'true');
  document.getElementById('filter-trigger-btn').setAttribute('aria-expanded', 'false');
  document.body.style.overflow = '';
}

function resetFilters() {
  state.filters = JSON.parse(JSON.stringify(FILTER_DEFAULTS));
  syncFilterControlsFromState();
  updateFilterBadge();
  recomputeAndRenderCandidates();
  try { localStorage.setItem('swing_filters', JSON.stringify(state.filters)); } catch (e) { /* ignore */ }
}

function applyFiltersAndClose() {
  updateFilterBadge();
  recomputeAndRenderCandidates();
  try { localStorage.setItem('swing_filters', JSON.stringify(state.filters)); } catch (e) { /* ignore */ }
  closeFilterPanel();
}

document.addEventListener('DOMContentLoaded', () => {
  syncSettingsUI();
  attachChipDelegation(document.getElementById('filter-panel'), () => state.filters);
  attachChipDelegation(document.getElementById('details-form-body'), () => state.details, updateDetailsProgress);
  updateFilterBadge();
});

async function runCountrySearch() {
  await loadDiscover();
  renderSwipeCard();
}
const countrySearchInput = document.getElementById('country-search');
if (countrySearchInput) {
  countrySearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runCountrySearch();
  });
}

function renderSwipeCard() {
  const card = document.getElementById('swipe-card');
  const hint = document.getElementById('swipe-hint');
  if (!state.candidates.length) {
    card.innerHTML = '<div class="empty-state">No more profiles right now. Check back later!</div>';
    hint.textContent = '';
    return;
  }
  const c = state.candidates[0];
  hint.textContent = '';
  const photoStyle = c.photoUrl
    ? \`background-image:url('\${c.photoUrl}');background-size:cover;background-position:center;\`
    : \`background:linear-gradient(135deg, \${colorFor(c.name)}, #2a1620);\`;
  card.innerHTML = \`
    <div class="swipe-card">
      <div class="swipe-photo" style="\${photoStyle}">
        <div class="photo-tag"><svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${c.tags && c.tags.length ? c.tags[0] : 'New here'}</div>
        \${c.compatibility !== null && c.compatibility !== undefined ? \`<div class="photo-counter compat-badge" style="position:absolute;top:16px;right:16px;"><svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${c.compatibility}% Match</div>\` : ''}
        <div class="swipe-details">
          <div class="name-row">\${c.name}\${c.age ? ', ' + c.age : ''}</div>
          <div class="meta">\${c.location ? '<span><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 21s7-6.5 7-11.5A7 7 0 1 0 5 9.5C5 14.5 12 21 12 21Z"/><circle cx="12" cy="9.5" r="2.2"/></svg> ' + c.location + '</span>' : ''}</div>
        </div>
      </div>
      <div class="swipe-card-body">
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg></span>About Me</div>
          <p class="swipe-section-text \${c.bio ? '' : 'empty'}">\${c.bio || 'No bio yet.'}</p>
          <div class="about-pills-grid">\${buildAboutPillsHTML(c)}</div>
        </div>
        \${c.datingIntentions && c.datingIntentions.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle">\${LOOKING_FOR_ICON}</span>I'm looking for</div>
          <div class="about-pills-grid">\${buildLookingForPillsHTML(c)}</div>
        </div>\` : ''}
        \${c.tags && c.tags.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></span>Interests</div>
          <div class="interests-chips">\${c.tags.map(t => '<span class="interest-chip">' + t + '</span>').join('')}</div>
        </div>\` : ''}
        \${c.galleryUrls && c.galleryUrls.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="3" y="6" width="18" height="14" rx="2.5"/><circle cx="12" cy="13" r="3.5"/><path d="M8 6l1.4-2.4A1.5 1.5 0 0 1 10.7 3h2.6a1.5 1.5 0 0 1 1.3.76L16 6"/></svg></span>My Vibes</div>
          <div class="swipe-vibes-grid">\${c.galleryUrls.map((url, i) => '<div class="swipe-vibes-thumb"><img src="' + url + '" alt="Vibes photo ' + (i + 1) + '" loading="lazy" /></div>').join('')}</div>
        </div>\` : ''}
        \${c.prompts && c.prompts.filter(p => p && p.question && p.answer).length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></span>Prompts</div>
          \${c.prompts.filter(p => p && p.question && p.answer).map(p => '<div class="prompt-view-card"><div class="prompt-view-question">' + p.question + '</div><div class="prompt-view-answer">' + p.answer + '</div></div>').join('')}
        </div>\` : ''}
        \${c.quizAnswers && c.quizAnswers.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></span>Compatibility Answers</div>
          \${c.quizAnswers.map(q => '<div class="prompt-view-card"><div class="prompt-view-question">' + q.question + '</div><div class="prompt-view-answer">' + q.answer + '</div></div>').join('')}
        </div>\` : ''}
      </div>
    </div>
  \`;
}

async function swipeAction(direction) {
  if (!state.candidates.length) return;
  const c = state.candidates[0];
  try {
    const data = await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: c.id, direction }) });
    state.candidates.shift();
    state.allCandidates = state.allCandidates.filter(x => x.id !== c.id);
    renderSwipeCard();
    if (data.matched) {
      await loadMatches();
      alert("It's a match with " + c.name + "!");
    }
  } catch (err) {
    alert(err.message);
  }
}

// ---------- Matches / Messages ----------

async function loadMatches() {
  const data = await api('/api/matches');
  state.matches = data.matches;
  const unreadTotal = state.matches.reduce((sum, m) => sum + m.unread, 0);
  const navMatches = document.getElementById('nav-matches-count');
  if (unreadTotal > 0) { navMatches.textContent = unreadTotal; navMatches.style.display = 'inline-block'; }
  else { navMatches.style.display = 'none'; }
  const mnavMsg = document.getElementById('mnav-messages-count');
  if (unreadTotal > 0) { mnavMsg.textContent = unreadTotal; mnavMsg.style.display = 'flex'; }
  else { mnavMsg.style.display = 'none'; }
  renderMatchesSidebar();
  if (document.getElementById('panel-matches').classList.contains('visible')) renderMatchesFull();
}

function renderMatchesSidebar() {
  const avatarsEl = document.getElementById('matches-list');
  if (!state.matches.length) {
    avatarsEl.innerHTML = '<div class="muted-note">No matches yet — start swiping!</div>';
  } else {
    avatarsEl.innerHTML = state.matches.slice(0, 6).map(m => \`
      <div class="match-avatar-wrap" onclick="openChat('\${m.matchKey}')">
        <div class="match-avatar" style="\${avatarStyleAttr(m.user)}">\${avatarInitials(m.user)}<span class="heart-badge"><svg viewBox="0 0 24 24" width="9" height="9" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></span></div>
        <div class="mname">\${m.user.name}</div>
      </div>
    \`).join('');
  }

  const msgsEl = document.getElementById('messages-list');
  const withMsgs = state.matches.filter(m => m.lastMessage);
  if (!withMsgs.length) {
    msgsEl.innerHTML = '<div class="muted-note">No messages yet.</div>';
  } else {
    msgsEl.innerHTML = withMsgs.slice(0, 5).map(m => \`
      <div class="msg-item" onclick="openChat('\${m.matchKey}')">
        <div class="msg-avatar" style="\${avatarStyleAttr(m.user)}">\${avatarInitials(m.user)}</div>
        <div class="msg-body">
          <div class="msg-top"><span class="mname">\${m.user.name}</span><span class="time">\${timeAgo(m.lastMessage.createdAt)}</span></div>
          <div class="msg-preview"><span class="text">\${m.lastMessage.text}</span>\${m.unread ? '<span class="unread-dot">' + m.unread + '</span>' : ''}</div>
        </div>
      </div>
    \`).join('');
  }
}

function renderMatchesFull() {
  const el = document.getElementById('matches-full-list');
  if (!state.matches.length) {
    el.innerHTML = '<div class="empty-state">No matches yet. Head to Discover and start swiping!</div>';
    return;
  }
  el.innerHTML = state.matches.map(m => \`
    <div class="msg-item" style="background:white;border-radius:14px;padding:12px 14px;margin-bottom:10px;border:none;" onclick="openChat('\${m.matchKey}')">
      <div class="msg-avatar" style="\${avatarStyleAttr(m.user)}width:46px;height:46px;font-size:15px;">\${avatarInitials(m.user)}</div>
      <div class="msg-body">
        <div class="msg-top"><span class="mname">\${m.user.name}</span><span class="time">\${m.lastMessage ? timeAgo(m.lastMessage.createdAt) : 'Matched ' + timeAgo(m.createdAt)}</span></div>
        <div class="msg-preview"><span class="text">\${m.lastMessage ? m.lastMessage.text : 'Say hello'}</span>\${m.unread ? '<span class="unread-dot">' + m.unread + '</span>' : ''}</div>
      </div>
    </div>
  \`).join('');
}

async function openChat(matchKey) {
  state.activeChat = matchKey;
  document.body.classList.add('chat-open');
  const match = state.matches.find(m => m.matchKey === matchKey);
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('visible'));
  document.getElementById('panel-chat').classList.add('visible');
  document.getElementById('view-title').textContent = match ? match.user.name : 'Chat';
  document.getElementById('chat-name').textContent = match ? match.user.name : '';
  const av = document.getElementById('chat-avatar');
  av.textContent = match ? avatarInitials(match.user) : '?';
  av.setAttribute('style', 'width:36px;height:36px;font-size:12px;' + (match ? avatarStyleAttr(match.user) : 'background:#ccc;'));

  const compatEl = document.getElementById('chat-compat-panel');
  if (match && match.compatibility !== null && match.compatibility !== undefined) {
    compatEl.innerHTML = \`
      <div class="compat-panel">
        <div class="compat-percent"><svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${match.compatibility}% Compatible</div>
        \${match.compatibilityReasons && match.compatibilityReasons.length ? '<ul>' + match.compatibilityReasons.map(r => '<li>' + r + '</li>').join('') + '</ul>' : ''}
      </div>
    \`;
  } else {
    compatEl.innerHTML = '';
  }

  await loadChatMessages(matchKey);
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState !== 'visible' || !state.user) return;
  if (state.activeChat) {
    loadChatMessages(state.activeChat);
  } else {
    loadMatches();
  }
  // Coming back from the background is also a good moment to make sure
  // the live connection didn't quietly die while we were away.
  if (state.eventSource && state.eventSource.readyState === EventSource.CLOSED) {
    connectLiveUpdates();
  }
});

async function loadChatMessages(matchKey) {
  const data = await api('/api/messages/' + matchKey);
  const el = document.getElementById('chat-messages');
  const wasNearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  if (!data.messages.length) {
    el.innerHTML = '<div class="muted-note" style="text-align:center;margin-top:20px;">You matched! Say hello</div>';
  } else {
    el.innerHTML = data.messages.map(m => \`
      <div class="bubble \${m.fromUserId === state.user.id ? 'mine' : 'theirs'}">\${m.text}</div>
    \`).join('');
  }
  if (wasNearBottom) el.scrollTop = el.scrollHeight;
  await loadMatches();
}

async function sendMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text || !state.activeChat) return;
  input.value = '';
  try {
    await api('/api/messages/' + state.activeChat, { method: 'POST', body: JSON.stringify({ text }) });
    await loadChatMessages(state.activeChat);
  } catch (err) {
    alert(err.message);
  }
}
document.getElementById('chat-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendMessage();
});

// Keep the input + send button visible above the on-screen keyboard.
// Relying on 100dvh alone isn't reliable across all mobile browsers, so
// on focus (and whenever the visual viewport resizes, i.e. the keyboard
// opens/closes) we explicitly scroll the row into view.
function keepInputVisible(inputEl) {
  const scrollIntoView = () => {
    setTimeout(() => {
      inputEl.scrollIntoView({ block: 'end', behavior: 'smooth' });
    }, 100);
  };
  inputEl.addEventListener('focus', scrollIntoView);
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', () => {
      if (document.activeElement === inputEl) scrollIntoView();
    });
  }
}
keepInputVisible(document.getElementById('chat-input'));

// ---------- Swing AI chat ----------

function renderAiChat() {
  const el = document.getElementById('ai-chat-messages');
  if (!state.aiChatHistory.length) {
    el.innerHTML = '<div class="muted-note" style="text-align:center;margin-top:20px;">Tell me what you are looking for in a partner, and I will help you find good matches from your Discover list. <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></div>';
  } else {
    el.innerHTML = state.aiChatHistory.map(m => \`<div class="bubble \${m.role === 'user' ? 'mine' : 'theirs'}">\${m.content}</div>\`).join('');
  }
  el.scrollTop = el.scrollHeight;
}

async function sendAiMessage(overrideText) {
  const input = document.getElementById('ai-chat-input');
  const text = (overrideText !== undefined ? overrideText : input.value).trim();
  if (!text) return;
  input.value = '';
  state.aiChatHistory.push({ role: 'user', content: text });
  renderAiChat();

  const el = document.getElementById('ai-chat-messages');
  const typingId = 'ai-typing-' + Date.now();
  el.insertAdjacentHTML('beforeend', \`<div class="bubble theirs" id="\${typingId}">Swing AI is typing...</div>\`);
  el.scrollTop = el.scrollHeight;

  try {
    const data = await api('/api/ai-chat', { method: 'POST', body: JSON.stringify({ messages: state.aiChatHistory }) });
    const typingEl = document.getElementById(typingId);
    if (typingEl) typingEl.remove();
    state.aiChatHistory.push({ role: 'assistant', content: data.reply });
    renderAiChat();
  } catch (err) {
    const typingEl = document.getElementById(typingId);
    if (typingEl) typingEl.remove();
    state.aiChatHistory.push({ role: 'assistant', content: '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 3.5 21.5 20h-19L12 3.5Z"/><path d="M12 9.5v4.5M12 17h.01"/></svg> ' + err.message });
    renderAiChat();
  }
}

document.getElementById('ai-chat-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendAiMessage();
});
keepInputVisible(document.getElementById('ai-chat-input'));

function toggleVoiceInput() {
  if (state.aiVoiceListening) {
    if (state.aiVoiceRecognition) state.aiVoiceRecognition.stop();
    return;
  }
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRecognition) {
    alert("Voice input isn't supported in this browser. Try Chrome or Safari, or just type your message.");
    return;
  }
  const recognition = new SpeechRecognition();
  recognition.lang = 'en-US';
  recognition.interimResults = false;
  recognition.maxAlternatives = 1;

  state.aiVoiceRecognition = recognition;
  state.aiVoiceListening = true;
  const btn = document.getElementById('ai-mic-btn');
  btn.style.background = 'var(--pink-600)';
  btn.style.color = 'white';
  document.getElementById('ai-chat-input').placeholder = 'Listening...';

  recognition.onresult = (event) => {
    const transcript = event.results[0][0].transcript;
    sendAiMessage(transcript);
  };
  recognition.onerror = () => stopVoiceUI();
  recognition.onend = () => stopVoiceUI();

  recognition.start();
}

function stopVoiceUI() {
  state.aiVoiceListening = false;
  state.aiVoiceRecognition = null;
  const btn = document.getElementById('ai-mic-btn');
  if (btn) { btn.style.background = 'var(--cream)'; btn.style.color = 'var(--pink-600)'; }
  const input = document.getElementById('ai-chat-input');
  if (input) input.placeholder = "Tell Swing AI what you're looking for...";
}

// ---------- Likes You ----------

async function loadAdmirers() {
  const data = await api('/api/likes-you');
  state.admirers = data.admirers;
  document.getElementById('nav-likes-count').textContent = state.admirers.length;
  const mnavLikes = document.getElementById('mnav-likes-count');
  if (state.admirers.length > 0) { mnavLikes.textContent = state.admirers.length; mnavLikes.style.display = 'flex'; }
  else { mnavLikes.style.display = 'none'; }
}

function renderAdmirers() {
  const el = document.getElementById('admirer-grid');
  if (!state.admirers.length) {
    el.innerHTML = '<div class="empty-state">No one has liked you yet. Keep your profile fresh!</div>';
    return;
  }
  el.innerHTML = state.admirers.map(a => \`
    <div class="admirer-card">
      <div class="match-avatar" style="\${avatarStyleAttr(a)}">\${avatarInitials(a)}</div>
      <div class="aname">\${a.name}\${a.age ? ', ' + a.age : ''}</div>
      <button onclick="likeBack('\${a.id}')" aria-label="Like this person back">Like back <svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></button>
    </div>
  \`).join('');
}

async function likeBack(userId) {
  try {
    const data = await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: userId, direction: 'like' }) });
    await loadAdmirers();
    renderAdmirers();
    if (data.matched) {
      await loadMatches();
      alert("It's a match!");
    }
  } catch (err) {
    alert(err.message);
  }
}

// ---------- Compatibility questionnaire ----------

async function showQuestionnaire(origin) {
  state.questionnaireOrigin = origin;
  const data = await api('/api/questionnaire');
  state.questionnaireQuestions = data.questions;
  state.questionnaireAnswers = { ...data.answers };
  state.questionnaireStep = 0;
  document.getElementById('dashboard').classList.remove('visible');
  document.getElementById('questionnaire-screen').classList.add('visible');
  renderQuestionnaireStep();
}

function renderQuestionnaireStep() {
  const qs = state.questionnaireQuestions;
  const i = state.questionnaireStep;
  const q = qs[i];
  const total = qs.length;
  const container = document.getElementById('questionnaire-body');
  const selected = state.questionnaireAnswers[q.id];

  let optionsHtml;
  if (q.type === 'single') {
    optionsHtml = q.options.map(o => \`
      <button type="button" class="q-option \${selected === o.value ? 'selected' : ''}" onclick="selectSingleAnswer('\${q.id}','\${o.value}')">
        <span>\${o.label}</span>\${selected === o.value ? '<span class="check"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 12.5l5 5L20 6.5"/></svg></span>' : ''}
      </button>
    \`).join('');
  } else {
    const arr = Array.isArray(selected) ? selected : [];
    optionsHtml = q.options.map(o => \`
      <button type="button" class="q-option \${arr.includes(o.value) ? 'selected' : ''}" onclick="toggleMultiAnswer('\${q.id}','\${o.value}')">
        <span>\${o.label}</span>\${arr.includes(o.value) ? '<span class="check"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 12.5l5 5L20 6.5"/></svg></span>' : ''}
      </button>
    \`).join('');
  }

  container.innerHTML = \`
    <div class="q-progress">Question \${i + 1} of \${total}</div>
    <div class="q-progress-bar"><div class="q-progress-fill" style="width:\${((i + 1) / total) * 100}%;"></div></div>
    <h3 class="q-title">\${q.question}</h3>
    \${q.type === 'multi' ? '<div class="q-hint">Select all that apply</div>' : ''}
    <div class="q-options">\${optionsHtml}</div>
  \`;

  document.getElementById('q-back-btn').style.visibility = i === 0 ? 'hidden' : 'visible';
  document.getElementById('q-next-btn').textContent = i === total - 1 ? 'Finish' : 'Next';
}

function selectSingleAnswer(qId, value) {
  state.questionnaireAnswers[qId] = value;
  renderQuestionnaireStep();
}

function toggleMultiAnswer(qId, value) {
  const arr = Array.isArray(state.questionnaireAnswers[qId]) ? [...state.questionnaireAnswers[qId]] : [];
  const idx = arr.indexOf(value);
  if (idx === -1) arr.push(value); else arr.splice(idx, 1);
  state.questionnaireAnswers[qId] = arr;
  renderQuestionnaireStep();
}

function goBackQuestion() {
  if (state.questionnaireStep > 0) {
    state.questionnaireStep--;
    renderQuestionnaireStep();
  }
}

async function goNextQuestion() {
  const total = state.questionnaireQuestions.length;
  if (state.questionnaireStep < total - 1) {
    state.questionnaireStep++;
    renderQuestionnaireStep();
  } else {
    await finishQuestionnaire();
  }
}

async function skipQuestionnaire() {
  await closeQuestionnaireScreen();
}

async function finishQuestionnaire() {
  try {
    const data = await api('/api/questionnaire', { method: 'PUT', body: JSON.stringify({ answers: state.questionnaireAnswers }) });
    state.user = data.user;
  } catch (e) {
    // Non-fatal — proceed either way, they can retake it later from Profile.
  }
  await closeQuestionnaireScreen();
}

async function closeQuestionnaireScreen() {
  document.getElementById('questionnaire-screen').classList.remove('visible');
  if (state.questionnaireOrigin === 'signup') {
    showDetailsScreen('signup');
  } else {
    document.getElementById('dashboard').classList.add('visible');
    await loadDiscover();
    await loadMatches();
    switchView('profile');
  }
}

// ---------- Complete your profile (extended details) ----------
// Mirrors PROFILE_COMPLETION_FIELDS on the server so the progress bar here
// and the "Profile strength" bar on the Profile tab agree with what the
// backend reports back after a save.
const PROFILE_STRENGTH_SECTIONS = [
  { key: 'profilePhoto', weight: 10, fields: [u => u.photoUrl] },
  { key: 'nameAndAge', weight: 10, fields: [u => u.name, u => u.age] },
  { key: 'bio', weight: 10, fields: [u => u.bio] },
  { key: 'locationAndQuiz', weight: 20, fields: [
    u => u.location,
    u => u.questionnaire?.relationship_goal,
    u => u.questionnaire?.wants_kids,
    u => u.questionnaire?.personality,
    u => u.questionnaire?.top_value,
    u => u.questionnaire?.conflict_style,
    u => u.questionnaire?.social_style,
    u => u.questionnaire?.career_priority,
    u => u.questionnaire?.communication_style,
    u => u.questionnaire?.personal_space,
    u => u.questionnaire?.lifestyle_pace,
    u => u.questionnaire?.dealbreakers,
  ] },
  { key: 'interestsAndQuickInfo', weight: 10, fields: [u => u.tags, u => u.languages] },
  { key: 'lookingFor', weight: 10, fields: [u => u.datingIntentions] },
  { key: 'lifestyle', weight: 5, fields: [
    u => u.education, u => u.heightCm, u => u.exercise, u => u.drinking,
    u => u.smoking, u => u.religion, u => u.political, u => u.children,
    u => u.wantsChildren,
  ] },
  { key: 'additionalPhotosOrVibe', weight: 15, fields: [
    u => u.galleryUrls?.[0], u => u.galleryUrls?.[1], u => u.galleryUrls?.[2],
  ] },
  { key: 'prompts', weight: 10, fields: [
    u => u.prompts?.[0], u => u.prompts?.[1], u => u.prompts?.[2],
  ] },
];
function isProfileValueCompletedClient(value) {
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'boolean') return true;
  return value !== null && value !== undefined && String(value).trim().length > 0;
}
function computeProfileStrengthClient(u) {
  let total = 0;
  for (const section of PROFILE_STRENGTH_SECTIONS) {
    const completed = section.fields.reduce((n, get) => {
      let value = null;
      try { value = get(u || {}); } catch (_) {}
      return n + (isProfileValueCompletedClient(value) ? 1 : 0);
    }, 0);
    total += section.weight * (completed / section.fields.length);
  }
  return Math.min(100, Math.round(total));
}
function computeCompletionClient(u) {
  return computeProfileStrengthClient(u);
}

function updateProfileCompletionDisplay() {
  const pctEl = document.getElementById('profile-completion-pct');
  if (!pctEl || !state.user) return;
  const pct = (state.user.profileStrength && typeof state.user.profileStrength.percentage === 'number')
    ? state.user.profileStrength.percentage
    : computeCompletionClient(state.user);
  pctEl.textContent = pct + '%';
  document.getElementById('profile-completion-fill').style.width = pct + '%';
  document.getElementById('profile-completion-cta').style.display = pct < 100 ? 'block' : 'none';
}

function defaultDetails() {
  return {
    languages: [], education: '', heightCm: 170, exercise: '',
    drinking: '', smoking: '', religion: '', political: '',
    children: '', wantsChildren: '', datingIntentions: [],
  };
}

function populateDetailsFormFromUser(user) {
  state.details = {
    languages: (user.languages || []).slice(),
    education: user.education || '',
    heightCm: user.heightCm || 170,
    exercise: user.exercise || '',
    drinking: user.drinking || '',
    smoking: user.smoking || '',
    religion: user.religion || '',
    political: user.political || '',
    children: user.children || '',
    wantsChildren: user.wantsChildren || '',
    datingIntentions: (user.datingIntentions || []).slice(),
  };
  document.getElementById('d-education').value = state.details.education;
  document.getElementById('d-religion').value = state.details.religion;
  document.getElementById('d-political').value = state.details.political;
  document.getElementById('d-height').value = state.details.heightCm;
  document.getElementById('d-height-val').textContent = state.details.heightCm + ' cm';
  syncChipSelectedStatesIn(document.getElementById('details-form-body'), state.details);
  updateDetailsProgress();
}

function onDetailsHeightInput() {
  const v = parseInt(document.getElementById('d-height').value, 10);
  state.details.heightCm = v;
  document.getElementById('d-height-val').textContent = v + ' cm';
  updateDetailsProgress();
}

function updateDetailsProgress() {
  const fill = document.getElementById('details-progress-fill');
  if (!fill || !state.user) return;
  const merged = Object.assign({}, state.user, state.details);
  fill.style.width = computeCompletionClient(merged) + '%';
}

function showDetailsScreen(origin) {
  state.detailsOrigin = origin;
  populateDetailsFormFromUser(state.user || {});
  document.getElementById('details-screen').classList.add('visible');
}

async function proceedAfterDetails() {
  document.getElementById('details-screen').classList.remove('visible');
  if (state.detailsOrigin === 'signup') {
    await enterDashboard();
  } else {
    document.getElementById('dashboard').classList.add('visible');
    updateProfileCompletionDisplay();
    switchView('profile');
  }
}

async function saveDetailsScreen() {
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify(state.details) });
    state.user = data.user;
  } catch (e) {
    // Non-fatal — they can fill this in later from the Profile tab.
  }
  await proceedAfterDetails();
}

async function skipDetailsScreen() {
  await proceedAfterDetails();
}

// ---------- Profile ----------

function fillProfileForm() {
  document.getElementById('p-name').value = state.user.name || '';
  document.getElementById('p-age').value = state.user.age || '';
  document.getElementById('p-gender').value = state.user.gender || 'other';
  document.getElementById('p-country').value = state.user.country || '';
  document.getElementById('p-location').value = state.user.location || '';
  document.getElementById('p-bio').value = state.user.bio || '';
  document.getElementById('p-tags').value = (state.user.tags || []).join(', ');
  refreshProfileViewMode();
  updateProfileCompletionDisplay();
}

function refreshProfileViewMode() {
  const u = state.user;
  if (!u) return;
  const preview = document.getElementById('ph-photo-preview');
  preview.textContent = avatarInitials(u);
  preview.setAttribute('style', avatarStyleAttr(u));
  document.getElementById('ph-name').textContent = u.name || 'Your name';
  document.getElementById('ph-verified-badge').style.display = u.verified ? 'inline-flex' : 'none';
  const metaParts = [];
  if (u.age) metaParts.push(u.age + ' yrs');
  const place = [u.location, u.country].filter(Boolean).join(', ');
  if (place) metaParts.push(place);
  document.getElementById('ph-meta').textContent = metaParts.length ? metaParts.join(' • ') : 'Add your age & location';
  const tagline = (u.bio || '').trim();
  const taglineEl = document.getElementById('ph-tagline');
  taglineEl.textContent = tagline ? (tagline.length > 90 ? tagline.slice(0, 90) + '…' : tagline) : '';
  const bioEl = document.getElementById('ph-bio-text');
  if (tagline) {
    bioEl.textContent = tagline;
    bioEl.classList.remove('empty');
  } else {
    bioEl.textContent = 'Nothing here yet — tap Edit Profile to write a bio.';
    bioEl.classList.add('empty');
  }
  renderInterestsChips(u);
  renderAboutPills(u);
  renderLookingFor(u);
  renderVibesGalleryView(u);
  renderPromptsView(u);
}

function renderInterestsChips(u) {
  const el = document.getElementById('ph-interests-chips');
  if (!el) return;
  const tags = u.tags || [];
  if (!tags.length) {
    el.innerHTML = '<p class="interests-empty-note">No interests added yet — tap Edit Profile to add some.</p>';
    return;
  }
  el.innerHTML = tags.map(t => \`<span class="interest-chip">\${t}</span>\`).join('');
}

const QUICK_INFO_ICONS = {
  gender: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="3.4"/><path d="M4.8 20a7.2 7.2 0 0 1 14.4 0"/></svg>',
  languages: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 3.8 5.8 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.8-3.8-9s1.3-6.5 3.8-9Z"/></svg>',
  education: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M2 8l10-4 10 4-10 4-10-4Z"/><path d="M6 10.5V16c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5v-5.5"/></svg>',
  heightCm: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 3v18M8 6l4-3 4 3M8 18l4 3 4-3"/></svg>',
  exercise: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M6.5 6.5 4 4M17.5 17.5 20 20M4 20l16-16M2.5 8.5l3-3M18.5 15l3 3M8.5 2.5l-3 3M15 18.5l3 3"/></svg>',
  drinking: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M6 3h12l-1.5 8a4.5 4.5 0 0 1-9 0Z"/><path d="M12 15v6M8 21h8"/></svg>',
  smoking: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M2 16h14v3H2zM16 16h3a2 2 0 0 0 0-4"/><path d="M4 12c1-2-1-3 0-5M9 12c1-2-1-3 0-5"/></svg>',
  religion: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 2v20M6 8h12M4 14h16l-1.5 6a2 2 0 0 1-2 1.6H7.5a2 2 0 0 1-2-1.6Z"/></svg>',
  political: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 3v18M5 4h12l-2.5 3.5L17 11H5"/></svg>',
  children: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="6" r="2.6"/><path d="M6 21c0-3.6 2.7-6.5 6-6.5s6 2.9 6 6.5"/></svg>',
  wantsChildren: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg>',
  datingIntentions: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M8.5 9.5 12 6l3.5 3.5M12 6v13M4 13.5l3.5 3.5L4 20.5M20 13.5l-3.5 3.5 3.5 3.5"/></svg>',
};
const LOOKING_FOR_ICON = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>';
const LOOKING_FOR_LABELS = {
  casual: 'A casual relationship',
  relationship: 'A long-term relationship',
  marriage: 'Marriage',
  friendship: 'Friendship',
  not_sure: 'Not sure yet',
};
function titleCaseWords(s) { return (s || '').toString().replace(/([A-Z])/g, ' $1').replace(/[_-]+/g, ' ').trim().replace(/\\b\\w/g, c => c.toUpperCase()); }

// Builds the "About Me" pill list (quick facts) for any user object — shared
// between the person's own Profile page and the Discover card of someone
// else's profile. Only fields that are actually filled in produce a pill.
function buildAboutPillsHTML(u) {
  const items = [];
  if (u.heightCm) items.push(['heightCm', u.heightCm + ' cm']);
  if (u.education) items.push(['education', titleCaseWords(u.education)]);
  if (u.languages && u.languages.length) items.push(['languages', u.languages.join(', ')]);
  if (u.exercise) items.push(['exercise', titleCaseWords(u.exercise)]);
  if (u.drinking) items.push(['drinking', titleCaseWords(u.drinking)]);
  if (u.smoking) items.push(['smoking', titleCaseWords(u.smoking)]);
  if (u.religion) items.push(['religion', titleCaseWords(u.religion)]);
  if (u.political) items.push(['political', titleCaseWords(u.political)]);
  if (u.children) items.push(['children', titleCaseWords(u.children)]);
  if (u.wantsChildren) items.push(['wantsChildren', titleCaseWords(u.wantsChildren)]);
  if (u.gender) items.push(['gender', titleCaseWords(u.gender)]);
  if (!items.length) return '';
  return items.map(([key, value]) => \`
    <span class="about-pill"><span class="icon-circle">\${QUICK_INFO_ICONS[key] || ''}</span>\${value}</span>
  \`).join('');
}

// Builds the "I'm looking for" pill list from datingIntentions.
function buildLookingForPillsHTML(u) {
  const values = u.datingIntentions || [];
  if (!values.length) return '';
  return values.map(v => \`
    <span class="about-pill"><span class="icon-circle">\${LOOKING_FOR_ICON}</span>\${LOOKING_FOR_LABELS[v] || titleCaseWords(v)}</span>
  \`).join('');
}

function renderAboutPills(u) {
  const el = document.getElementById('ph-about-pills');
  if (!el) return;
  el.innerHTML = buildAboutPillsHTML(u);
}

function renderLookingFor(u) {
  const el = document.getElementById('ph-lookingfor-pills');
  if (!el) return;
  const html = buildLookingForPillsHTML(u);
  el.innerHTML = html || '<p class="quick-info-card-text empty">Not set yet — tap Edit Profile to add this.</p>';
}

// ---------- My Vibes gallery ----------
let vibesPendingIndex = null;   // slot index being replaced, or null = adding a new photo
let vibesUploadingIndex = null; // slot index currently mid-upload (drives the spinner)

function triggerVibesUpload(replaceIndex) {
  vibesPendingIndex = (typeof replaceIndex === 'number') ? replaceIndex : null;
  const input = document.getElementById('vibes-photo-input');
  input.value = '';
  input.click();
}

async function handleVibesPhotoSelect(event) {
  const file = event.target.files[0];
  if (!file) return;
  const statusEl = document.getElementById('vibes-status');
  statusEl.textContent = '';

  if (file.size > 8 * 1024 * 1024) {
    statusEl.textContent = 'Image too large (max 8MB).';
    return;
  }

  const gallery = state.user.galleryUrls || [];
  const isReplace = vibesPendingIndex !== null;
  if (!isReplace && gallery.length >= 3) {
    statusEl.textContent = 'You can upload up to 3 photos.';
    return;
  }

  const targetIndex = isReplace ? vibesPendingIndex : gallery.length;
  vibesUploadingIndex = targetIndex;
  renderVibesGalleryEdit(state.user);
  statusEl.textContent = 'Uploading...';

  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const dataUrl = reader.result;
      const data = isReplace
        ? await api('/api/profile/gallery/' + targetIndex, { method: 'PUT', body: JSON.stringify({ photo: dataUrl }) })
        : await api('/api/profile/gallery', { method: 'POST', body: JSON.stringify({ photo: dataUrl }) });
      state.user = data.user;
      statusEl.textContent = '';
      renderVibesGalleryView(state.user);
    } catch (err) {
      statusEl.textContent = err.message || 'Upload failed. Please try again.';
    } finally {
      vibesUploadingIndex = null;
      vibesPendingIndex = null;
      renderVibesGalleryEdit(state.user);
    }
  };
  reader.onerror = () => {
    statusEl.textContent = 'Could not read that file. Please try again.';
    vibesUploadingIndex = null;
    vibesPendingIndex = null;
    renderVibesGalleryEdit(state.user);
  };
  reader.readAsDataURL(file);
}

async function deleteVibesPhoto(index) {
  if (!confirm('Remove this photo from My Vibes?')) return;
  const statusEl = document.getElementById('vibes-status');
  try {
    const data = await api('/api/profile/gallery/' + index, { method: 'DELETE' });
    state.user = data.user;
    statusEl.textContent = '';
    renderVibesGalleryEdit(state.user);
    renderVibesGalleryView(state.user);
  } catch (err) {
    statusEl.textContent = err.message || 'Could not delete photo.';
  }
}

async function moveVibesPhoto(index, direction) {
  const gallery = state.user.galleryUrls || [];
  const to = index + direction;
  if (to < 0 || to >= gallery.length) return;
  const statusEl = document.getElementById('vibes-status');
  try {
    const data = await api('/api/profile/gallery/reorder', { method: 'POST', body: JSON.stringify({ from: index, to }) });
    state.user = data.user;
    statusEl.textContent = '';
    renderVibesGalleryEdit(state.user);
    renderVibesGalleryView(state.user);
  } catch (err) {
    statusEl.textContent = err.message || 'Could not reorder photos.';
  }
}

// Edit-mode gallery: filled slots + empty "Add Photo" slots, with
// replace / delete / reorder controls. Lives inside the Edit Profile screen.
function renderVibesGalleryEdit(u) {
  const grid = document.getElementById('vibes-grid');
  const counter = document.getElementById('vibes-counter');
  if (!grid) return;
  const gallery = (u && u.galleryUrls) || [];
  counter.textContent = gallery.length + '/3 photos';

  let html = '';
  for (let i = 0; i < 3; i++) {
    const url = gallery[i];
    const loading = vibesUploadingIndex === i;
    if (url) {
      html += \`
        <div class="vibes-slot">
          <img src="\${url}" alt="My Vibes photo \${i + 1}" loading="lazy" onload="this.classList.add('loaded')" />
          <div class="vibes-slot-actions">
            \${i > 0 ? \`<button type="button" onclick="moveVibesPhoto(\${i}, -1)" aria-label="Move left" title="Move left"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M15 5l-7 7 7 7"/></svg></button>\` : ''}
            \${i < gallery.length - 1 ? \`<button type="button" onclick="moveVibesPhoto(\${i}, 1)" aria-label="Move right" title="Move right"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M9 5l7 7-7 7"/></svg></button>\` : ''}
            <button type="button" onclick="triggerVibesUpload(\${i})" aria-label="Replace photo" title="Replace">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 4v5h5M20 20v-5h-5"/><path d="M5.5 15A7 7 0 0 0 19 12M18.5 9A7 7 0 0 0 5 12"/></svg>
            </button>
            <button type="button" onclick="deleteVibesPhoto(\${i})" aria-label="Delete photo" title="Delete">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>
            </button>
          </div>
          \${loading ? '<div class="vibes-slot-loading"><div class="vibes-spinner"></div></div>' : ''}
        </div>\`;
    } else if (loading) {
      html += '<div class="vibes-slot vibes-slot-empty"><div class="vibes-spinner"></div></div>';
    } else {
      html += \`
        <button type="button" class="vibes-slot vibes-slot-empty" onclick="triggerVibesUpload(null)">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 5v14M5 12h14"/></svg>
          <span style="font-size:11.5px;font-weight:600;">Add Photo</span>
        </button>\`;
    }
  }
  grid.innerHTML = html;
}

// View-mode gallery: read-only, shows only the photos that exist — no
// add/replace/delete controls, since photo management now lives in Edit
// Profile. Keeps the main profile page looking like a finished profile.
function renderVibesGalleryView(u) {
  const grid = document.getElementById('ph-vibes-grid');
  const counter = document.getElementById('ph-vibes-counter');
  if (!grid) return;
  const gallery = (u && u.galleryUrls) || [];
  counter.textContent = gallery.length + '/3 photos';
  if (!gallery.length) {
    grid.innerHTML = '<p class="quick-info-card-text empty">No photos yet — add some from Edit Profile.</p>';
    return;
  }
  grid.innerHTML = gallery.map((url, i) => \`
    <div class="vibes-slot vibes-slot-view">
      <img src="\${url}" alt="My Vibes photo \${i + 1}" loading="lazy" onload="this.classList.add('loaded')" />
    </div>
  \`).join('');
}

// ---------- Prompts ----------
// Mirrors PROMPT_LIBRARY on the server (see validatePrompts / handleGetPrompts).
const PROMPT_LIBRARY_CLIENT = [
  'My simple pleasures are...',
  'Together, we could...',
  'The way to win me over is...',
  'A life goal of mine is...',
  'My most controversial opinion is...',
  'A typical Sunday for me looks like...',
  "I'm looking for someone who...",
  'Two truths and a lie about me...',
];
const MAX_PROMPTS_CLIENT = 3;

function renderPromptsView(u) {
  const el = document.getElementById('ph-prompts-list');
  if (!el) return;
  const prompts = (u.prompts || []).filter(p => p && p.question && p.answer);
  if (!prompts.length) {
    el.innerHTML = '<p class="swipe-section-text empty">No prompts answered yet — tap Edit Profile to add up to 3.</p>';
    return;
  }
  el.innerHTML = prompts.map(p => \`
    <div class="prompt-view-card">
      <div class="prompt-view-question">\${p.question}</div>
      <div class="prompt-view-answer">\${p.answer}</div>
    </div>
  \`).join('');
}

function renderPromptsEdit(u) {
  const wrap = document.getElementById('prompts-edit-rows');
  const counter = document.getElementById('prompts-counter');
  if (!wrap) return;
  const current = (u.prompts || []).filter(p => p && p.question && p.answer);
  const options = PROMPT_LIBRARY_CLIENT.map(q => \`<option value="\${q}">\${q}</option>\`).join('');
  wrap.innerHTML = '';
  for (let i = 0; i < MAX_PROMPTS_CLIENT; i++) {
    const existing = current[i] || { question: '', answer: '' };
    const row = document.createElement('div');
    row.className = 'prompt-edit-row';
    row.innerHTML = \`
      <select id="prompt-q-\${i}">
        <option value="">Choose a prompt…</option>
        \${options}
      </select>
      <textarea id="prompt-a-\${i}" maxlength="300" placeholder="Your answer">\${existing.answer}</textarea>
    \`;
    wrap.appendChild(row);
    document.getElementById(\`prompt-q-\${i}\`).value = existing.question;
  }
  if (counter) counter.textContent = current.length + '/3 answered';
}

async function savePrompts() {
  const statusEl = document.getElementById('prompts-status');
  const rows = [];
  for (let i = 0; i < MAX_PROMPTS_CLIENT; i++) {
    const question = document.getElementById(\`prompt-q-\${i}\`).value.trim();
    const answer = document.getElementById(\`prompt-a-\${i}\`).value.trim();
    if (question && answer) rows.push({ question, answer });
  }
  try {
    const data = await api('/api/prompts', { method: 'PUT', body: JSON.stringify({ prompts: rows }) });
    state.user = data.user;
    renderPromptsEdit(state.user);
    renderPromptsView(state.user);
    updateProfileCompletionDisplay();
    if (statusEl) { statusEl.textContent = 'Saved!'; setTimeout(() => { statusEl.textContent = ''; }, 2000); }
  } catch (err) {
    if (statusEl) statusEl.textContent = err.message || 'Could not save prompts.';
  }
}

function enterProfileEditMode() {
  document.getElementById('profile-view-mode').style.display = 'none';
  document.getElementById('profile-edit-mode').style.display = 'block';
  renderVibesGalleryEdit(state.user);
  renderPromptsEdit(state.user);
}

function exitProfileEditMode() {
  document.getElementById('profile-edit-mode').style.display = 'none';
  document.getElementById('profile-view-mode').style.display = 'flex';
}

function handlePhotoSelect(event) {
  const file = event.target.files[0];
  if (!file) return;
  if (file.size > 8 * 1024 * 1024) {
    document.getElementById('photo-upload-status').textContent = 'Image too large (max 8MB).';
    return;
  }
  const reader = new FileReader();
  reader.onload = async () => {
    const dataUrl = reader.result;
    const status = document.getElementById('photo-upload-status');
    status.textContent = 'Uploading...';
    try {
      const data = await api('/api/profile/photo', { method: 'POST', body: JSON.stringify({ photo: dataUrl }) });
      state.user = data.user;
      fillProfileForm();
      updateMeAvatars();
      status.textContent = 'Photo updated!';
      setTimeout(() => status.textContent = '', 1500);
    } catch (err) {
      status.textContent = err.message;
    }
  };
  reader.readAsDataURL(file);
}

async function saveProfile() {
  const body = {
    name: document.getElementById('p-name').value,
    age: document.getElementById('p-age').value,
    gender: document.getElementById('p-gender').value,
    country: document.getElementById('p-country').value,
    location: document.getElementById('p-location').value,
    bio: document.getElementById('p-bio').value,
    tags: document.getElementById('p-tags').value,
  };
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify(body) });
    state.user = data.user;
    document.getElementById('me-name').textContent = state.user.name;
    refreshProfileViewMode();
    updateProfileCompletionDisplay();
    const note = document.getElementById('save-note');
    note.style.display = 'inline';
    setTimeout(() => { note.style.display = 'none'; exitProfileEditMode(); }, 700);
  } catch (err) {
    alert(err.message);
  }
}

function getSwingSettings() {
  try {
    return {
      theme: localStorage.getItem('swing_theme') || 'system',
      reducedMotion: localStorage.getItem('swing_reduced_motion') === '1'
    };
  } catch (e) {
    return { theme: 'system', reducedMotion: false };
  }
}

function applySwingTheme(theme) {
  const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.body.classList.toggle('settings-dark', !!isDark);
  document.documentElement.dataset.swingTheme = theme;
  document.querySelectorAll('[data-theme-choice]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-theme-choice') === theme);
  });
}

function applyReducedMotion(enabled) {
  document.body.classList.toggle('settings-reduced-motion', enabled);
  const styleId = 'swing-reduced-motion-style';
  let style = document.getElementById(styleId);
  if (enabled && !style) {
    style = document.createElement('style');
    style.id = styleId;
    style.textContent = '* { scroll-behavior: auto !important; } *, *::before, *::after { animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; transition-duration: 0.001ms !important; }';
    document.head.appendChild(style);
  } else if (!enabled && style) {
    style.remove();
  }
  const toggle = document.getElementById('settings-motion-toggle');
  if (toggle) toggle.classList.toggle('active', enabled);
}

function syncSettingsUI() {
  const settings = getSwingSettings();
  applySwingTheme(settings.theme);
  applyReducedMotion(settings.reducedMotion);
  const email = document.getElementById('settings-email');
  if (email) email.textContent = (state.user && state.user.email) ? state.user.email : 'Hidden';
}

function openProfileSettings() {
  const panel = document.getElementById('settings-panel');
  const overlay = document.getElementById('settings-overlay');
  if (!panel || !overlay) return;
  syncSettingsUI();
  panel.classList.add('open');
  overlay.classList.add('open');
  panel.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
}

function closeProfileSettings() {
  const panel = document.getElementById('settings-panel');
  const overlay = document.getElementById('settings-overlay');
  if (!panel || !overlay) return;
  panel.classList.remove('open');
  overlay.classList.remove('open');
  panel.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}

function setSwingTheme(theme) {
  if (!['system', 'light', 'dark'].includes(theme)) return;
  try { localStorage.setItem('swing_theme', theme); } catch (e) { /* ignore */ }
  applySwingTheme(theme);
}

const swingSystemThemeMedia = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
if (swingSystemThemeMedia) {
  const syncSystemTheme = () => {
    const theme = getSwingSettings().theme;
    if (theme === 'system') applySwingTheme('system');
  };
  if (swingSystemThemeMedia.addEventListener) swingSystemThemeMedia.addEventListener('change', syncSystemTheme);
  else if (swingSystemThemeMedia.addListener) swingSystemThemeMedia.addListener(syncSystemTheme);
}

function toggleReducedMotion() {
  const next = !getSwingSettings().reducedMotion;
  try { localStorage.setItem('swing_reduced_motion', next ? '1' : '0'); } catch (e) { /* ignore */ }
  applyReducedMotion(next);
}

function resetFiltersFromSettings() {
  if (!confirm('Reset all Discover filters to their defaults?')) return;
  state.filters = defaultFilters();
  try { localStorage.setItem('swing_filters', JSON.stringify(state.filters)); } catch (e) { /* ignore */ }
  if (typeof syncFilterControls === 'function') syncFilterControls();
  updateFilterBadge();
  recomputeAndRenderCandidates();
  closeProfileSettings();
}

function logoutFromSettings() {
  closeProfileSettings();
  logout();
}

// ---------- Boot ----------

async function boot() {
  if (state.token) {
    let data;
    try {
      data = await api('/api/me');
    } catch (e) {
      // Only a failed /api/me means the session itself is invalid —
      // this is the one case where clearing the token is correct.
      localStorage.removeItem('swing_token');
      state.token = null;
      setAuthMode('login');
      return;
    }
    state.user = data.user;
    try {
      await enterDashboard();
    } catch (e) {
      // Logged in fine, but something in the dashboard failed to load
      // (network blip, a bug in one panel, etc). Don't log the person
      // out over this — show the dashboard shell and let them retry.
      console.error('Dashboard failed to load:', e);
      document.getElementById('auth-screen').style.display = 'none';
      document.getElementById('dashboard').classList.add('visible');
    }
  } else {
    setAuthMode('login');
  }
}
boot();
</script>
</body>
</html>`;


// ---------- Server ----------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const { pathname } = url;

  try {
    if (pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(FRONTEND_HTML);
    }

    if (pathname === '/robots.txt' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('User-agent: *\nAllow: /\n');
    }

    if (pathname === '/api/register' && req.method === 'POST') {
      return await handleRegister(req, res);
    }
    if (pathname === '/api/login' && req.method === 'POST') {
      return await handleLogin(req, res);
    }
    if (pathname === '/api/me' && req.method === 'GET') {
      return await handleMe(req, res);
    }
    if (pathname === '/api/logout' && req.method === 'POST') {
      return await handleLogout(req, res);
    }
    if (pathname === '/api/stream' && req.method === 'GET') {
      return await handleStream(req, res, url.searchParams);
    }
    if (pathname === '/api/profile' && req.method === 'PUT') {
      return await handleUpdateProfile(req, res);
    }
    if (pathname === '/api/profile/photo' && req.method === 'POST') {
      return await handleUploadPhoto(req, res);
    }
    const galleryMatch = pathname.match(/^\/api\/profile\/gallery(?:\/(\d+))?$/);
    if (galleryMatch && req.method === 'POST' && galleryMatch[1] === undefined) {
      return await handleAddGalleryPhoto(req, res);
    }
    if (galleryMatch && req.method === 'PUT' && galleryMatch[1] !== undefined) {
      return await handleReplaceGalleryPhoto(req, res, galleryMatch[1]);
    }
    if (galleryMatch && req.method === 'DELETE' && galleryMatch[1] !== undefined) {
      return await handleDeleteGalleryPhoto(req, res, galleryMatch[1]);
    }
    if (pathname === '/api/profile/gallery/reorder' && req.method === 'POST') {
      return await handleReorderGalleryPhotos(req, res);
    }
    if (pathname === '/api/questionnaire' && req.method === 'GET') {
      return await handleGetQuestionnaire(req, res);
    }
    if (pathname === '/api/questionnaire' && req.method === 'PUT') {
      return await handleSubmitQuestionnaire(req, res);
    }
    if (pathname === '/api/prompts' && req.method === 'GET') {
      return await handleGetPrompts(req, res);
    }
    if (pathname === '/api/prompts' && req.method === 'PUT') {
      return await handleUpdatePrompts(req, res);
    }
    if (pathname === '/api/discover' && req.method === 'GET') {
      return await handleDiscover(req, res, url.searchParams);
    }
    if (pathname === '/api/like' && req.method === 'POST') {
      return await handleLike(req, res);
    }
    if (pathname === '/api/likes-you' && req.method === 'GET') {
      return await handleLikesYou(req, res);
    }
    if (pathname === '/api/ai-chat' && req.method === 'POST') {
      return await handleAiChat(req, res);
    }
    if (pathname === '/api/matches' && req.method === 'GET') {
      return await handleMatches(req, res);
    }

    const msgMatch = pathname.match(/^\/api\/messages\/([^/]+)$/);
    if (msgMatch && req.method === 'GET') {
      return await handleGetMessages(req, res, decodeURIComponent(msgMatch[1]));
    }
    if (msgMatch && req.method === 'POST') {
      return await handlePostMessage(req, res, decodeURIComponent(msgMatch[1]));
    }

    sendJSON(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    sendJSON(res, 500, { error: 'Internal server error' });
  }
});

server.listen(PORT, () => {
  console.log(`Swing running at http://localhost:${PORT}`);
});
