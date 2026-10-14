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
const MAX_BODY_BYTES = 8 * 1024 * 1024; // absolute request cap; JSON/text endpoints enforce smaller limits
const MAX_TEXT_BYTES = 32 * 1024;
const MAX_MESSAGE_CHARS = 2000;
const MAX_BIO_CHARS = 1000;
const MAX_NAME_CHARS = 80;
const MAX_LOCATION_CHARS = 120;
const MAX_COUNTRY_CHARS = 80;
// Expanded gender options (was previously just man/woman/other). Kept as a
// single source of truth here so registration and profile-update validation
// can't drift out of sync with each other.
const VALID_GENDERS = ['man', 'woman', 'non-binary', 'genderqueer', 'genderfluid', 'agender', 'other', 'prefer_not_to_say'];
// Orientation and "interested in" are both private matching inputs — see
// toPublicUser/toOwnUser below, neither is ever returned for anyone other
// than the account owner, and neither is shown on a profile. "everyone" is
// a UI-only shortcut: it's resolved to all three buckets before saving, so
// interested_in in the DB only ever contains 'men'/'women'/'nonbinary'.
// Requires (run once):
//   ALTER TABLE users ADD COLUMN orientation text;
//   ALTER TABLE users ADD COLUMN interested_in text[] NOT NULL DEFAULT '{}';
const VALID_ORIENTATIONS = ['straight', 'gay', 'lesbian', 'bisexual', 'pansexual', 'asexual', 'queer', 'questioning', 'other', 'prefer_not_to_say'];
const VALID_INTERESTED_IN = ['men', 'women', 'nonbinary'];
const PHOTOS_BUCKET = 'photos';
const SESSION_COOKIE = 'swing_session';
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SESSION_RENEW_THRESHOLD_MS = 7 * 24 * 60 * 60 * 1000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const TRUST_PROXY = process.env.TRUST_PROXY !== 'false';
// How many reverse proxies sit in front of this server (Render = 1; Render
// behind Cloudflare = 2). X-Forwarded-For is client-controllable on its
// left side, so the real client IP is the entry N hops from the RIGHT.
const TRUSTED_PROXY_HOPS = Math.max(1, parseInt(process.env.TRUSTED_PROXY_HOPS || '1', 10) || 1);
const MIN_PASSWORD_LENGTH = 8;
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true' || IS_PRODUCTION || process.env.RENDER === 'true';
// Admins (can open /admin and review reports). Set either or both as
// comma-separated env vars, e.g. ADMIN_EMAILS=you@example.com
const ADMIN_USER_IDS = new Set(String(process.env.ADMIN_USER_IDS || '').split(',').map(v => v.trim()).filter(Boolean));
const ADMIN_EMAILS = new Set(String(process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean));
// Email-based admin is only honored for accounts flagged users.verified = true
// (set manually in the DB for your own account). Sign-up does not verify email
// ownership, so without this anyone could register an ADMIN_EMAILS address
// that isn't taken yet and become admin. ADMIN_USER_IDS is the safer option.
function isAdminUser(user) {
  if (!user) return false;
  if (ADMIN_USER_IDS.has(user.id)) return true;
  return user.verified === true && !!user.email && ADMIN_EMAILS.has(String(user.email).toLowerCase());
}

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables.');
  console.error('Set them before starting the server (see README).');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

if (ADMIN_EMAILS.size) {
  console.warn('[admin] ADMIN_EMAILS only grants admin to accounts with users.verified = true. Prefer ADMIN_USER_IDS.');
}

// Used to scope the CSP's img-src to just our own Storage bucket instead of
// a blanket `https:` (see applySecurityHeaders below) — a wildcard there
// would let an XSS payload exfiltrate data via <img src="https://evil...">
// even with connect-src locked down, since image loads aren't covered by it.
const SUPABASE_ORIGIN = (() => {
  try { return new URL(SUPABASE_URL).origin; } catch (e) { return ''; }
})();

// ---------- Helpers ----------

// crypto.scryptSync/pbkdf2Sync block Node's single-threaded event loop for
// their entire runtime. That's a big deal specifically for login/register:
// under any concurrent load (two people signing in around the same time,
// a double-clicked submit button, etc.) one hash computation stalls every
// other in-flight request on the server — including unrelated ones — for
// however long scrypt takes on the host's CPU. On a resource-constrained
// instance that can be long enough to trip the platform's request/health
// check timeout, which looks to users like an intermittent "Internal
// server error" or a hard "Load failed" with no clean response at all,
// concentrated on login/signup since that's where hashing happens. Using
// the async (threadpool-backed) variants keeps the event loop free.
const { promisify } = require('util');
const scryptAsync = promisify(crypto.scrypt);
const pbkdf2Async = promisify(crypto.pbkdf2);

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
  return { salt: salt.toString('hex'), hash: `scrypt$${derived.toString('hex')}` };
}

async function verifyPassword(password, salt, storedHash) {
  try {
    // Existing accounts used PBKDF2. Keep them working once, then transparently
    // upgrade them to scrypt on successful login.
    if (String(storedHash || '').startsWith('scrypt$')) {
      const hashBuf = Buffer.from(storedHash.slice(7), 'hex');
      const check = await scryptAsync(password, Buffer.from(salt, 'hex'), 64, { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
      return check.length === hashBuf.length && crypto.timingSafeEqual(check, hashBuf);
    }
    const check = await pbkdf2Async(password, salt, 100000, 64, 'sha512');
    const hashBuf = Buffer.from(storedHash, 'hex');
    return check.length === hashBuf.length && crypto.timingSafeEqual(check, hashBuf);
  } catch (_) {
    return false;
  }
}

// Hashed once at startup; verified against when a login names an unknown
// account so response time doesn't reveal whether the account exists.
const dummyCredsPromise = hashPassword(crypto.randomBytes(12).toString('hex') + 'a1').catch(() => null);

// Password rule: 8+ chars, must contain at least one letter and one digit
// (case optional). Applied on register and on password reset.
function isValidAge(a) {
  return typeof a === 'number' && Number.isInteger(a) && a >= 18 && a <= 100;
}

function isValidPassword(pw) {
  return typeof pw === 'string' && pw.length >= MIN_PASSWORD_LENGTH && pw.length <= 128
    && /[A-Za-z]/.test(pw) && /[0-9]/.test(pw);
}

// ---------- Identity (email or phone) ----------
// Sign-in supports either an email address or a phone number as the
// account identity. classifyIdentity() takes whatever the person typed
// into the single "email or phone" field and figures out which one it is
// and normalizes it, so the rest of the code can treat it uniformly.
function normalizeEmail(v) {
  return String(v || '').trim().toLowerCase();
}
function isValidEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}
function normalizePhone(v) {
  const raw = String(v || '').trim();
  const hasPlus = raw.startsWith('+');
  const digits = raw.replace(/\D/g, '');
  return digits ? (hasPlus ? '+' + digits : digits) : '';
}
function isValidPhone(v) {
  // Loose E.164-ish check: optional leading +, 7–15 digits total.
  return /^\+?[0-9]{7,15}$/.test(v);
}
function classifyIdentity(raw) {
  const value = String(raw || '').trim();
  if (!value) return null;
  if (value.includes('@')) {
    const email = normalizeEmail(value);
    return isValidEmail(email) ? { field: 'email', value: email } : null;
  }
  const phone = normalizePhone(value);
  return isValidPhone(phone) ? { field: 'phone', value: phone } : null;
}

function makeToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashSessionToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function cookieFlags(maxAgeSeconds) {
  const parts = [
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  if (COOKIE_SECURE) parts.push('Secure');
  return parts.join('; ');
}

function setSessionCookie(res, token, maxAgeSeconds = SESSION_TTL_MS / 1000) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token ? encodeURIComponent(token) : ''}; ${cookieFlags(maxAgeSeconds)}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; ${cookieFlags(0)}`);
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) {
      try { return decodeURIComponent(v.join('=')); } catch (_) { return null; }
    }
  }
  return null;
}

// ⚠️ SCHEMA CHANGE — this table used to store the raw session token in a
// `token` column; it now stores a SHA-256 hash in `token_hash` instead (so
// a leaked DB dump can't be replayed as live sessions directly). This is a
// breaking change: deploying this file against the old schema will make
// every login/session check fail with "column token_hash does not exist".
// Run once, before deploying this file:
//   CREATE EXTENSION IF NOT EXISTS pgcrypto; -- provides digest()
//   ALTER TABLE sessions ADD COLUMN token_hash text;
//   UPDATE sessions SET token_hash = encode(digest(token, 'sha256'), 'hex');
//   ALTER TABLE sessions ALTER COLUMN token_hash SET NOT NULL;
//   ALTER TABLE sessions ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);
// The UPDATE backfills existing sessions so people don't get logged out by
// this migration. Once you've confirmed the app is running fine on
// token_hash (give it a few days), you can drop the now-unused column:
//   ALTER TABLE sessions DROP COLUMN token;
async function createSession(token, userId) {
  const tokenHash = hashSessionToken(token);
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const { error } = await supabase.from('sessions').insert({ token_hash: tokenHash, user_id: userId, expires_at: expiresAt });
  if (error) throw error;
  return expiresAt;
}

async function getSessionUserId(token) {
  if (!token || token.length > 256) return null;
  const tokenHash = hashSessionToken(token);
  const { data, error } = await supabase
    .from('sessions').select('user_id, expires_at').eq('token_hash', tokenHash).maybeSingle();
  if (error) throw error;
  if (!data) return null;
  const expires = new Date(data.expires_at).getTime();
  if (!Number.isFinite(expires) || expires <= Date.now()) {
    await supabase.from('sessions').delete().eq('token_hash', tokenHash);
    return null;
  }
  if (expires - Date.now() < SESSION_RENEW_THRESHOLD_MS) {
    const newExpiry = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    await supabase.from('sessions').update({ expires_at: newExpiry }).eq('token_hash', tokenHash);
  }
  return data.user_id;
}

async function deleteSession(token) {
  if (!token) return;
  await supabase.from('sessions').delete().eq('token_hash', hashSessionToken(token));
}

// ---------- Live updates (Server-Sent Events) ----------
// Maps a userId to the set of open SSE connections for that person
// (they might have the app open on more than one device/tab at once).
const sseClients = new Map(); // userId -> Set<res>

const MAX_SSE_PER_USER = 5;
function addSseClient(userId, res) {
  if (!sseClients.has(userId)) sseClients.set(userId, new Set());
  const set = sseClients.get(userId);
  set.add(res);
  // Cap open streams per user; drop the oldest ones first.
  while (set.size > MAX_SSE_PER_USER) {
    const oldest = set.values().next().value;
    set.delete(oldest);
    try { oldest.end(); } catch (_) { /* already closed */ }
  }
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

function httpError(statusCode, message) {
  const e = new Error(message);
  e.statusCode = statusCode;
  return e;
}

// Rejects with an error carrying .statusCode (400 invalid JSON, 413 too large)
// so the top-level handler can answer with the right status instead of 500.
function readBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const tooLarge = () => httpError(413, `Request too large (max ${Math.floor(maxBytes / 1024)}KB)`);
    const declared = parseInt(req.headers['content-length'] || '', 10);
    if (Number.isFinite(declared) && declared > maxBytes) {
      req.pause();
      return reject(tooLarge());
    }
    const chunks = [];
    let bytes = 0;
    let finished = false;
    req.on('data', chunk => {
      if (finished) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        finished = true;
        chunks.length = 0;
        req.pause(); // stop reading; the socket is closed after the 413 is sent
        reject(tooLarge());
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (finished) return;
      finished = true;
      if (!chunks.length) return resolve({});
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {});
      } catch (_) {
        reject(httpError(400, 'Invalid JSON'));
      }
    });
    req.on('error', err => {
      if (!finished) { finished = true; reject(err); }
    });
  });
}

function sendJSON(res, status, obj, extraHeaders = {}) {
  const bodyStr = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(bodyStr),
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(bodyStr);
}

function getAuthToken(req) {
  const token = getCookie(req, SESSION_COOKIE);
  return token && token.length <= 256 ? token : null;
}

function isMutatingMethod(method) {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
}

function getClientIp(req) {
  if (TRUST_PROXY) {
    const parts = String(req.headers['x-forwarded-for'] || '').split(',').map(v => v.trim()).filter(Boolean);
    if (parts.length) return parts[Math.max(0, parts.length - TRUSTED_PROXY_HOPS)];
  }
  return req.socket.remoteAddress || 'unknown';
}

// Small in-process rate limiter. It is intentionally conservative and is a
// baseline, not a replacement for edge/WAF rate limiting in production.
const rateBuckets = new Map();
function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  const existing = rateBuckets.get(key);
  if (!existing || existing.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  existing.count += 1;
  return existing.count <= limit;
}
function clearRateLimit(key) {
  rateBuckets.delete(key);
}
// True if the bucket has already reached `limit` (does NOT count this call).
// Pair with rateLimit() on failures only, so successes never lock anyone out.
function rateLimitBlocked(key, limit) {
  const b = rateBuckets.get(key);
  return !!b && b.resetAt > Date.now() && b.count >= limit;
}

function validateOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // same-origin form/fetches often omit Origin
  const host = req.headers.host;
  if (!host) return false;
  try {
    const originUrl = new URL(origin);
    const expectedProtocol = (IS_PRODUCTION || req.headers['x-forwarded-proto'] === 'https') ? 'https:' : 'http:';
    return originUrl.host === host && originUrl.protocol === expectedProtocol;
  } catch (_) {
    return false;
  }
}

function pairKey(id1, id2) {
  return [id1, id2].sort().join('::');
}

function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: ${SUPABASE_ORIGIN}; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';`);
  if (IS_PRODUCTION || TRUST_PROXY) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
}

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
  // Lifestyle details are private-by-default (not in toPublicUser) but the
  // owner must get them back, or the Details screen, profile pills and the
  // profile-strength score can never see what they saved.
  const lifestyle = {
    education: row.education || '',
    heightCm: row.height_cm == null ? null : row.height_cm,
    exercise: row.exercise || '',
    drinking: row.drinking || '',
    smoking: row.smoking || '',
    religion: row.religion || '',
    political: row.political_views || '',
    children: row.children || '',
    wantsChildren: row.wants_children || '',
  };
  const profileData = { ...pub, questionnaire, ...lifestyle };
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
    ...lifestyle,
    profileCompletion: profileStrength.percentage,
    profileStrength,
  };
}

// Only the columns toPublicUser/matching actually read. Used for every query
// that loads OTHER people, so password hashes/salts/contact info never get
// pulled into memory for them.
const PUBLIC_USER_COLUMNS = 'id, name, age, bio, location, show_location, country, gender, tags, photo_url, gallery_urls, created_at, languages, dating_intentions, prompts, questionnaire, verified, discoverable, interested_in';
const DISCOVER_POOL_LIMIT = 2000;
const DISCOVER_MAX_CANDIDATES = 300;

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

// Live updates over Server-Sent Events. EventSource can't send custom
// headers, so this authenticates with the HttpOnly session cookie (same-origin).
async function handleStream(req, res) {
  const token = getAuthToken(req);
  const user = token ? await getUserByToken(token) : null;
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'text/plain' });
    return res.end('Not authenticated');
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 3000\n\n');

  addSseClient(user.id, res);

  const heartbeat = setInterval(() => {
    try { res.write(': keep-alive\n\n'); } catch (e) { /* ignore */ }
  }, 20000);

  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    clearInterval(heartbeat);
    removeSseClient(user.id, res);
  };
  req.on('close', cleanup);
  res.on('close', cleanup);
}

const MAX_TAGS = 60;
const MAX_TAG_CHARS = 40;
function parseTags(tags) {
  let list = [];
  if (Array.isArray(tags)) list = tags;
  else if (typeof tags === 'string') list = tags.split(',');
  const seen = new Set();
  const out = [];
  for (const t of list) {
    if (typeof t !== 'string') continue;
    const clean = t.trim().replace(/\s+/g, ' ').slice(0, MAX_TAG_CHARS);
    const k = clean.toLowerCase();
    if (!clean || seen.has(k)) continue;
    seen.add(k);
    out.push(clean);
    if (out.length >= MAX_TAGS) break;
  }
  return out;
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

// ⚠️ SCHEMA CHANGE — sign-in now accepts either an email or a phone number
// as the account identity, and forgot-password needs somewhere to store
// reset codes. Run this once, before deploying this file:
//   ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
//   ALTER TABLE users ADD COLUMN IF NOT EXISTS phone text UNIQUE;
//   CREATE TABLE IF NOT EXISTS password_resets (
//     id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
//     user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
//     code_hash text NOT NULL,
//     expires_at timestamptz NOT NULL,
//     created_at timestamptz NOT NULL DEFAULT now()
//   );
//   CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);
async function handleRegister(req, res) {
  if (!rateLimit(`register:${getClientIp(req)}`, 10, 60 * 60 * 1000)) {
    return sendJSON(res, 429, { error: 'Too many sign-ups from this network. Please try again later.' });
  }
  const body = await readBody(req, MAX_TEXT_BYTES);
  const { name, identity, password, age, bio, location, country, gender, tags } = body;

  if (!name || !identity || !password) {
    return sendJSON(res, 400, { error: 'name, an email or phone number, and password are required' });
  }
  if (!isValidPassword(password)) {
    return sendJSON(res, 400, { error: 'Password must be at least 8 characters and include both letters and numbers' });
  }
  const cleanName = String(name).trim().replace(/\s+/g, ' ').slice(0, MAX_NAME_CHARS);
  if (!cleanName) {
    return sendJSON(res, 400, { error: 'A valid name is required' });
  }
  const id = classifyIdentity(identity);
  if (!id) {
    return sendJSON(res, 400, { error: 'Enter a valid email address or phone number' });
  }
  if (!gender || !VALID_GENDERS.includes(gender)) {
    return sendJSON(res, 400, { error: 'A valid gender selection is required' });
  }
  const ageNum = Number(age);
  if (!isValidAge(ageNum)) {
    return sendJSON(res, 400, { error: 'You must be 18 or older to join. Enter a valid age (18-100).' });
  }

  const { data: existing, error: existingErr } = await supabase
    .from('users').select('id').eq(id.field, id.value).maybeSingle();
  if (existingErr) throw existingErr;
  if (existing) {
    return sendJSON(res, 409, { error: `An account with that ${id.field === 'email' ? 'email' : 'phone number'} already exists` });
  }

  const { salt, hash } = await hashPassword(password);
  const { data: created, error: insertErr } = await supabase
    .from('users')
    .insert({
      name: cleanName,
      age: ageNum,
      bio: String(bio || '').trim().slice(0, MAX_BIO_CHARS),
      location: String(location || '').trim().slice(0, MAX_LOCATION_CHARS),
      country: String(country || '').trim().slice(0, MAX_COUNTRY_CHARS),
      gender,
      tags: parseTags(tags),
      email: id.field === 'email' ? id.value : null,
      phone: id.field === 'phone' ? id.value : null,
      password_salt: salt,
      password_hash: hash,
    })
    .select()
    .single();
  if (insertErr) {
    // Unique-constraint race: two sign-ups for the same email/phone at once.
    if (insertErr.code === '23505') {
      return sendJSON(res, 409, { error: `An account with that ${id.field === 'email' ? 'email' : 'phone number'} already exists` });
    }
    throw insertErr;
  }

  const token = makeToken();
  await createSession(token, created.id);
  setSessionCookie(res, token);

  sendJSON(res, 201, { user: toOwnUser(created) });
}

async function handleLogin(req, res) {
  const body = await readBody(req, MAX_TEXT_BYTES);
  const { identity, password } = body;
  if (!identity || !password) {
    return sendJSON(res, 400, { error: 'An email/phone number and password are required' });
  }
  const id = classifyIdentity(identity);
  // Same generic error whether the identity is malformed, unknown, or the
  // password is wrong — never confirm or deny that an account exists.
  const genericFail = () => sendJSON(res, 401, { error: 'Invalid email/phone or password' });
  if (!id) return genericFail();

  // Per-identity brute-force lockout, on top of the per-IP rate limit
  // applied to every /api/login request. This catches slow, distributed
  // credential-stuffing attempts against one specific account that a
  // per-IP limit alone wouldn't.
  const lockKey = `loginfail:${id.field}:${id.value}`;
  // Only FAILED attempts count toward the lockout, so normal logins never
  // lock a person out of their own account.
  if (rateLimitBlocked(lockKey, 8)) {
    return sendJSON(res, 429, { error: 'Too many failed attempts. Please try again later.' });
  }

  const { data: user, error } = await supabase
    .from('users').select('*').eq(id.field, id.value).maybeSingle();
  if (error) throw error;
  let passwordOk = false;
  if (user) {
    passwordOk = await verifyPassword(password, user.password_salt, user.password_hash);
  } else {
    // Burn the same hashing time so unknown accounts can't be told apart by timing.
    const dummy = await dummyCredsPromise;
    if (dummy) await verifyPassword(String(password), dummy.salt, dummy.hash);
  }
  if (!passwordOk) {
    rateLimit(lockKey, 8, 15 * 60 * 1000);
    return genericFail();
  }
  clearRateLimit(lockKey); // successful login — forget prior failures

  // Transparently upgrade legacy PBKDF2 hashes to scrypt after a successful
  // login, so existing users do not need to reset their passwords.
  if (!String(user.password_hash || '').startsWith('scrypt$')) {
    const upgraded = await hashPassword(password);
    await supabase.from('users').update({ password_salt: upgraded.salt, password_hash: upgraded.hash }).eq('id', user.id);
    user.password_salt = upgraded.salt;
    user.password_hash = upgraded.hash;
  }

  const token = makeToken();
  await createSession(token, user.id);
  setSessionCookie(res, token);
  sendJSON(res, 200, { user: toOwnUser(user) });
}

// ---------- Account recovery (forgot password) ----------
// No email/SMS provider is wired up yet, so the reset code is written to
// the server console instead of actually being emailed/texted. Everything
// else (hashed, time-limited, single-use codes; generic responses that
// never reveal whether an account exists; session invalidation on reset)
// is the real, production-shaped flow — swap in a provider call where
// noted below and this is done.
function hashResetCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

// Delivers the reset code. Plug in your email/SMS provider here, or set
// RESET_DELIVERY_WEBHOOK_URL to a service that receives
// { channel: 'email'|'phone', to, code, expiresInMinutes } and sends it
// (optionally authenticated with RESET_DELIVERY_WEBHOOK_SECRET as a Bearer token).
// In production the code is NEVER written to the logs.
async function deliverResetCode(id, code) {
  const hook = process.env.RESET_DELIVERY_WEBHOOK_URL;
  if (hook) {
    try {
      const headers = { 'Content-Type': 'application/json' };
      if (process.env.RESET_DELIVERY_WEBHOOK_SECRET) headers.Authorization = `Bearer ${process.env.RESET_DELIVERY_WEBHOOK_SECRET}`;
      const resp = await fetch(hook, {
        method: 'POST',
        headers,
        body: JSON.stringify({ channel: id.field, to: id.value, code, expiresInMinutes: 15 }),
        signal: typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(8000) : undefined,
      });
      if (!resp.ok) console.error('[password reset] delivery webhook returned HTTP', resp.status);
    } catch (e) {
      console.error('[password reset] delivery webhook failed:', e && e.message ? e.message : e);
    }
    return;
  }
  if (!IS_PRODUCTION) {
    console.log(`[password reset:dev] code for ${id.field} ${id.value}: ${code}`);
    return;
  }
  console.error('[password reset] no delivery configured (set RESET_DELIVERY_WEBHOOK_URL). Code was NOT sent.');
}

async function handleForgotPassword(req, res) {
  const body = await readBody(req, MAX_TEXT_BYTES);
  const id = classifyIdentity(body.identity);
  const generic = { ok: true, message: 'If an account exists for that email or phone number, a reset code has been sent.' };
  if (!id) return sendJSON(res, 200, generic); // never confirm/deny format validity either
  // Max 3 codes per identity per 15 min: stops code spam, and stops an
  // attacker from re-issuing codes to reset the guess counter.
  if (!rateLimit(`forgot:${id.field}:${id.value}`, 3, 15 * 60 * 1000)) return sendJSON(res, 200, generic);

  const { data: user, error } = await supabase
    .from('users').select('id').eq(id.field, id.value).maybeSingle();
  if (error) throw error;
  if (user) {
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    // Invalidate any earlier unused codes for this user first.
    await supabase.from('password_resets').delete().eq('user_id', user.id);
    const { error: insertErr } = await supabase.from('password_resets').insert({
      user_id: user.id, code_hash: hashResetCode(code), expires_at: expiresAt,
    });
    if (insertErr) throw insertErr;
    await deliverResetCode(id, code);
  }
  sendJSON(res, 200, generic);
}

async function handleResetPassword(req, res) {
  const body = await readBody(req, MAX_TEXT_BYTES);
  const { identity, code, newPassword } = body;
  const id = classifyIdentity(identity);
  const genericFail = () => sendJSON(res, 400, { error: 'Invalid or expired code' });
  if (!id || !code || !newPassword) return genericFail();
  if (!isValidPassword(newPassword)) {
    return sendJSON(res, 400, { error: 'Password must be at least 8 characters and include both letters and numbers' });
  }

  // Per-account guess limit (independent of IP, so spoofed/rotating IPs don't
  // help): 5 wrong codes and the pending code is destroyed.
  const attemptKey = `resetfail:${id.field}:${id.value}`;
  if (rateLimitBlocked(attemptKey, 5)) {
    return sendJSON(res, 429, { error: 'Too many attempts. Please request a new code later.' });
  }

  const { data: user, error } = await supabase
    .from('users').select('id').eq(id.field, id.value).maybeSingle();
  if (error) throw error;
  if (!user) {
    rateLimit(attemptKey, 5, 15 * 60 * 1000);
    return genericFail();
  }

  const { data: reset, error: resetErr } = await supabase
    .from('password_resets').select('*').eq('user_id', user.id).eq('code_hash', hashResetCode(String(code).trim())).maybeSingle();
  if (resetErr) throw resetErr;
  if (!reset || new Date(reset.expires_at).getTime() <= Date.now()) {
    rateLimit(attemptKey, 5, 15 * 60 * 1000);
    if (rateLimitBlocked(attemptKey, 5)) {
      await supabase.from('password_resets').delete().eq('user_id', user.id);
    }
    return genericFail();
  }
  clearRateLimit(attemptKey);

  const { salt, hash } = await hashPassword(newPassword);
  await supabase.from('users').update({ password_salt: salt, password_hash: hash }).eq('id', user.id);
  await supabase.from('password_resets').delete().eq('user_id', user.id);
  // Resetting a password is a strong signal something was wrong — sign the
  // account out everywhere so a compromised session can't linger.
  await supabase.from('sessions').delete().eq('user_id', user.id);

  sendJSON(res, 200, { ok: true });
}

async function handleMe(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  sendJSON(res, 200, { user: toOwnUser(user) });
}

async function handleLogout(req, res) {
  const token = getAuthToken(req);
  if (token) await deleteSession(token);
  clearSessionCookie(res);
  sendJSON(res, 200, { ok: true });
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
    return sendJSON(res, 400, { error: 'New password must be at least 8 characters and include both letters and numbers' });
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

  // Clean up everything that references this account. Messages are removed by
  // sender/recipient (not via current matches) so messages left behind by an
  // earlier unmatch or block are deleted too. Every step is checked: if one
  // fails we stop with an error instead of claiming the account was deleted.
  //
  // Reports are intentionally NOT deleted here, so moderators keep evidence
  // against someone who deletes their account right after abusing others.
  // For that to hold, drop the cascading foreign keys once (admin UI already
  // shows "(deleted user)"):
  //   ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_reporter_id_fkey;
  //   ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_reported_id_fkey;
  // Until then the DB cascade still removes them, same as before.
  const uid = user.id;
  const cleanupSteps = [
    () => supabase.from('messages').delete().or(`from_user_id.eq.${uid},to_user_id.eq.${uid}`),
    () => supabase.from('matches').delete().or(`user_id_1.eq.${uid},user_id_2.eq.${uid}`),
    () => supabase.from('likes').delete().or(`from_user_id.eq.${uid},to_user_id.eq.${uid}`),
    () => supabase.from('blocks').delete().or(`blocker_id.eq.${uid},blocked_id.eq.${uid}`),
    () => supabase.from('password_resets').delete().eq('user_id', uid),
    () => supabase.from('sessions').delete().eq('user_id', uid),
  ];
  for (const run of cleanupSteps) {
    const { error: stepErr } = await run();
    if (stepErr) throw stepErr;
  }

  // Best-effort — an orphaned Storage file isn't worth failing the deletion over.
  await removeFromPhotosBucket(user.photo_url);
  for (const url of (user.gallery_urls || [])) await removeFromPhotosBucket(url);

  const { error: deleteErr } = await supabase.from('users').delete().eq('id', uid);
  if (deleteErr) throw deleteErr;

  clearSessionCookie(res);
  sendJSON(res, 200, { ok: true });
}

async function handleUpdateProfile(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const updates = {};
  if (body.name !== undefined) {
    const cleanName = String(body.name).trim().replace(/\s+/g, ' ').slice(0, MAX_NAME_CHARS);
    if (!cleanName) return sendJSON(res, 400, { error: 'Name cannot be empty' });
    updates.name = cleanName;
  }
  if (body.age !== undefined && body.age !== null && String(body.age).trim() !== '') {
    const a = Number(body.age);
    if (!isValidAge(a)) return sendJSON(res, 400, { error: 'Age must be a whole number between 18 and 100' });
    updates.age = a;
  } else if (body.age !== undefined && isValidAge(user.age)) {
    return sendJSON(res, 400, { error: 'Age is required (18 or older)' });
  }
  if (body.bio !== undefined) updates.bio = String(body.bio).trim().slice(0, MAX_BIO_CHARS);
  if (body.location !== undefined) updates.location = String(body.location).trim().slice(0, MAX_LOCATION_CHARS);
  if (body.country !== undefined) updates.country = String(body.country).trim().slice(0, MAX_COUNTRY_CHARS);
  // ⚠️ SCHEMA CHANGE — discoverable/show_location are new boolean columns.
  // This isn't in the original setup SQL — add it once via:
  //   ALTER TABLE users ADD COLUMN discoverable boolean NOT NULL DEFAULT true;
  //   ALTER TABLE users ADD COLUMN show_location boolean NOT NULL DEFAULT true;
  // Until that migration runs, these two lines will make every profile
  // update fail (Postgres will reject the unknown columns).
  if (body.discoverable !== undefined) updates.discoverable = body.discoverable === true;
  if (body.showLocation !== undefined) updates.show_location = body.showLocation === true;
  if (body.gender !== undefined && VALID_GENDERS.includes(body.gender)) updates.gender = body.gender;
  if (body.orientation !== undefined) {
    if (body.orientation === null || body.orientation === '') updates.orientation = null;
    else if (VALID_ORIENTATIONS.includes(body.orientation)) updates.orientation = body.orientation;
  }
  if (body.interestedIn !== undefined && Array.isArray(body.interestedIn)) {
    updates.interested_in = [...new Set(body.interestedIn.filter(v => VALID_INTERESTED_IN.includes(v)))];
  }
  if (body.tags !== undefined) updates.tags = parseTags(body.tags);

  // Extended profile fields (see PROFILE_COMPLETION_FIELDS / matchesFilters
  // on the frontend). Each is validated against the same option lists used
  // by the "complete your profile" screen and the Discover filter panel, so
  // stored values always line up with what the filters check against.
  const ONE_WORD_SCALE = ['never', 'sometimes', 'often'];
  if (body.languages !== undefined) {
    updates.languages = Array.isArray(body.languages)
      ? body.languages.map(l => (typeof l === 'string' ? l.trim().slice(0, 40) : '')).filter(Boolean).slice(0, 10)
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
    // DB check constraint allows NULL or one of the five values, but not ''
    // — so an empty string (meaning "unset") must be stored as NULL.
    updates.political_views = body.political === '' ? null : body.political;
  }
  if (body.children !== undefined && ['', 'has', 'none', 'unspecified'].includes(body.children)) updates.children = body.children;
  if (body.wantsChildren !== undefined && ['', 'yes', 'no', 'maybe'].includes(body.wantsChildren)) updates.wants_children = body.wantsChildren;
  if (body.datingIntentions !== undefined) {
    const allowed = ['casual', 'relationship', 'marriage', 'friendship', 'not_sure'];
    updates.dating_intentions = Array.isArray(body.datingIntentions)
      ? body.datingIntentions.filter(v => allowed.includes(v))
      : [];
  }

  if (!Object.keys(updates).length) return sendJSON(res, 200, { user: toOwnUser(user) });
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
  const body = await readBody(req, MAX_TEXT_BYTES);
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
  const body = await readBody(req, MAX_TEXT_BYTES);
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

// Strips location/camera metadata (EXIF GPS etc.) server-side, so privacy
// doesn't depend on the client having re-encoded the image. JPEG and PNG are
// handled; anything malformed is returned unchanged rather than corrupted.
function stripJpegMetadata(buf) {
  if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return buf;
  const out = [buf.slice(0, 2)];
  let i = 2;
  while (i + 4 <= buf.length) {
    if (buf[i] !== 0xff) return buf;
    const marker = buf[i + 1];
    if (marker === 0xff) { i++; continue; }
    if (marker === 0xda) { out.push(buf.slice(i)); return Buffer.concat(out); } // start of scan: rest is image data
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { out.push(buf.slice(i, i + 2)); i += 2; continue; }
    const len = buf.readUInt16BE(i + 2);
    if (len < 2 || i + 2 + len > buf.length) return buf;
    const drop = marker === 0xe1 || marker === 0xed || marker === 0xfe; // EXIF/XMP, IPTC, comments
    if (!drop) out.push(buf.slice(i, i + 2 + len));
    i += 2 + len;
  }
  return buf;
}

function stripPngMetadata(buf) {
  if (buf.length < 8) return buf;
  const out = [buf.slice(0, 8)];
  let i = 8;
  let sawEnd = false;
  while (i + 12 <= buf.length) {
    const len = buf.readUInt32BE(i);
    const type = buf.toString('latin1', i + 4, i + 8);
    const end = i + 12 + len;
    if (end > buf.length) return buf;
    if (!['eXIf', 'tEXt', 'zTXt', 'iTXt'].includes(type)) out.push(buf.slice(i, end));
    i = end;
    if (type === 'IEND') { sawEnd = true; break; }
  }
  return sawEnd ? Buffer.concat(out) : buf;
}

function stripImageMetadata(buffer, mimeType) {
  try {
    if (mimeType === 'image/jpeg') return stripJpegMetadata(buffer);
    if (mimeType === 'image/png') return stripPngMetadata(buffer);
  } catch (_) { /* fall through to the original bytes */ }
  return buffer;
}

function hasValidImageSignature(buffer, mimeType) {
  if (mimeType === 'image/jpeg') return buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  if (mimeType === 'image/png') return buffer.length >= 8 && buffer.slice(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
  if (mimeType === 'image/gif') return buffer.length >= 6 && (buffer.slice(0, 6).toString() === 'GIF87a' || buffer.slice(0, 6).toString() === 'GIF89a');
  if (mimeType === 'image/webp') return buffer.length >= 12 && buffer.slice(0, 4).toString() === 'RIFF' && buffer.slice(8, 12).toString() === 'WEBP';
  return false;
}

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
  if (buffer.length > 5 * 1024 * 1024) return { error: 'Image too large (max 5MB)' };
  if (!hasValidImageSignature(buffer, mimeType)) return { error: 'Invalid image data' };
  return { mimeType, ext, buffer: stripImageMetadata(buffer, mimeType) };
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
    return sendJSON(res, err.statusCode || 413, { error: err.message });
  }

  const decoded = decodeImageDataUrl(body.photo);
  if (decoded.error) return sendJSON(res, 400, { error: decoded.error });

  const photoUrl = await uploadToPhotosBucket(user.id, 'profile', decoded);

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ photo_url: photoUrl }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  // Remove the replaced profile photo so old pictures don't stay public.
  if (user.photo_url && user.photo_url !== photoUrl) await removeFromPhotosBucket(user.photo_url);

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
    return sendJSON(res, err.statusCode || 413, { error: err.message });
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
    return sendJSON(res, err.statusCode || 413, { error: err.message });
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
    body = await readBody(req, MAX_TEXT_BYTES);
  } catch (err) {
    return sendJSON(res, err.statusCode || 413, { error: err.message });
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
  if (!isValidAge(other.age)) return false; // 18+ only, never show profiles without a valid age
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
  if (!isValidAge(user.age)) {
    return sendJSON(res, 403, { error: 'Add your age (18 or older) to your profile to use Discover.' });
  }

  const { data: swiped, error: swipedErr } = await supabase
    .from('likes').select('to_user_id, direction').eq('from_user_id', user.id);
  if (swipedErr) throw swipedErr;
  const swipedIds = new Set((swiped || []).map(l => l.to_user_id));
  const likedIds = new Set((swiped || []).filter(l => l.direction === 'like').map(l => l.to_user_id));

  const blockedIds = await getBlockedIdSet(user.id);

  // select('*') here (rather than a hand-picked column list) is deliberate:
  // toPublicUser() already controls exactly what's exposed to the client,
  // so narrowing this query doesn't add any real safety, but it did cause a
  // real bug — a previous column allowlist here quietly omitted
  // `discoverable`/`show_location`, which silently broke both privacy
  // toggles (see toPublicUser and isEligibleCandidate above). Selecting
  // everything means a new column can never be forgotten here again.
  // Bounded, column-limited pool (newest first) instead of the whole table
  // with password hashes: keeps memory/latency flat as the user base grows.
  const { data: allUsers, error: usersErr } = await supabase
    .from('users').select(PUBLIC_USER_COLUMNS)
    .neq('id', user.id)
    .order('created_at', { ascending: false })
    .limit(DISCOVER_POOL_LIMIT);
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
    .slice(0, DISCOVER_MAX_CANDIDATES)
    .map(toCandidate);

  // Profiles the current user already liked. These are intentionally returned
  // separately so Discover can show them without putting them back into the
  // swipe/like queue.
  const likedProfiles = eligibleUsers
    .filter(u => likedIds.has(u.id))
    .slice(0, DISCOVER_MAX_CANDIDATES)
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

  if (typeof targetUserId !== 'string' || !targetUserId || !['like', 'pass'].includes(direction)) {
    return sendJSON(res, 400, { error: 'targetUserId and direction (like|pass) are required' });
  }

  const { data: targetUser, error: targetErr } = await supabase
    .from('users').select('id, gender, age, discoverable, interested_in').eq('id', targetUserId).maybeSingle();
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

  // A like must respect the same rules as Discover (18+, discoverable,
  // mutual gender/interest preferences) — except liking back someone who
  // already liked you, which is how "Likes You" works.
  if (direction === 'like') {
    if (!isValidAge(user.age)) {
      return sendJSON(res, 403, { error: 'Add your age (18 or older) to your profile first.' });
    }
    if (!isEligibleCandidate(user, targetUser, new Set())) {
      const { data: theyLikedMe, error: theyErr } = await supabase
        .from('likes').select('id').eq('from_user_id', targetUserId).eq('to_user_id', user.id).eq('direction', 'like').maybeSingle();
      if (theyErr) throw theyErr;
      if (!theyLikedMe) return sendJSON(res, 403, { error: 'This interaction is unavailable.' });
    }
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
        // 23505 = both people liked at the same instant and the other request
        // created the match first; it's still a match, just don't notify twice.
        if (matchInsertErr && matchInsertErr.code !== '23505') throw matchInsertErr;
        matched = true;
        if (!matchInsertErr) pushEventToUser(targetUserId, 'match', { matchKey, withUserId: user.id });
      }
    }
  }

  sendJSON(res, 200, { matched, matchKey });
}

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
    .from('users').select(PUBLIC_USER_COLUMNS).in('id', blockedIds);
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
    .from('users').select(PUBLIC_USER_COLUMNS).in('id', visibleAdmirerIds);
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

  // Batched: one query for the other people, one for unread counts, and one
  // tiny LIMIT 1 query per match (in parallel) for the last message — instead
  // of loading every message of every match one match at a time.
  const rows = matchRows || [];
  const otherIds = rows.map(m => (m.user_id_1 === user.id ? m.user_id_2 : m.user_id_1));
  const keys = rows.map(m => m.key);

  const othersById = new Map();
  if (otherIds.length) {
    const { data: others, error: othersErr } = await supabase
      .from('users').select(PUBLIC_USER_COLUMNS).in('id', otherIds);
    if (othersErr) throw othersErr;
    for (const o of others || []) othersById.set(o.id, o);
  }

  const unreadByKey = new Map();
  if (keys.length) {
    const { data: unreadRows, error: unreadErr } = await supabase
      .from('messages').select('match_key').in('match_key', keys).eq('to_user_id', user.id).eq('read', false);
    if (unreadErr) throw unreadErr;
    for (const r of unreadRows || []) unreadByKey.set(r.match_key, (unreadByKey.get(r.match_key) || 0) + 1);
  }

  const lastMessages = await Promise.all(rows.map(async m => {
    const { data, error: lastErr } = await supabase
      .from('messages').select('text, from_user_id, created_at')
      .eq('match_key', m.key).order('created_at', { ascending: false }).limit(1);
    if (lastErr) throw lastErr;
    return data && data.length ? data[0] : null;
  }));

  const results = rows.map((m, i) => {
    const other = othersById.get(otherIds[i]) || null;
    const lastMsg = lastMessages[i];
    const compat = other ? computeCompatibility(user.questionnaire, other.questionnaire) : null;
    return {
      matchKey: m.key,
      createdAt: m.created_at,
      user: other ? toPublicUser(other) : null,
      lastMessage: lastMsg ? { text: lastMsg.text, fromUserId: lastMsg.from_user_id, createdAt: lastMsg.created_at } : null,
      unread: unreadByKey.get(m.key) || 0,
      compatibility: compat ? compat.percent : null,
      compatibilityReasons: compat ? compat.reasons : [],
    };
  });

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

  const { data: newlyRead, error: readErr } = await supabase
    .from('messages')
    .update({ read: true })
    .eq('match_key', matchKey)
    .eq('to_user_id', user.id)
    .eq('read', false)
    .select('id');
  if (readErr) throw readErr;
  if (newlyRead && newlyRead.length) {
    const senderId = match.user_id_1 === user.id ? match.user_id_2 : match.user_id_1;
    pushEventToUser(senderId, 'read', { matchKey, readerId: user.id });
  }

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
  if (!rateLimit(`msg:${user.id}`, 30, 60 * 1000)) {
    return sendJSON(res, 429, { error: 'You are sending messages too quickly. Please slow down.' });
  }

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

// ---------- Typing, delete/report message, unmatch ----------
// No schema changes needed: typing is a transient SSE event, deleting a
// message removes its row, reporting a message writes to the existing
// `reports` table with a snapshot of the message text in `details`, and
// unmatching removes the `matches` row and marks both likes as 'pass'.

async function handleTyping(req, res, matchKey) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const match = await getMatchForUser(matchKey, user.id);
  if (!match) return sendJSON(res, 404, { error: 'Match not found' });
  const otherId = match.user_id_1 === user.id ? match.user_id_2 : match.user_id_1;
  pushEventToUser(otherId, 'typing', { matchKey, fromUserId: user.id });
  sendJSON(res, 200, { ok: true });
}

async function getMessageInMatch(matchKey, messageId) {
  if (!messageId || messageId.length > 64) return null;
  const { data, error } = await supabase
    .from('messages').select('*').eq('id', messageId).eq('match_key', matchKey).maybeSingle();
  if (error) throw error;
  return data;
}

async function handleDeleteMessage(req, res, matchKey, messageId) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const match = await getMatchForUser(matchKey, user.id);
  if (!match) return sendJSON(res, 404, { error: 'Match not found' });
  const msg = await getMessageInMatch(matchKey, messageId);
  if (!msg || msg.from_user_id !== user.id) {
    return sendJSON(res, 404, { error: 'Message not found' });
  }
  const { error } = await supabase.from('messages').delete().eq('id', msg.id);
  if (error) throw error;
  const otherId = match.user_id_1 === user.id ? match.user_id_2 : match.user_id_1;
  pushEventToUser(otherId, 'message_deleted', { matchKey, id: msg.id });
  sendJSON(res, 200, { deleted: true });
}

async function handleReportMessage(req, res, matchKey, messageId) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const match = await getMatchForUser(matchKey, user.id);
  if (!match) return sendJSON(res, 404, { error: 'Match not found' });
  const msg = await getMessageInMatch(matchKey, messageId);
  // You can only report messages the other person sent to you.
  if (!msg || msg.to_user_id !== user.id) {
    return sendJSON(res, 404, { error: 'Message not found' });
  }
  const body = await readBody(req, MAX_TEXT_BYTES);
  const reason = String(body.reason || '').trim().slice(0, 70);
  if (!reason) return sendJSON(res, 400, { error: 'reason is required' });
  const { error } = await supabase.from('reports').insert({
    reporter_id: user.id,
    reported_id: msg.from_user_id,
    reason: ('Message: ' + reason).slice(0, 80),
    details: ('Reported message: ' + String(msg.text || '')).slice(0, 1000),
  });
  if (error) throw error;
  sendJSON(res, 201, { reported: true });
}

async function handleUnmatch(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const matchKey = String(body.matchKey || '').trim();
  const match = matchKey ? await getMatchForUser(matchKey, user.id) : null;
  if (!match) return sendJSON(res, 404, { error: 'Match not found' });
  const otherId = match.user_id_1 === user.id ? match.user_id_2 : match.user_id_1;

  // Mark both directions as 'pass' so neither person reappears in the
  // other's Discover or Likes You, and can't instantly re-match.
  const { error: likeErr } = await supabase.from('likes').upsert([
    { from_user_id: user.id, to_user_id: otherId, direction: 'pass' },
    { from_user_id: otherId, to_user_id: user.id, direction: 'pass' },
  ], { onConflict: 'from_user_id,to_user_id' });
  if (likeErr) throw likeErr;

  const { error: matchErr } = await supabase.from('matches').delete().eq('key', matchKey);
  if (matchErr) throw matchErr;

  pushEventToUser(otherId, 'unmatch', { matchKey });
  sendJSON(res, 200, { unmatched: true });
}

// ---------- Admin: review reports ----------
// Access is limited to users listed in ADMIN_USER_IDS / ADMIN_EMAILS.
// "Dismiss" deletes the report row (no status column needed).

async function handleAdminReports(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!isAdminUser(user)) return sendJSON(res, 403, { error: 'Forbidden' });

  const { data: reports, error } = await supabase
    .from('reports').select('*').order('created_at', { ascending: false }).limit(200);
  if (error) throw error;

  const ids = [...new Set((reports || []).flatMap(r => [r.reporter_id, r.reported_id]))];
  const people = {};
  if (ids.length) {
    const { data: rows, error: usersErr } = await supabase
      .from('users').select('id, name, email, phone').in('id', ids);
    if (usersErr) throw usersErr;
    for (const u of rows || []) people[u.id] = { id: u.id, name: u.name, email: u.email || '', phone: u.phone || '' };
  }
  const counts = {};
  for (const r of reports || []) counts[r.reported_id] = (counts[r.reported_id] || 0) + 1;

  sendJSON(res, 200, {
    reports: (reports || []).map(r => ({
      id: r.id,
      reason: r.reason,
      details: r.details || '',
      createdAt: r.created_at,
      reporter: people[r.reporter_id] || { id: r.reporter_id, name: '(deleted user)', email: '', phone: '' },
      reported: people[r.reported_id] || { id: r.reported_id, name: '(deleted user)', email: '', phone: '' },
      reportsAgainstUser: counts[r.reported_id] || 0,
    })),
  });
}

async function handleAdminDismissReport(req, res, reportId) {
  const user = await requireAuth(req, res);
  if (!user) return;
  if (!isAdminUser(user)) return sendJSON(res, 403, { error: 'Forbidden' });
  if (!reportId || reportId.length > 64) return sendJSON(res, 400, { error: 'Invalid report id' });
  const { error } = await supabase.from('reports').delete().eq('id', reportId);
  if (error) throw error;
  sendJSON(res, 200, { dismissed: true });
}

// Standalone page — the data itself is only served by /api/admin/reports,
// which enforces the admin check, so this HTML is safe to serve to anyone.
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Swing — Reports</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; background: #faf5f6; color: #2a1a20; margin: 0; padding: 24px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #7a6a70; font-size: 13px; margin-bottom: 20px; }
  .card { background: #fff; border-radius: 14px; padding: 16px 18px; margin-bottom: 12px; max-width: 760px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  .top { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; }
  .reason { font-weight: 700; }
  .time { color: #7a6a70; font-size: 12px; }
  .row { font-size: 13.5px; margin-top: 8px; }
  .label { color: #7a6a70; }
  .details { background: #faf5f6; border-radius: 8px; padding: 8px 10px; margin-top: 8px; font-size: 13px; white-space: pre-wrap; word-break: break-word; }
  .badge { display: inline-block; background: #fde8ee; color: #c6284d; border-radius: 999px; padding: 1px 8px; font-size: 11.5px; font-weight: 700; margin-left: 6px; }
  button { margin-top: 12px; border: none; background: #ec4c7e; color: #fff; border-radius: 8px; padding: 8px 14px; font-weight: 600; cursor: pointer; }
  #msg { color: #7a6a70; }
</style></head><body>
<h1>Reports</h1>
<div class="sub">Newest first. Dismiss removes a report once you've handled it.</div>
<div id="msg">Loading…</div>
<div id="list"></div>
<script>
function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
function who(p) { return p.name + ' (' + (p.email || p.phone || 'no contact') + ') · ' + p.id; }
async function load() {
  var msg = document.getElementById('msg'), list = document.getElementById('list');
  list.textContent = '';
  var res = await fetch('/api/admin/reports', { credentials: 'same-origin', cache: 'no-store' });
  if (res.status === 401) { msg.textContent = 'Please sign in to Swing first, then reload this page.'; return; }
  if (res.status === 403) { msg.textContent = 'You are not an admin.'; return; }
  var data = await res.json();
  if (!res.ok) { msg.textContent = data.error || 'Failed to load'; return; }
  msg.textContent = data.reports.length ? data.reports.length + ' report(s)' : 'No reports. 🎉';
  data.reports.forEach(function (r) {
    var card = el('div', 'card');
    var top = el('div', 'top');
    top.appendChild(el('span', 'reason', r.reason));
    top.appendChild(el('span', 'time', new Date(r.createdAt).toLocaleString()));
    card.appendChild(top);
    var rep = el('div', 'row'); rep.appendChild(el('span', 'label', 'Reported: ')); rep.appendChild(document.createTextNode(who(r.reported)));
    if (r.reportsAgainstUser > 1) rep.appendChild(el('span', 'badge', r.reportsAgainstUser + ' reports'));
    card.appendChild(rep);
    var by = el('div', 'row'); by.appendChild(el('span', 'label', 'Reported by: ')); by.appendChild(document.createTextNode(who(r.reporter)));
    card.appendChild(by);
    if (r.details) card.appendChild(el('div', 'details', r.details));
    var btn = el('button', '', 'Dismiss');
    btn.onclick = async function () {
      if (!confirm('Dismiss this report?')) return;
      var d = await fetch('/api/admin/reports/' + encodeURIComponent(r.id), { method: 'DELETE', credentials: 'same-origin' });
      if (d.ok) load(); else alert('Could not dismiss');
    };
    card.appendChild(btn);
    list.appendChild(card);
  });
}
load();
</script></body></html>`;

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
<link rel="manifest" href="/manifest.webmanifest" />
<meta name="theme-color" content="#7c3aed" />
<link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png" />
<link rel="apple-touch-icon" href="/icon-maskable-512.png" />
<meta name="mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-title" content="Swing" />
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Playball&family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --maroon-950: #1e1033;
    --maroon-800: #3c1361;
    --maroon-700: #4c1d95;
    --pink-500: #8b5cf6;
    --pink-600: #7c3aed;
    --pink-100: #ede9fe;
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

  /* Shown immediately on load/refresh, removed once boot() resolves. */
  #boot-loader {
    position: fixed; inset: 0; z-index: 9999;
    display: flex; align-items: center; justify-content: center;
    background: var(--cream);
    transition: opacity 0.25s ease;
  }
  #boot-loader.boot-loader-hidden {
    opacity: 0; pointer-events: none;
  }
  #boot-loader .boot-wheel {
    width: 56px; height: 56px;
    border-radius: 50%;
    border: 5px solid var(--pink-100);
    border-top-color: var(--pink-500);
    animation: boot-spin 0.8s linear infinite;
  }
  @keyframes boot-spin {
    to { transform: rotate(360deg); }
  }
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
  .password-field-wrap { position: relative; margin-bottom: 12px; }
  .password-field-wrap input { margin-bottom: 0; padding-right: 42px; }
  .password-toggle-btn {
    position: absolute; top: 50%; right: 6px; transform: translateY(-50%);
    width: 30px; height: 30px; border: none; background: transparent;
    color: var(--muted); display: flex; align-items: center; justify-content: center; border-radius: 8px;
  }
  .password-toggle-btn:hover { background: var(--pink-100); color: var(--pink-600); }
  .password-toggle-btn.is-visible { color: var(--pink-600); }
  .auth-forgot-link { text-align: right; margin: -6px 0 14px; }
  .auth-forgot-link button { background: none; border: none; padding: 0; font-size: 12.5px; font-weight: 600; color: var(--pink-600); }
  .auth-forgot-link button:hover { text-decoration: underline; }
  #forgot-password-panel .filter-panel-body input { width: 100%; padding: 12px 14px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 12px; font-size: 14px; outline: none; }
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
  #looking-for-screen {
    display: none; min-height: 100vh; align-items: center; justify-content: center;
    background: radial-gradient(circle at 30% 20%, var(--maroon-700), var(--maroon-950) 70%);
    padding: 24px;
  }
  #looking-for-screen.visible { display: flex; }

  /* Profile-section editors open as the same bottom-sheet overlay used by
     Interests, instead of replacing the whole Profile view. Signup keeps the
     original full-screen details experience. */
  #details-screen.profile-overlay-mode,
  #looking-for-screen.profile-overlay-mode {
    position: fixed; inset: 0; z-index: 250;
    min-height: 0; padding: 0;
    align-items: flex-end; justify-content: stretch;
    background: rgba(20,5,12,0.45);
  }
  #details-screen.profile-overlay-mode .q-card,
  #looking-for-screen.profile-overlay-mode .q-card {
    position: relative; width: 100%; max-width: none; max-height: 86vh;
    margin: 0; overflow: hidden;
    border-radius: 20px 20px 0 0;
    box-shadow: 0 -12px 40px rgba(20,5,12,0.25);
    animation: profileEditorSheetIn 0.32s cubic-bezier(.32,.72,0,1);
  }
  #details-screen.profile-overlay-mode .q-header,
  #looking-for-screen.profile-overlay-mode .q-header {
    display: none;
  }
  #details-screen.profile-overlay-mode .q-card::before,
  #looking-for-screen.profile-overlay-mode .q-card::before {
    content: ''; display: block; width: 36px; height: 4px; border-radius: 3px;
    background: var(--border); margin: 10px auto 2px;
  }
  #details-screen.profile-overlay-mode .q-title,
  #looking-for-screen.profile-overlay-mode .q-title {
    padding-right: 42px;
  }
  .profile-overlay-close {
    display: none; position: absolute; top: 16px; right: 18px; z-index: 2;
    width: 32px; height: 32px; border-radius: 50%; border: none;
    background: var(--cream); color: var(--muted); align-items: center; justify-content: center;
    cursor: pointer;
  }
  #details-screen.profile-overlay-mode .profile-overlay-close,
  #looking-for-screen.profile-overlay-mode .profile-overlay-close { display: inline-flex; }
  @keyframes profileEditorSheetIn {
    from { transform: translateY(100%); opacity: .85; }
    to { transform: translateY(0); opacity: 1; }
  }
  @media (min-width: 760px) {
    #details-screen.profile-overlay-mode .q-card,
    #looking-for-screen.profile-overlay-mode .q-card {
      width: min(620px, 100%); max-height: 86vh;
      margin: 0 24px 24px auto; border-radius: 20px;
      animation-name: profileEditorPanelIn;
    }
    @keyframes profileEditorPanelIn {
      from { transform: translateX(100%); opacity: .85; }
      to { transform: translateX(0); opacity: 1; }
    }
  }
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
  .discover-category-tabs { display: flex; flex-wrap: nowrap; gap: 8px; margin-bottom: 12px; width: 100%; }
  /* Full-width row — each tab takes an equal rectangular share of the
     device width instead of a fixed-size circle bunched to one side. */
  .discover-category-tabs button {
    flex: 1 1 0; min-width: 0; width: auto; height: 46px; padding: 0;
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center; line-height: 1;
  }
  .discover-category-tabs button.active { background: var(--pink-500); border-color: var(--pink-500); }
  .filter-tabs button { display: flex; align-items: center; gap: 6px; border: 1px solid var(--border); background: white; padding: 9px 16px; border-radius: 20px; font-size: 13.5px; font-weight: 500; color: var(--muted); }
  .filter-tabs button.active { background: var(--maroon-800); color: white; border-color: var(--maroon-800); }

  .swipe-card { width: 100%; max-width: min(520px, 100%); margin: 0 auto; background: white; border-radius: 22px; overflow: hidden; box-shadow: 0 10px 40px rgba(75,20,45,0.1); }
  .swipe-photo { position: relative; aspect-ratio: 3 / 4; background-size: cover; background-position: center; display: flex; flex-direction: column; justify-content: flex-end; }
  .swipe-photo::after { content: ''; position: absolute; inset: 0; background: linear-gradient(180deg, transparent 40%, rgba(20,5,12,0.75) 100%); }
  .photo-tag { position: absolute; top: 16px; left: 16px; background: rgba(0,0,0,0.45); color: white; font-size: 12px; padding: 5px 12px; border-radius: 20px; z-index: 2; display: inline-flex; align-items: center; gap: 5px; }
  .swipe-details { position: relative; z-index: 2; padding: 20px 22px; color: white; }
  .swipe-details .name-row { display: flex; align-items: center; gap: 8px; font-size: 26px; font-weight: 700; }
  .swipe-details .meta { display: flex; gap: 14px; font-size: 12.5px; opacity: 0.9; margin: 4px 0 10px; }
  .swipe-details .meta span { display: inline-flex; align-items: center; gap: 4px; }
  .swipe-details .interest-tags-row { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 10px; }
  .swipe-details .interest-tag-pill { background: rgba(0,0,0,0.45); color: white; font-size: 11px; font-weight: 600; padding: 4px 10px; border-radius: 20px; display: inline-flex; align-items: center; gap: 5px; white-space: nowrap; }
  .swipe-details .interest-tag-pill svg { flex-shrink: 0; }
  .discover-carousel-photo .info-affordance { position: absolute; top: 12px; left: 12px; width: 26px; height: 26px; border-radius: 50%; background: rgba(0,0,0,0.45); color: white; display: flex; align-items: center; justify-content: center; z-index: 2; pointer-events: none; }
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
  .swipe-vibes-thumb { aspect-ratio: 1; border-radius: 12px; overflow: hidden; background: var(--cream); cursor: pointer; }
  .swipe-vibes-thumb img { width: 100%; height: 100%; object-fit: cover; display: block; }

  /* ---------- Photo lightbox (full-size vibes photos) ---------- */
  .photo-lightbox-overlay {
    display: none; position: fixed; inset: 0; z-index: 300;
    background: rgba(10,4,8,0.92); align-items: center; justify-content: center; padding: 40px 16px;
  }
  .photo-lightbox-overlay.visible { display: flex; }
  .photo-lightbox-overlay img {
    max-width: 100%; max-height: 100%; object-fit: contain; border-radius: 8px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .photo-lightbox-close, .photo-lightbox-nav {
    position: fixed; border: none; background: rgba(255,255,255,0.12); color: white;
    border-radius: 50%; display: flex; align-items: center; justify-content: center;
    cursor: pointer; backdrop-filter: blur(2px);
  }
  .photo-lightbox-close:hover, .photo-lightbox-nav:hover { background: rgba(255,255,255,0.22); }
  .photo-lightbox-close { top: 18px; right: 18px; width: 40px; height: 40px; }
  .photo-lightbox-nav { top: 50%; transform: translateY(-50%); width: 48px; height: 48px; }
  .photo-lightbox-prev { left: 18px; }
  .photo-lightbox-next { right: 18px; }
  .photo-lightbox-nav:disabled { opacity: 0.25; cursor: default; }
  .photo-lightbox-counter {
    position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
    color: white; font-size: 12.5px; opacity: 0.8; background: rgba(255,255,255,0.12);
    padding: 4px 12px; border-radius: 999px;
  }
  @media (max-width: 560px) {
    .photo-lightbox-nav { width: 40px; height: 40px; }
  }

  /* ---------- Profile photo crop step ---------- */
  .photo-crop-overlay {
    display: none; position: fixed; inset: 0; z-index: 320;
    background: rgba(10,4,8,0.92); align-items: center; justify-content: center; padding: 20px;
  }
  .photo-crop-overlay.visible { display: flex; }
  .photo-crop-modal {
    width: 100%; max-width: 420px; background: var(--card); border-radius: 18px;
    padding: 18px; display: flex; flex-direction: column; gap: 12px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.4);
  }
  .photo-crop-header { font-weight: 700; font-size: 16px; text-align: center; }
  /* Fixed 3:4 stage. The image inside is absolutely positioned and moved/
     scaled via a JS-driven transform (drag to pan, wheel/pinch to zoom) —
     whatever's visible inside this box on confirm is exactly what gets
     uploaded, so every profile photo ends up the same 3:4 portrait shape. */
  .photo-crop-stage {
    position: relative; width: 100%; aspect-ratio: 3 / 4; background: #000;
    border-radius: 12px; overflow: hidden; touch-action: none; cursor: grab;
  }
  .photo-crop-stage.dragging { cursor: grabbing; }
  .photo-crop-stage img {
    position: absolute; top: 0; left: 0; max-width: none; max-height: none;
    will-change: transform; user-select: none; -webkit-user-drag: none; pointer-events: none;
  }
  .photo-crop-hint { text-align: center; font-size: 12px; color: var(--muted); }
  .photo-crop-actions { display: flex; gap: 10px; }
  .photo-crop-actions button { flex: 1; padding: 12px; border-radius: 10px; border: none; font-weight: 600; font-size: 14px; }
  .photo-crop-cancel { background: var(--cream); color: var(--ink); }
  .photo-crop-confirm { background: var(--pink-600); color: white; }
  .photo-crop-confirm:disabled { opacity: 0.6; }

  .swipe-actions { display: flex; justify-content: center; align-items: center; gap: 18px; padding: 22px 0 6px; }
  .swipe-actions button { border: none; border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }
  .act-pass { width: 62px; height: 62px; background: white; color: #d8536b; font-size: 24px; }
  .act-like { width: 62px; height: 62px; background: linear-gradient(135deg, var(--pink-500), var(--pink-600)); color: white; font-size: 24px; }
  .act-reload, .act-message { width: 48px; height: 48px; background: white; color: var(--muted); }
  .act-message { font-size: 22px; line-height: 1; }
  .act-emoji { display: block; line-height: 1; }
  .act-reload:disabled { opacity: 0.6; cursor: default; }
  .act-reload.spinning svg { animation: act-reload-spin 0.8s linear infinite; }
  @keyframes act-reload-spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .act-reload.spinning svg { animation: none; } }
  .swipe-hint { text-align: center; font-size: 12.5px; color: var(--muted); }
  #discover-explore-hint { margin-bottom: 4px; }

  /* ---------- Discover — horizontal scrolling carousel ---------- */
  /* Profiles scroll left-to-right like a filmstrip. There's no "pass" —
     scrolling past a profile just moves on; tapping the heart on a card
     likes it. */
  .discover-stack-wrap { display: flex; flex-direction: column; align-items: center; gap: 6px; }
  .discover-stack-nav-wrap { position: relative; width: 100%; max-width: min(760px, 100%); margin: 0 auto; }
  .discover-nav-btn {
    display: none; position: absolute; top: 50%; transform: translateY(-50%);
    width: 44px; height: 44px; border-radius: 50%; border: none;
    background: white; box-shadow: 0 6px 18px rgba(0,0,0,0.14);
    color: var(--ink); align-items: center; justify-content: center;
    cursor: pointer; z-index: 6;
  }
  .discover-nav-btn:disabled { opacity: 0.3; cursor: default; }
  .discover-nav-prev { left: -58px; }
  .discover-nav-next { right: -58px; }
  @media (min-width: 721px) {
    .discover-nav-btn { display: flex; }
  }
  .discover-stack {
    position: relative; width: 100%; max-width: min(900px, 100%); margin: 0 auto;
  }
  /* Only the "may like" carousel gets a fixed min-height — matching a
     card's photo height (width * 5/4 aspect ratio) at each breakpoint
     below — so that area holds its size whether it's showing cards or
     an empty-state message ("no more profiles"). The row-list tabs
     (Liked/Nearby/New) size to their own content as before. */
  .discover-stack.discover-stack--carousel { min-height: 620px; }
  .discover-stack .empty-state { position: static; }
  .discover-stack.discover-stack--carousel .empty-state {
    height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center;
  }
  .discover-carousel {
    display: flex; flex-wrap: nowrap; align-items: flex-start; gap: 0;
    overflow-x: auto; overflow-y: hidden; scroll-snap-type: x mandatory;
    -webkit-overflow-scrolling: touch; scrollbar-width: none; padding: 4px 0 16px;
  }
  .discover-carousel::-webkit-scrollbar { display: none; }
  /* Each slide is exactly the full width of the carousel track, so only one
     profile is ever visible/snapped at a time — scroll sideways to the
     next one, rather than several cards peeking side by side. Deliberately
     NOT capped with max-width here: doing that shrinks the flex item's own
     footprint in the track, so on a wide/laptop screen several capped-width
     slides fit side by side and a single scroll advances by less than one
     full profile. The visual size cap instead lives on .discover-carousel-photo
     below, which only narrows the card's *content* — each slide still spans
     the full track width, so scrolling always moves exactly one profile. */
  .discover-carousel-card {
    flex: 0 0 100%; width: 100%; scroll-snap-align: start; scroll-snap-stop: always;
    display: flex; flex-direction: column; align-items: center; gap: 12px;
  }
  @media (max-width: 900px) {
    .discover-stack.discover-stack--carousel { min-height: 560px; }
  }
  @media (max-width: 560px) {
    .discover-stack.discover-stack--carousel { min-height: 400px; }
  }
  @media (max-width: 380px) {
    .discover-stack.discover-stack--carousel { min-height: 350px; }
  }
  /* max-width only ever matters once the track is wider than 480px
     (tablets/laptops) — phones are already narrower than that, so this
     doesn't change anything there. Without it, the photo scaled all the
     way up to the .discover-stack cap (900px), looking oversized next to
     every other ~440-520px panel in the app on a laptop screen. */
  .discover-carousel-photo {
    width: 100%; max-width: 480px; margin: 0 auto; border-radius: 22px; overflow: hidden;
    box-shadow: 0 10px 40px rgba(75,20,45,0.1); cursor: pointer; transition: box-shadow 0.2s ease;
  }
  .discover-carousel-photo .swipe-details .name-row { font-size: 22px; }
  /* The Pass/Like buttons below the carousel act on whichever card is
     currently snapped into view — ring it in pink so that's clear. */
  .discover-carousel-card.is-current .discover-carousel-photo {
    box-shadow: 0 0 0 3px var(--pink-500), 0 10px 40px rgba(75,20,45,0.1);
  }
  @keyframes carousel-like-pop { 0% { transform: scale(1); } 50% { transform: scale(1.25); } 100% { transform: scale(1); } }
  .discover-stack-actions button.tap-pop { animation: carousel-like-pop 0.3s ease; }

  .discover-section { width: 100%; max-width: 760px; margin: 0 auto 22px; }
  .discover-section-title { display: flex; align-items: center; gap: 8px; font-size: 16px; font-weight: 800; color: var(--ink); margin: 4px 0 10px; }
  .discover-section-title span { font-size: 11px; font-weight: 700; color: var(--muted); background: var(--cream); border-radius: 999px; padding: 3px 8px; }
  .discover-like-section { margin-bottom: 0; }

  /* ---------- Explore — grid of many profiles at once ---------- */
  .explore-panel { width: 100%; max-width: 900px; margin: 0 auto; }
  .explore-header { margin-bottom: 16px; }
  .explore-title { font-size: 22px; font-weight: 800; color: var(--ink); margin-bottom: 4px; }
  .explore-grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 12px;
  }
  .explore-card {
    position: relative; aspect-ratio: 3 / 4; border-radius: 16px; overflow: hidden; cursor: pointer;
    box-shadow: 0 4px 16px rgba(75,20,45,0.08); transition: transform 0.15s ease, box-shadow 0.15s ease;
  }
  .explore-card:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(75,20,45,0.14); }
  .explore-card-photo {
    width: 100%; height: 100%; background-size: cover; background-position: center;
    display: flex; flex-direction: column; justify-content: flex-end;
  }
  .explore-card-info {
    background: linear-gradient(to top, rgba(0,0,0,0.65), transparent); color: white; padding: 24px 10px 10px;
  }
  .explore-card-name { font-size: 13.5px; font-weight: 700; }
  .explore-card-loc { font-size: 11px; opacity: 0.9; }
  @media (max-width: 480px) {
    .explore-grid { grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 8px; }
  }

  /* ---------- Discover — list layout ---------- */
  .discover-row {
    display: flex; align-items: flex-start; gap: 14px; background: white; border-radius: 18px;
    padding: 14px; margin-bottom: 14px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); position: relative; cursor: pointer;
  }
  .discover-row-photo {
    width: 92px; height: 92px; border-radius: 14px; background-size: cover; background-position: center;
    flex-shrink: 0; background-color: var(--cream);
  }
  .discover-row-body { flex: 1; min-width: 0; padding-right: 30px; }
  .discover-row-name { font-weight: 800; font-size: 15.5px; color: var(--ink); display: flex; align-items: center; gap: 7px; }
  .discover-row-loc { display: flex; align-items: center; gap: 4px; font-size: 12px; color: var(--muted); margin-top: 2px; }
  .discover-row-bio {
    font-size: 12.5px; color: var(--ink); opacity: 0.85; margin-top: 6px; line-height: 1.4;
    display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
  }
  .discover-row-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .discover-row-tags span { background: var(--cream); color: var(--ink); font-size: 11px; font-weight: 600; padding: 4px 11px; border-radius: 20px; }
  .discover-row-like {
    align-self: center; width: 46px; height: 46px; border-radius: 50%; flex-shrink: 0;
    background: var(--pink-100); color: var(--pink-600); border: none; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
  }
  .discover-row-kebab {
    position: absolute; top: 12px; right: 10px; background: none; border: none; color: var(--muted);
    cursor: pointer; padding: 6px; display: flex; z-index: 2;
  }
  .discover-row-menu {
    display: none; position: absolute; top: 38px; right: 10px; background: white; border-radius: 12px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.14); padding: 6px; z-index: 5; min-width: 150px;
  }
  .discover-row-menu.open { display: block; }
  .discover-row-menu button {
    display: block; width: 100%; text-align: left; background: none; border: none; padding: 9px 10px;
    font-size: 13px; font-weight: 600; color: var(--ink); border-radius: 8px; cursor: pointer;
  }
  .discover-row-menu button:hover { background: var(--cream); }

  /* ---------- Discover — full profile modal ---------- */
  .candidate-modal-overlay {
    display: none; position: fixed; inset: 0; background: rgba(20,8,14,0.55); z-index: 60;
    align-items: flex-start; justify-content: center; padding: 30px 16px; overflow-y: auto;
  }
  .candidate-modal-overlay.visible { display: flex; }
  .candidate-modal { background: white; border-radius: 24px; max-width: 440px; width: 100%; overflow: hidden; position: relative; margin-bottom: 40px; }
  .candidate-modal-close {
    position: absolute; top: 14px; right: 14px; z-index: 2; width: 34px; height: 34px; border-radius: 50%;
    background: rgba(0,0,0,0.4); color: white; border: none; display: flex; align-items: center; justify-content: center; cursor: pointer;
  }
  .candidate-modal-menu-btn {
    position: absolute; top: 14px; right: 56px; z-index: 2; width: 34px; height: 34px; border-radius: 50%;
    background: rgba(0,0,0,0.4); color: white; border: none; display: flex; align-items: center; justify-content: center; cursor: pointer;
  }
  .candidate-modal .swipe-actions { padding: 18px 20px 24px; }

  /* ---------- Block / Report action sheet ---------- */
  .action-sheet-overlay {
    display: none; position: fixed; inset: 0; z-index: 320; background: rgba(20,5,12,0.45);
    align-items: flex-end; justify-content: center;
  }
  .action-sheet-overlay.open { display: flex; }
  .action-sheet {
    background: white; border-radius: 20px 20px 0 0; width: 100%; max-width: 440px;
    padding: 8px 0 max(10px, env(safe-area-inset-bottom)); overflow: hidden;
  }
  .action-sheet-row {
    width: 100%; padding: 16px 20px; border: none; background: none; text-align: left;
    font: inherit; font-size: 15px; font-weight: 600; color: var(--ink); display: flex;
    align-items: center; gap: 12px; cursor: pointer; border-bottom: 1px solid var(--border);
  }
  .action-sheet-row:hover { background: var(--cream); }
  .action-sheet-row:last-child { border-bottom: none; }
  .action-sheet-row.danger { color: #c6284d; }
  .action-sheet-row.cancel { font-weight: 700; justify-content: center; margin-top: 4px; }
  .report-reason-list { padding: 6px 20px 16px; display: flex; flex-direction: column; gap: 8px; }
  .report-reason-list button {
    padding: 12px 14px; border-radius: 12px; border: 1px solid var(--border); background: white;
    text-align: left; font: inherit; font-size: 14px; color: var(--ink); cursor: pointer;
  }
  .report-reason-list button:hover { background: var(--cream); }
  .report-reason-list button.selected { background: var(--pink-500); border-color: var(--pink-500); color: white; font-weight: 600; }
  .blocked-user-row { display: flex; align-items: center; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--border); }
  .blocked-user-row:last-child { border-bottom: none; }
  .blocked-user-row .avatar { width: 42px; height: 42px; border-radius: 50%; background-size: cover; background-position: center; flex-shrink: 0; }
  .blocked-user-row .name { font-weight: 600; font-size: 14.5px; flex: 1; min-width: 0; }
  .blocked-user-row button {
    padding: 7px 14px; border-radius: 10px; border: 1px solid var(--border); background: white;
    font: inherit; font-size: 13px; font-weight: 600; color: var(--ink); cursor: pointer; flex-shrink: 0;
  }
  .blocked-user-row button:hover { background: var(--cream); }

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
  .bubble[data-mid] { cursor: pointer; }
  .receipt { align-self: flex-end; font-size: 11px; color: var(--muted); margin-top: -6px; }
  .chat-typing { display: none; padding: 0 20px 6px; font-size: 12px; color: var(--muted); font-style: italic; }
  .chat-menu-btn { margin-left: auto; background: var(--cream); border: none; width: 34px; height: 34px; border-radius: 50%; font-size: 18px; line-height: 1; cursor: pointer; color: var(--ink); }
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
  .profile-strength-block { margin-top: 16px; text-align: left; }
  .profile-strength-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
  .profile-strength-label { font-size: 12.5px; font-weight: 700; color: var(--ink); }
  .profile-strength-pct { font-size: 12.5px; font-weight: 800; color: var(--pink-600); }
  .profile-strength-track { width: 100%; height: 8px; border-radius: 6px; background: var(--cream); overflow: hidden; }
  .profile-strength-fill { height: 100%; border-radius: 6px; background: linear-gradient(135deg, var(--pink-500), var(--violet)); transition: width 0.4s ease; }
  .profile-strength-hint { font-size: 11.5px; color: var(--muted); margin-top: 6px; }
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
  .vibes-grid-view .vibes-slot-view { cursor: pointer; }
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
      color: white; box-shadow: 0 6px 16px rgba(124,58,237,0.4);
    }
    .mobile-nav-fab .icon svg { width: 21px; height: 21px; }
    .mobile-nav-fab .icon-filled { display: block; }
    .mobile-nav-fab .icon-outline { display: none; }
    @media (prefers-color-scheme: dark) {
      .mobile-nav { background: #17181c; border-top-color: rgba(255,255,255,0.08); box-shadow: 0 -1px 16px rgba(0,0,0,0.35); }
      .mobile-nav-item { color: #6e7079; }
      .mobile-nav-item.active { color: #a78bfa; }
      .mobile-nav-item.active .nav-dot { background: #a78bfa; }
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
    .content-grid { gap: 16px; }
    .swipe-photo { aspect-ratio: 3 / 4; min-height: 0; }
    .chat-input-row button, .profile-form button, .admirer-card button { min-height: 44px; }
    .swipe-actions button, .icon-btn, .back-btn, .nav-item, .mobile-nav-item { min-height: 44px; }

    /* ---------- Discover on phones: fit the screen, no scrolling ----------
       While the "may like" carousel has profiles (body.discover-fit), the
       app is exactly one screen tall: top bar, tabs, then a card that
       stretches to fill whatever space is left, with Reload/Pass/Like/
       Message pinned right under it above the bottom nav. */
    body.discover-fit:not(.chat-open) #dashboard.visible {
      height: 100vh; height: 100dvh; min-height: 0; overflow: hidden;
    }
    body.discover-fit:not(.chat-open) .main {
      display: flex; flex-direction: column; min-height: 0;
      padding: 10px 12px calc(56px + env(safe-area-inset-bottom, 0px) + 16px);
    }
    body.discover-fit:not(.chat-open) .topbar { flex-wrap: nowrap; flex-shrink: 0; margin-bottom: 8px; }
    body.discover-fit:not(.chat-open) .content-grid { flex: 1; min-height: 0; display: flex; align-items: stretch; }
    body.discover-fit:not(.chat-open) .discover-col { flex: 1; min-width: 0; min-height: 0; display: flex; flex-direction: column; }
    body.discover-fit:not(.chat-open) #panel-discover.visible { flex: 1; min-height: 0; display: flex; flex-direction: column; }
    body.discover-fit:not(.chat-open) .discover-category-tabs { flex-shrink: 0; margin-bottom: 8px; }
    body.discover-fit:not(.chat-open) .discover-category-tabs button { height: 40px; min-height: 40px; }
    body.discover-fit:not(.chat-open) .discover-section-title { flex-shrink: 0; margin: 0 0 6px; }
    body.discover-fit:not(.chat-open) .discover-stack-wrap { flex: 1; min-height: 0; width: 100%; gap: 2px; }
    body.discover-fit:not(.chat-open) .discover-stack-nav-wrap { flex: 1; min-height: 0; display: flex; flex-direction: column; max-width: 100%; }
    body.discover-fit:not(.chat-open) .discover-stack.discover-stack--carousel {
      flex: 1; min-height: 0; display: flex; flex-direction: column; max-width: 100%;
    }
    body.discover-fit:not(.chat-open) .discover-stack.discover-stack--carousel > .discover-section {
      flex: 1; min-height: 0; display: flex; flex-direction: column; margin: 0; max-width: 100%;
    }
    body.discover-fit:not(.chat-open) .discover-carousel { flex: 1; min-height: 0; align-items: stretch; padding: 0; }
    body.discover-fit:not(.chat-open) .discover-carousel-card { gap: 0; }
    body.discover-fit:not(.chat-open) .discover-carousel-photo {
      flex: 1 1 auto; min-height: 0; height: auto; aspect-ratio: auto; max-width: 100%;
    }
    body.discover-fit:not(.chat-open) .discover-carousel-card.is-current .discover-carousel-photo {
      box-shadow: inset 0 0 0 3px var(--pink-500), 0 6px 20px rgba(75,20,45,0.1);
    }
    body.discover-fit:not(.chat-open) #discover-explore-hint { margin: 0; font-size: 11.5px; flex-shrink: 0; }
    body.discover-fit:not(.chat-open) #discover-stack-hint { display: none !important; }
    body.discover-fit:not(.chat-open) #discover-stack-actions { flex-shrink: 0; padding: 8px 0 2px; gap: 14px; }
    body.discover-fit:not(.chat-open) #discover-stack-actions .act-pass,
    body.discover-fit:not(.chat-open) #discover-stack-actions .act-like { width: 58px; height: 58px; }
    body.discover-fit:not(.chat-open) #discover-stack-actions .act-reload,
    body.discover-fit:not(.chat-open) #discover-stack-actions .act-message { width: 46px; height: 46px; }
    body.discover-fit:not(.chat-open) .app-footer { display: none; }
    /* Short phones / small windows: drop the extras so the card keeps room. */
    @media (max-height: 640px) {
      body.discover-fit:not(.chat-open) .discover-section-title,
      body.discover-fit:not(.chat-open) #discover-explore-hint { display: none; }
    }
    @media (max-height: 560px) {
      body.discover-fit:not(.chat-open) .topbar h1 { font-size: 18px; }
      body.discover-fit:not(.chat-open) .discover-category-tabs button { height: 36px; min-height: 36px; }
      body.discover-fit:not(.chat-open) #discover-stack-actions .act-pass,
      body.discover-fit:not(.chat-open) #discover-stack-actions .act-like { width: 52px; height: 52px; }
      body.discover-fit:not(.chat-open) #discover-stack-actions .act-reload,
      body.discover-fit:not(.chat-open) #discover-stack-actions .act-message { width: 42px; height: 42px; }
    }
  }

  /* ---------- Filter system ---------- */
  .icon-btn.filter-btn.has-active { color: var(--pink-600); }
  .filter-overlay {
    position: fixed; inset: 0; background: rgba(20,5,12,0.45); z-index: 220;
    opacity: 0; pointer-events: none; transition: opacity 0.25s ease;
  }
  .filter-overlay.open { opacity: 1; pointer-events: auto; }

  .filter-panel {
    position: fixed; left: 0; right: 0; bottom: 0; z-index: 221;
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
  .interest-chip-disabled { opacity: 0.35; pointer-events: none; }

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
    .discover-carousel { scroll-behavior: auto; }
    .discover-stack-actions button.tap-pop { animation: none; }
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
  .settings-danger-btn { background: #c6284d !important; }
  .settings-danger-btn:hover { background: #a91f40 !important; }
  .settings-note { margin:8px 4px 0; font-size:11px; color:var(--muted); line-height:1.45; }
  body.settings-dark {
    --cream:#15161a; --card:#202126; --ink:#f4f1f3; --muted:#aaa5ab; --border:#35363d; --pink-100:#3b202b;
  }
  body.settings-dark .q-option, body.settings-dark .settings-choice { background:var(--card); color:var(--ink); }
  body.settings-dark .icon-btn { background:var(--card); }
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
  body.settings-dark .settings-card,
  body.settings-dark .discover-row,
  body.settings-dark .discover-row-menu,
  body.settings-dark .candidate-modal {
    background: var(--card);
    color: var(--ink);
  }
  body.settings-dark .discover-row-tags span { background: var(--cream); }
  body.settings-dark .filter-tabs button,
  body.settings-dark .act-pass,
  body.settings-dark .act-reload,
  body.settings-dark .act-message {
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
  /* The dark-mode "make every filter-tabs button dark" rule above also
     matched the active (pink) discover-category-tabs button, wiping out
     its pink highlight — restore it here with higher specificity. */
  body.settings-dark .discover-category-tabs button.active {
    background: var(--pink-500);
    border-color: var(--pink-500);
    color: white;
  }
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

<div id="boot-loader"><div class="boot-wheel"></div></div>

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
    <use href="#couple-icon" x="230" y="700" width="170" height="200" style="color:#7c3aed" opacity="0.45"/>
    <use href="#couple-icon" x="770" y="400" width="210" height="250" style="color:#e0b48a" opacity="0.5"/>
    <use href="#couple-icon" x="790" y="680" width="190" height="230" style="color:#8b5cf6" opacity="0.45"/>
    <use href="#couple-icon" x="450" y="740" width="180" height="210" style="color:#f0b79a" opacity="0.4"/>
  </svg>

  <svg class="landing-map" viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
    <g fill="none" stroke="rgba(255,255,255,0.5)" stroke-width="1" stroke-dasharray="1 4">
      <path d="M50,150 Q200,80 350,140 T650,120"/>
      <path d="M100,200 Q300,220 500,160 T750,180"/>
    </g>
    <g fill="#8b5cf6">
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
          <option value="non-binary">Non-binary</option>
          <option value="genderqueer">Genderqueer</option>
          <option value="genderfluid">Genderfluid</option>
          <option value="agender">Agender</option>
          <option value="other">Other</option>
          <option value="prefer_not_to_say">Prefer not to say</option>
        </select>
        <input id="f-country" name="country" placeholder="Country (e.g. Philippines)" style="display:none;" />
        <input id="f-location" name="location" placeholder="Location (e.g. Manila, Philippines)" style="display:none;" />
        <textarea id="f-bio" name="bio" placeholder="Short bio" style="display:none;"></textarea>
        <div id="f-tags-picker" style="display:none;margin-bottom:12px;">
          <div class="filter-field-label" style="margin-bottom:6px;">Interests <span style="font-weight:400;color:var(--muted);">(up to 2 per category)</span></div>
          <div id="f-tags-chips"></div>
        </div>
        <input id="f-identity" name="identity" type="text" inputmode="email" autocomplete="username" placeholder="Email or phone number" required />
        <div class="password-field-wrap">
          <input id="f-password" name="password" type="password" placeholder="Password" autocomplete="current-password" required />
          <button type="button" class="password-toggle-btn" id="password-toggle-btn" onclick="togglePasswordVisibility()" aria-label="Show password" aria-pressed="false">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
        <div class="field-hint" id="password-hint" style="display:none;">At least 8 characters, with letters and numbers.</div>
        <div class="auth-forgot-link" id="auth-forgot-link"><button type="button" onclick="openForgotPassword()">Forgot password?</button></div>
        <button type="submit" class="auth-submit" id="auth-submit-btn">Log in</button>
      </form>
    </div>
  </div>

  <div class="filter-overlay" id="forgot-password-overlay" onclick="closeForgotPassword()"></div>
  <div class="filter-panel" id="forgot-password-panel" role="dialog" aria-modal="true" aria-labelledby="forgot-password-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="forgot-password-title">Reset password</h2>
      <button class="filter-panel-close" onclick="closeForgotPassword()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div id="forgot-step-request">
        <div class="field-hint" style="margin:0 0 14px 2px;">Enter the email or phone number on your account and we'll send a reset code.</div>
        <input id="fp-identity" type="text" placeholder="Email or phone number" />
        <div id="forgot-request-error" class="auth-error" style="display:none;"></div>
      </div>
      <div id="forgot-step-reset" style="display:none;">
        <div class="field-hint" id="forgot-reset-hint" style="margin:0 0 14px 2px;">Enter the code and choose a new password.</div>
        <input id="fp-code" type="text" inputmode="numeric" maxlength="6" placeholder="6-digit code" />
        <div class="password-field-wrap">
          <input id="fp-new-password" type="password" placeholder="New password" autocomplete="new-password" />
          <button type="button" class="password-toggle-btn" onclick="togglePasswordVisibility('fp-new-password', this)" aria-label="Show password" aria-pressed="false">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
        <div class="field-hint">At least 8 characters, with letters and numbers.</div>
        <div id="forgot-reset-error" class="auth-error" style="display:none;"></div>
      </div>
    </div>
    <div class="filter-panel-footer">
      <button type="button" class="filter-apply-btn" id="forgot-step-btn" onclick="submitForgotPasswordStep()">Send reset code</button>
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
    <button type="button" class="profile-overlay-close" onclick="closeDetailsScreen()" aria-label="Close About Me">
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>
    </button>
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

<div id="looking-for-screen">
  <div class="q-card" style="max-width:540px;">
    <button type="button" class="profile-overlay-close" onclick="closeLookingForScreen()" aria-label="Close I'm looking for">
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>
    </button>
    <div class="q-header">
      <div class="logo-font">swing</div>
      <div class="q-kicker"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg> I'M LOOKING FOR</div>
    </div>
    <h3 class="q-title">What are you looking for?</h3>
    <div class="q-hint">Choose as many as apply</div>

    <div class="details-body" id="looking-for-form-body">
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

    <button id="looking-for-save-btn" onclick="saveLookingForScreen()">Save</button>
    <button class="q-skip" onclick="closeLookingForScreen()">Cancel</button>
  </div>
</div>

<div id="dashboard">
  <aside class="sidebar">
    <div class="brand"><div class="logo-font">swing <span class="brand-heart"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></span></div></div>
    <div class="tagline">Meet someone worth<br/>staying for.</div>

    <button class="nav-item active" data-view="discover" onclick="switchView('discover')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v9a1 1 0 0 0 1 1H9a1 1 0 0 0 1-1v-4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v4a1 1 0 0 0 1 1h2.5a1 1 0 0 0 1-1v-9"/></svg></span> Discover</button>
    <button class="nav-item" data-view="matches" onclick="switchView('matches')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 11.5a8.4 8.4 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.4 8.4 0 0 1-3.8-.9L3 21l1.9-5.7a8.4 8.4 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6A8.4 8.4 0 0 1 12.5 3h.5a8.48 8.48 0 0 1 8 8v.5Z"/></svg></span> Matches <span class="badge" id="nav-matches-count" style="display:none;">0</span></button>
    <button class="nav-item" data-view="likes" onclick="switchView('likes')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 2.5 15 9l7 .9-5.1 4.8L18.2 21 12 17.4 5.8 21l1.3-6.3L2 9.9 9 9z"/></svg></span> Likes You <span class="badge" id="nav-likes-count">0</span></button>
    <button class="nav-item" data-view="explore" onclick="switchView('explore')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="m15.5 8.5-2 5-5 2 2-5Z"/></svg></span> Explore</button>
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
          <div class="filter-tabs discover-category-tabs" role="tablist" aria-label="Discover categories">
            <button class="active" type="button" role="tab" aria-selected="true" onclick="setDiscoverTab('maylike')" aria-label="Profiles You May Like" title="Profiles You May Like"><svg viewBox="0 0 24 24" width="19" height="19" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></button>
            <button type="button" role="tab" aria-selected="false" onclick="setDiscoverTab('liked')" aria-label="Profiles You Liked" title="Profiles You Liked"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21.2l7.8-7.8 1-1a5.5 5.5 0 0 0 0-7.8Z"/></svg></button>
            <button type="button" role="tab" aria-selected="false" onclick="setDiscoverTab('nearby')" aria-label="Users Nearby" title="Users Nearby"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 21s7-6.5 7-11.5A7 7 0 1 0 5 9.5C5 14.5 12 21 12 21Z"/><circle cx="12" cy="9.5" r="2.2"/></svg></button>
            <button type="button" role="tab" aria-selected="false" onclick="setDiscoverTab('new')" aria-label="New Users" title="New Users"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/></svg></button>
          </div>
          <div class="discover-section-title" id="discover-tab-heading">Profiles You May Like <span id="discover-tab-count">0</span></div>
          <div class="discover-stack-wrap">
            <div class="discover-stack-nav-wrap">
              <div id="discover-list" class="discover-stack"></div>
              <button type="button" class="discover-nav-btn discover-nav-prev" id="discover-nav-prev" onclick="scrollDiscoverCarousel(-1)" aria-label="Previous profile" title="Previous profile" style="display:none;"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M15 5l-7 7 7 7"/></svg></button>
              <button type="button" class="discover-nav-btn discover-nav-next" id="discover-nav-next" onclick="scrollDiscoverCarousel(1)" aria-label="Next profile" title="Next profile" style="display:none;"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M9 5l7 7-7 7"/></svg></button>
            </div>
            <div class="swipe-hint" id="discover-explore-hint" style="display:none;">Tap a profile to explore more</div>
            <div class="swipe-actions" id="discover-stack-actions" style="display:none;">
              <button type="button" class="act-reload" id="discover-reload-btn" onclick="reloadDiscover()" aria-label="Reload profiles" title="Reload profiles"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20 11a8 8 0 0 0-14.5-4.5L4 8"/><path d="M4 4v4h4"/><path d="M4 13a8 8 0 0 0 14.5 4.5L20 16"/><path d="M20 20v-4h-4"/></svg></button>
              <button type="button" class="act-pass" onclick="swipeCurrentCard('pass')" aria-label="Pass" title="Pass"><svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg></button>
              <button type="button" class="act-like" onclick="swipeCurrentCard('like')" aria-label="Like" title="Like"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></button>
              <button type="button" class="act-message" onclick="messageCurrentCard()" aria-label="Message" title="Message"><span class="act-emoji" aria-hidden="true">💬</span></button>
            </div>
            <div class="swipe-hint" id="discover-stack-hint" style="display:none;">Scroll sideways to browse, or use the buttons below</div>
          </div>
        </div>

        <div class="candidate-modal-overlay" id="candidate-detail-modal">
          <div class="candidate-modal">
            <button type="button" class="candidate-modal-menu-btn" onclick="openProfileActionSheet()" aria-label="More options" title="More options"><svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg></button>
            <button type="button" class="candidate-modal-close" onclick="closeCandidateDetail()" aria-label="Close"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
            <div id="candidate-detail-body"></div>
            <div class="swipe-actions" id="candidate-detail-footer"></div>
          </div>
        </div>

        <div class="photo-lightbox-overlay" id="photo-lightbox" onclick="if (event.target === this) closePhotoLightbox()">
          <button type="button" class="photo-lightbox-close" onclick="closePhotoLightbox()" aria-label="Close"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
          <button type="button" class="photo-lightbox-nav photo-lightbox-prev" id="photo-lightbox-prev" onclick="navPhotoLightbox(-1)" aria-label="Previous photo"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M15 5l-7 7 7 7"/></svg></button>
          <img id="photo-lightbox-img" src="" alt="Full-size photo" />
          <button type="button" class="photo-lightbox-nav photo-lightbox-next" id="photo-lightbox-next" onclick="navPhotoLightbox(1)" aria-label="Next photo"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M9 5l7 7-7 7"/></svg></button>
          <div class="photo-lightbox-counter" id="photo-lightbox-counter"></div>
        </div>

        <div class="action-sheet-overlay" id="action-sheet-overlay" onclick="if (event.target === this) closeActionSheet()">
          <div class="action-sheet" id="action-sheet-body"></div>
        </div>

        <!-- Profile photo crop step: every profile photo is cropped to a
             3:4 portrait before it's uploaded, so every profile photo in
             the app ends up the same shape. -->
        <div class="photo-crop-overlay" id="photo-crop-overlay">
          <div class="photo-crop-modal">
            <div class="photo-crop-header">Crop your photo</div>
            <div class="photo-crop-stage" id="photo-crop-stage"><img id="photo-crop-img" src="" alt="" /></div>
            <div class="photo-crop-hint">Drag to reposition, pinch or scroll to zoom</div>
            <div class="photo-crop-actions">
              <button type="button" class="photo-crop-cancel" onclick="cancelPhotoCrop()">Cancel</button>
              <button type="button" class="photo-crop-confirm" id="photo-crop-confirm-btn" onclick="confirmPhotoCrop()">Use photo</button>
            </div>
          </div>
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
              <button class="chat-menu-btn" type="button" onclick="openChatMenu()" aria-label="Chat options">&#8943;</button>
            </div>
            <div id="chat-compat-panel"></div>
            <div class="chat-messages" id="chat-messages"></div>
            <div class="chat-typing" id="chat-typing">typing…</div>
            <div class="chat-input-row">
              <input id="chat-input" placeholder="Type a message..." />
              <button onclick="sendMessage()">Send</button>
            </div>
          </div>
        </div>

        <div class="view-panel" id="panel-likes">
          <div class="admirer-grid" id="admirer-grid"></div>
        </div>

        <div class="view-panel" id="panel-explore">
          <div class="explore-panel">
            <div class="explore-header">
              <div class="explore-title">Explore</div>
              <div class="explore-sub muted-note">Browse everyone currently available to you at a glance — tap anyone to see their full profile.</div>
            </div>
            <div class="explore-grid" id="explore-grid"></div>
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

              <div class="profile-strength-block" id="ph-strength-block">
                <div class="profile-strength-row">
                  <span class="profile-strength-label">Profile Strength</span>
                  <span class="profile-strength-pct" id="ph-strength-pct">0%</span>
                </div>
                <div class="profile-strength-track"><div class="profile-strength-fill" id="ph-strength-fill" style="width:0%;"></div></div>
                <div class="profile-strength-hint" id="ph-strength-hint"></div>
              </div>

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
              <div class="about-card-header" style="justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:9px;">
                  <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></span>
                  <h3>Interests</h3>
                </div>
                <button type="button" class="about-card-edit-link" onclick="openInterestsPanel()">Edit</button>
              </div>
              <div class="interests-chips" id="ph-interests-chips"></div>
            </div>

            <div class="about-card">
              <div class="about-card-header" style="justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:9px;">
                  <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg></span>
                  <h3>I'm looking for</h3>
                </div>
                <button type="button" class="about-card-edit-link" onclick="showLookingForScreen()">Edit</button>
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
              <option value="non-binary">Non-binary</option>
              <option value="genderqueer">Genderqueer</option>
              <option value="genderfluid">Genderfluid</option>
              <option value="agender">Agender</option>
              <option value="other">Other</option>
              <option value="prefer_not_to_say">Prefer not to say</option>
            </select>
            <label>Country</label><input id="p-country" />
            <label>Location</label><input id="p-location" />
            <label>Bio</label><textarea id="p-bio"></textarea>
            <div class="field-hint" style="margin:-8px 0 14px 2px;">Interests are edited from the Interests card on your profile — tap "Edit" there.</div>

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
    <button class="mobile-nav-item mobile-nav-fab" data-view="explore" onclick="switchView('explore')" aria-label="Explore">
      <span class="icon">
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm3.8 5.7-2.1 5.6a1 1 0 0 1-.6.6l-5.6 2.1a.5.5 0 0 1-.6-.6l2.1-5.6a1 1 0 0 1 .6-.6l5.6-2.1a.5.5 0 0 1 .6.6Z"/></svg>
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
          <div class="settings-row">
            <span class="settings-icon">☎</span><span class="settings-copy"><span class="settings-label">Phone</span><span class="settings-desc">Your sign-in phone number</span></span><span class="settings-value" id="settings-phone">—</span>
          </div>
          <button class="settings-row clickable" type="button" onclick="openChangePassword()">
            <span class="settings-icon">🔒</span><span class="settings-copy"><span class="settings-label">Change password</span><span class="settings-desc">Update the password you sign in with.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">DISCOVERY</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="closeProfileSettings(); openFilterPanel();">
            <span class="settings-icon">⌘</span><span class="settings-copy"><span class="settings-label">Discovery filters</span><span class="settings-desc">Control who appears in Discover and Explore.</span></span><span class="settings-chevron">›</span>
          </button>
          <button class="settings-row clickable" type="button" onclick="resetFiltersFromSettings()">
            <span class="settings-icon">↺</span><span class="settings-copy"><span class="settings-label">Reset filters</span><span class="settings-desc">Return Discover preferences to their defaults.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">DATING PREFERENCES</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="openOrientationPanel()">
            <span class="settings-icon">◐</span><span class="settings-copy"><span class="settings-label">Sexual Orientation</span><span class="settings-desc">Private — used for matching only, never shown on your profile.</span></span><span class="settings-chevron">›</span>
          </button>
          <button class="settings-row clickable" type="button" onclick="openInterestedInPanel()">
            <span class="settings-icon">⚭</span><span class="settings-copy"><span class="settings-label">Interested In</span><span class="settings-desc">Private — controls who's eligible to see you and who you see in Discover.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">PRIVACY</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="togglePrivacySetting('discoverable')">
            <span class="settings-icon">◎</span><span class="settings-copy"><span class="settings-label">Pause my account</span><span class="settings-desc">Take a break: hide your profile from Discover. Your matches and chats stay as they are.</span></span><span class="settings-toggle" id="settings-discoverable-toggle" aria-hidden="true"></span>
          </button>
          <button class="settings-row clickable" type="button" onclick="togglePrivacySetting('showLocation')">
            <span class="settings-icon">⌖</span><span class="settings-copy"><span class="settings-label">Show my location</span><span class="settings-desc">Allow your saved city/location to appear on your profile.</span></span><span class="settings-toggle" id="settings-location-toggle" aria-hidden="true"></span>
          </button>
          <button class="settings-row clickable" type="button" onclick="openBlockedUsersPanel()">
            <span class="settings-icon">🚫</span><span class="settings-copy"><span class="settings-label">Blocked Users</span><span class="settings-desc">See and manage people you've blocked.</span></span><span class="settings-chevron">›</span>
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

      <div class="settings-section" id="install-app-row" style="display:none;">
        <p class="settings-section-title">APP</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="installApp()">
            <span class="settings-icon">⬇</span><span class="settings-copy"><span class="settings-label">Install Swing app</span><span class="settings-desc">Add Swing to your home screen for quick, full-screen access.</span></span><span class="settings-chevron">›</span>
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

      <div class="settings-section">
        <p class="settings-section-title">DANGER ZONE</p>
        <div class="settings-card">
          <button class="settings-row clickable settings-danger" type="button" onclick="openDeleteAccount()">
            <span class="settings-icon">⚠</span><span class="settings-copy"><span class="settings-label">Delete account</span><span class="settings-desc">Permanently delete your account, matches, and messages. This can't be undone.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>
      <p class="settings-note">Settings marked for this device are stored locally in your browser. Account and profile data remain managed by your Swing account.</p>
    </div>
  </aside>

  <div class="filter-overlay" id="change-password-overlay" onclick="closeChangePassword()"></div>
  <div class="filter-panel" id="change-password-panel" role="dialog" aria-modal="true" aria-labelledby="change-password-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="change-password-title">Change password</h2>
      <button class="filter-panel-close" onclick="closeChangePassword()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div class="password-field-wrap">
        <input id="cp-current-password" type="password" placeholder="Current password" autocomplete="current-password" />
        <button type="button" class="password-toggle-btn" onclick="togglePasswordVisibility('cp-current-password', this)" aria-label="Show password" aria-pressed="false">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <div class="password-field-wrap">
        <input id="cp-new-password" type="password" placeholder="New password" autocomplete="new-password" />
        <button type="button" class="password-toggle-btn" onclick="togglePasswordVisibility('cp-new-password', this)" aria-label="Show password" aria-pressed="false">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <div class="field-hint">At least 8 characters, with letters and numbers.</div>
      <div id="change-password-error" class="auth-error" style="display:none;"></div>
    </div>
    <div class="filter-panel-footer">
      <button type="button" class="filter-apply-btn" id="change-password-btn" onclick="submitChangePassword()">Update password</button>
    </div>
  </div>

  <div class="filter-overlay" id="delete-account-overlay" onclick="closeDeleteAccount()"></div>
  <div class="filter-panel" id="delete-account-panel" role="dialog" aria-modal="true" aria-labelledby="delete-account-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="delete-account-title">Delete account</h2>
      <button class="filter-panel-close" onclick="closeDeleteAccount()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div class="field-hint" style="margin:0 0 14px 2px;">This permanently deletes your profile, photos, matches, and messages. This can't be undone. Enter your password to confirm.</div>
      <div class="password-field-wrap">
        <input id="da-password" type="password" placeholder="Password" autocomplete="current-password" />
        <button type="button" class="password-toggle-btn" onclick="togglePasswordVisibility('da-password', this)" aria-label="Show password" aria-pressed="false">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <div id="delete-account-error" class="auth-error" style="display:none;"></div>
    </div>
    <div class="filter-panel-footer">
      <button type="button" class="filter-apply-btn settings-danger-btn" id="delete-account-btn" onclick="submitDeleteAccount()">Permanently delete my account</button>
    </div>
  </div>

  <div class="filter-overlay" id="blocked-users-overlay" onclick="closeBlockedUsersPanel()"></div>
  <div class="filter-panel" id="blocked-users-panel" role="dialog" aria-modal="true" aria-labelledby="blocked-users-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="blocked-users-title">Blocked Users</h2>
      <button class="filter-panel-close" onclick="closeBlockedUsersPanel()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body" id="blocked-users-body">
      <div class="field-hint">Loading…</div>
    </div>
  </div>

  <div class="filter-overlay" id="orientation-overlay" onclick="closeOrientationPanel()"></div>
  <div class="filter-panel" id="orientation-panel" role="dialog" aria-modal="true" aria-labelledby="orientation-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="orientation-title">Sexual Orientation</h2>
      <button class="filter-panel-close" onclick="closeOrientationPanel()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div class="field-hint" style="margin-bottom:12px;">Private — this is used to help with matching and is never shown on your profile.</div>
      <div class="report-reason-list" id="orientation-options"></div>
      <div class="auth-error" id="orientation-error" style="display:none;"></div>
      <button type="button" class="filter-apply-btn" onclick="saveOrientation()" id="orientation-save-btn">Save</button>
    </div>
  </div>

  <div class="filter-overlay" id="interested-in-overlay" onclick="closeInterestedInPanel()"></div>
  <div class="filter-panel" id="interested-in-panel" role="dialog" aria-modal="true" aria-labelledby="interested-in-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="interested-in-title">Interested In</h2>
      <button class="filter-panel-close" onclick="closeInterestedInPanel()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div class="field-hint" style="margin-bottom:12px;">Private — controls who's eligible to see you and who you see in Discover. Pick as many as apply.</div>
      <div class="report-reason-list" id="interested-in-options"></div>
      <div class="auth-error" id="interested-in-error" style="display:none;"></div>
      <button type="button" class="filter-apply-btn" onclick="saveInterestedIn()" id="interested-in-save-btn">Save</button>
    </div>
  </div>

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
          <label class="filter-field-label" for="f-filter-country">Country</label>
          <input class="filter-input" id="f-filter-country" type="text" placeholder="e.g. Philippines" oninput="onTextFilterInput('country', this)" />
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-city">City</label>
          <input class="filter-input" id="f-city" type="text" placeholder="e.g. Manila" oninput="onTextFilterInput('city', this)" />
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

<div class="filter-overlay" id="interests-overlay" onclick="closeInterestsPanel()"></div>
<div class="filter-panel" id="interests-panel" role="dialog" aria-modal="true" aria-labelledby="interests-panel-title" aria-hidden="true">
  <div class="filter-panel-handle"></div>
  <div class="filter-panel-header">
    <h2 id="interests-panel-title">Interests</h2>
    <button class="filter-panel-close" onclick="closeInterestsPanel()" aria-label="Close interests"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg></button>
  </div>
  <div class="filter-panel-body">
    <div class="field-hint" style="margin:0 0 14px 2px;">Pick up to 2 interests per category.</div>
    <div id="interests-panel-body"></div>
  </div>
  <div class="filter-panel-footer">
    <button type="button" class="filter-reset-btn" onclick="clearAllInterests()">Clear all</button>
    <button type="button" class="filter-apply-btn" onclick="saveInterestsAndClose()">
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20 6 9 17l-5-5"/></svg>
      Save interests
    </button>
  </div>
</div>

<script>
// Escapes user-supplied text before it's interpolated into innerHTML.
// ALWAYS wrap any profile/message/free-text field (name, bio, tags,
// prompts, chat text, etc.) in this before inserting it into HTML —
// none of that data can be trusted, it all comes from other users.
function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
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
  religion: 'single', political: 'single',
};
function loadStoredFilters() {
  try {
    const saved = JSON.parse(localStorage.getItem('swing_filters') || 'null');
    if (saved && typeof saved === 'object') return Object.assign(JSON.parse(JSON.stringify(FILTER_DEFAULTS)), saved);
  } catch (e) { /* ignore corrupt storage */ }
  return JSON.parse(JSON.stringify(FILTER_DEFAULTS));
}

// Single source of truth for a "fresh" client state, used both at initial
// page load and whenever we log out. Previously logout() reset state to
// a hand-written object that only listed a subset of these fields (it was
// missing filters/allCandidates/likedProfiles/nearbyProfiles/newProfiles/
// details/detailsOrigin/activeDiscoverTab). That meant e.g. state.filters
// stayed undefined after the first logout, which made matchesFilters()
// throw inside the next account's loadDiscover() call and silently abort
// it — leaving the previous account's candidate cards on screen (while the
// sidebar name/avatar, set separately, already showed the new account) —
// exactly the "two different users' profiles until I refresh" symptom.
// Building both the initial state and the logout reset from this one
// function keeps them from drifting apart again.
function createFreshState() {
  return {
    token: null,
    user: null,
    candidates: [],
    allCandidates: [],
    likedProfiles: [],
    nearbyProfiles: [],
    newProfiles: [],
    filters: loadStoredFilters(),
    details: defaultDetails(),
    detailsOrigin: null,
    matches: [],
    admirers: [],
    activeChat: null,
    eventSource: null,
    registerInterests: {},
    interestsDraft: {},
    activeDiscoverTab: 'maylike',
    swipeBusy: false, // guards against double-tapping the Pass/Like buttons
    carouselCurrentId: null, // id of the "may like" carousel card currently snapped into view
  };
}

let state = createFreshState();

// Bumped every time we log out or log in as a (possibly different) account.
// Async loaders (loadDiscover/loadMatches/loadAdmirers/etc.) capture this
// value before they fetch, then check it again once the response comes
// back — if it changed in the meantime, the account was switched mid-request,
// and the now-stale response for the OLD account is dropped instead of
// being written into the NEW account's state. Without this, a slow
// /api/discover (etc.) call started just before logout can resolve after
// the next login and silently overwrite the new user's data with the
// previous user's — which is why a hard refresh (which cancels all
// in-flight requests) used to "fix" it.
let sessionEpoch = 0;

// Interests, grouped the same way as the reference picker screenshots.
// Each user can pick at most 2 options per category (enforced in the
// picker UI below). Stored on the user as a flat tags array, same as
// before — the category is only used to organize the picker itself.
const INTEREST_CATEGORIES = {
  'Pets': ['Birds', 'Cats', 'Dogs', 'Fish', 'Lizards', 'Rabbits', 'Snakes', 'Turtles'],
  'Personality and traits': ['Ambition', 'Being active', 'Being family-oriented', 'Being open-minded', 'Being romantic', 'Confidence', 'Creativity', 'Empathy', 'Intelligence', 'Positivity', 'Self-awareness'],
  'Self-care': ['Aromatherapy', 'Astrology', 'Cold plunging', 'Crystals', 'Deep chats', 'Journaling', 'Mindfulness', 'Nutrition', 'Retreats', 'Skin care', 'Sleeping well', 'Slow living', 'Therapy', 'Time offline'],
  'Sports': ['Badminton', 'Baseball', 'Basketball', 'Bodybuilding', 'Bouldering', 'Bowling', 'Boxing', 'Cardio', 'Crew', 'Cricket', 'Cycling', 'Football', 'Functional fitness', 'Go karting', 'Golf', 'Gym', 'Gymnastics', 'Handball', 'HIIT', 'Hiking', 'Hockey', 'Horse riding', 'Kayaking', 'Lacrosse', 'Martial arts', 'Meditation', 'Motorbiking'],
  'Creativity': ['Art', 'Crafts', 'Crocheting', 'Dancing', 'Design', 'Drawing', 'Fashion', 'Knitting', 'Make-up', 'Making videos', 'Memes', 'Nail art', 'Painting', 'Photography', 'Pottery', 'Singing', 'Thrifting', 'Upcycling', 'Writing'],
  'Going out': ['Bars', 'Cafe-hopping', 'Clubs', 'Concerts', 'Drag shows', 'Festivals', 'Improv', 'Karaoke', 'LGBTQ+ nightlife', 'Movies', 'Museums & galleries', 'Salsa dancing', 'Stand up', 'Theater', 'Trivia', 'Wine tasting'],
  'Staying in': ['AI', 'Baking', 'Board games', 'Chess', 'Cooking', 'Gardening', 'House plants', 'Podcasts', 'Programming', 'Reading', 'Video games'],
  'Film and TV': ['Action & adventure', 'Animated', 'Anime', 'Bollywood', 'Comedy', 'Cooking shows', 'Crime', 'Documentaries', 'Drama', 'Fantasy', 'Game shows', 'Horror', 'Indie', 'K-drama', 'Mystery', 'Reality shows', 'Rom-com', 'Romance', 'Sci-fi', 'Superhero', 'Thriller', 'True crime'],
  'Reading': ['Action & adventure', 'Biographies', 'Classics', 'Comedy', 'Comic books', 'Crime', 'Fantasy', 'History', 'Horror', 'Manga', 'Mystery', 'Philosophy', 'Poetry', 'Psychology', 'Romance', 'Sci-fi', 'Science', 'Thriller'],
  'Music': ['Afro', 'Arab', 'Blues', 'Classical', 'Country', 'Desi', 'EDM', 'Electronic', 'Folk & acoustic', 'Funk', 'Gothic', 'Hip hop', 'House', 'Indie', 'Jazz', 'K-pop', 'Latin', 'Metal', 'Pop', 'Punk', 'R&B', 'Rap', 'Reggae', 'Rock', 'Soul', 'Techno'],
  'Food and drink': ['Coffee', 'BBQ', 'Beer', 'Biryani', 'Boba tea', 'Burgers', 'Cake', 'Cocktails', 'Foodie', 'Gin', 'Kimchi', 'Mocktails', 'Pizza', 'Plant-based', 'Smoothies', 'Sushi', 'Sweet tooth', 'Tacos', 'Takeout', 'Tea', 'Vegan', 'Vegetarian', 'Whisky', 'Wine'],
  'Traveling': ['Camping', 'Exploring new cities', 'Backpacking', 'Beaches', 'Fishing trips', 'Hiking trips', 'Road trips', 'Solo trips', 'Spa weekends', 'Staycations', 'Winter sports'],
};
const INTEREST_MAX_PER_CATEGORY = 2;

// Turns a flat tags array (as stored on the user) into a { category: [values] }
// draft for the picker. Some option labels appear in more than one category
// (e.g. "Horror" in both Film and TV and Reading) — when reconstructing the
// draft from a flat list we can't know for certain which category a saved
// tag came from, so each saved tag is assigned to the first category
// (in the order above) that offers it and still has room.
function buildInterestsDraftFromTags(tags) {
  const draft = {};
  const remaining = (tags || []).slice();
  Object.keys(INTEREST_CATEGORIES).forEach(cat => {
    draft[cat] = [];
    INTEREST_CATEGORIES[cat].forEach(opt => {
      if (draft[cat].length >= INTEREST_MAX_PER_CATEGORY) return;
      const idx = remaining.indexOf(opt);
      if (idx > -1) {
        draft[cat].push(opt);
        remaining.splice(idx, 1);
      }
    });
  });
  return draft;
}

function flattenInterestsDraft(draft) {
  const seen = new Set();
  const out = [];
  Object.values(draft).forEach(arr => (arr || []).forEach(v => {
    if (seen.has(v)) return;
    seen.add(v);
    out.push(v);
  }));
  return out;
}

function renderInterestCategoryPicker(containerId, draft) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = Object.keys(INTEREST_CATEGORIES).map(cat => {
    const selected = draft[cat] || [];
    const atCap = selected.length >= INTEREST_MAX_PER_CATEGORY;
    const chips = INTEREST_CATEGORIES[cat].map(opt => {
      const isSel = selected.includes(opt);
      const disabledCls = (!isSel && atCap) ? ' interest-chip-disabled' : '';
      return \`<button type="button" class="filter-chip\${isSel ? ' selected' : ''}\${disabledCls}" data-category="\${escapeHtml(cat)}" data-value="\${escapeHtml(opt)}">\${escapeHtml(opt)}</button>\`;
    }).join('');
    return \`<div class="filter-field-label">\${escapeHtml(cat)} <span class="val">\${selected.length}/\${INTEREST_MAX_PER_CATEGORY}</span></div><div class="filter-chips">\${chips}</div>\`;
  }).join('');
}

function attachInterestCategoryDelegation(containerId, getDraft) {
  const el = document.getElementById(containerId);
  if (!el || el.dataset.catPickerBound) return;
  el.dataset.catPickerBound = '1';
  el.addEventListener('click', (e) => {
    const chip = e.target.closest('.filter-chip');
    if (!chip || chip.classList.contains('interest-chip-disabled')) return;
    const draft = getDraft();
    const cat = chip.dataset.category;
    const val = chip.dataset.value;
    if (!draft[cat]) draft[cat] = [];
    const idx = draft[cat].indexOf(val);
    if (idx > -1) {
      draft[cat].splice(idx, 1);
    } else {
      if (draft[cat].length >= INTEREST_MAX_PER_CATEGORY) return;
      draft[cat].push(val);
    }
    renderInterestCategoryPicker(containerId, draft);
  });
}

async function api(pathName, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  const res = await fetch(pathName, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });
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
  ['f-name','f-age','f-gender','f-country','f-location','f-bio','f-tags-picker'].forEach(id => {
    document.getElementById(id).style.display = mode === 'register' ? 'block' : 'none';
  });
  if (mode === 'register') {
    renderInterestCategoryPicker('f-tags-chips', state.registerInterests);
    attachInterestCategoryDelegation('f-tags-chips', () => state.registerInterests);
  }
  document.getElementById('f-gender').required = mode === 'register';
  document.getElementById('password-hint').style.display = mode === 'register' ? 'block' : 'none';
  document.getElementById('auth-forgot-link').style.display = mode === 'register' ? 'none' : 'block';
  document.getElementById('f-password').autocomplete = mode === 'register' ? 'new-password' : 'current-password';
  document.getElementById('auth-submit-btn').textContent = mode === 'register' ? 'Sign up' : 'Log in';
  document.getElementById('auth-error').style.display = 'none';
}

function showError(msg) {
  const el = document.getElementById('auth-error');
  el.textContent = msg;
  el.style.display = 'block';
}

// Reused for both the main password field and the "new password" field in
// the reset-password panel. Defaults to the main login/signup field so
// existing calls with no arguments keep working.
function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId || 'f-password');
  const button = btn || document.getElementById('password-toggle-btn');
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  button.classList.toggle('is-visible', !showing);
  button.setAttribute('aria-pressed', String(!showing));
  button.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
}

document.getElementById('auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const identity = document.getElementById('f-identity').value;
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
      const tags = flattenInterestsDraft(state.registerInterests);
      if (!gender) { return showError('Please select a gender.'); }
      data = await api('/api/register', { method: 'POST', body: JSON.stringify({ name, identity, password, age, gender, country, location, bio, tags }) });
      justRegistered = true;
    } else {
      data = await api('/api/login', { method: 'POST', body: JSON.stringify({ identity, password }) });
    }
    sessionEpoch++; // treat this as a new session too, in case anything from a prior one is still in flight
    state.token = null;
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

// ---------- Forgot password ----------
let forgotPasswordStep = 'request'; // 'request' | 'reset'

function openForgotPassword() {
  forgotPasswordStep = 'request';
  document.getElementById('fp-identity').value = document.getElementById('f-identity').value || '';
  document.getElementById('fp-code').value = '';
  document.getElementById('fp-new-password').value = '';
  document.getElementById('forgot-step-request').style.display = 'block';
  document.getElementById('forgot-step-reset').style.display = 'none';
  document.getElementById('forgot-step-btn').textContent = 'Send reset code';
  document.getElementById('forgot-request-error').style.display = 'none';
  document.getElementById('forgot-reset-error').style.display = 'none';
  document.getElementById('forgot-password-overlay').classList.add('open');
  document.getElementById('forgot-password-panel').classList.add('open');
}

function closeForgotPassword() {
  document.getElementById('forgot-password-overlay').classList.remove('open');
  document.getElementById('forgot-password-panel').classList.remove('open');
}

async function submitForgotPasswordStep() {
  if (forgotPasswordStep === 'request') {
    const identity = document.getElementById('fp-identity').value.trim();
    const errEl = document.getElementById('forgot-request-error');
    errEl.style.display = 'none';
    if (!identity) { errEl.textContent = 'Enter your email or phone number.'; errEl.style.display = 'block'; return; }
    try {
      await api('/api/forgot-password', { method: 'POST', body: JSON.stringify({ identity }) });
      forgotPasswordStep = 'reset';
      document.getElementById('forgot-step-request').style.display = 'none';
      document.getElementById('forgot-step-reset').style.display = 'block';
      document.getElementById('forgot-step-btn').textContent = 'Reset password';
      document.getElementById('forgot-reset-hint').textContent =
        'If an account exists for ' + identity + ', a 6-digit code was sent. Enter it below with your new password.';
    } catch (err) {
      errEl.textContent = err.message;
      errEl.style.display = 'block';
    }
  } else {
    const identity = document.getElementById('fp-identity').value.trim();
    const code = document.getElementById('fp-code').value.trim();
    const newPassword = document.getElementById('fp-new-password').value;
    const errEl = document.getElementById('forgot-reset-error');
    errEl.style.display = 'none';
    if (!code || !newPassword) { errEl.textContent = 'Enter the code and a new password.'; errEl.style.display = 'block'; return; }
    try {
      await api('/api/reset-password', { method: 'POST', body: JSON.stringify({ identity, code, newPassword }) });
      closeForgotPassword();
      showError('Password reset. Please log in with your new password.');
      document.getElementById('f-identity').value = identity;
      document.getElementById('f-password').value = '';
    } catch (err) {
      errEl.textContent = err.message;
      errEl.style.display = 'block';
    }
  }
}

// Defense-in-depth: wipe every place a name/photo/bio is shown before the
// auth screen takes over on logout, so no residual PII from the account
// that's logging out is left visible for even a frame.
function blankProfileView() {
  ['ph-name', 'me-name', 'ph-meta', 'ph-tagline', 'ph-bio-text'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '';
  });
  ['ph-interests-chips', 'ph-about-pills', 'ph-lookingfor-pills', 'ph-vibes-grid', 'ph-prompts-list'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });
  ['ph-photo-preview', 'me-avatar', 'top-avatar'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = '';
    el.removeAttribute('style');
  });
}

async function logout() {
  sessionEpoch++; // invalidate any in-flight requests from this account
  if (state.eventSource) state.eventSource.close();
  document.body.classList.remove('chat-open');
  blankProfileView();
  try { await api('/api/logout', { method: 'POST' }); } catch (e) { /* best-effort */ }
  state = createFreshState();
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

  const es = new EventSource('/api/stream');
  state.eventSource = es;

  es.addEventListener('message', (e) => {
    const msg = JSON.parse(e.data);
    if (state.activeChat === msg.matchKey) {
      hideTypingIndicator();
      // Only load (which marks messages as read) if the person can actually
      // see the chat; otherwise it's loaded when they come back to the tab.
      if (document.visibilityState === 'visible') loadChatMessages(msg.matchKey);
      else loadMatches();
    } else {
      loadMatches();
    }
  });

  es.addEventListener('typing', (e) => {
    const d = JSON.parse(e.data);
    if (state.activeChat === d.matchKey) showTypingIndicator();
  });

  es.addEventListener('read', (e) => {
    const d = JSON.parse(e.data);
    if (state.activeChat === d.matchKey) loadChatMessages(d.matchKey);
  });

  es.addEventListener('message_deleted', (e) => {
    const d = JSON.parse(e.data);
    if (state.activeChat === d.matchKey) loadChatMessages(d.matchKey);
    else loadMatches();
  });

  es.addEventListener('unmatch', (e) => {
    const d = JSON.parse(e.data);
    if (state.activeChat === d.matchKey) switchView('matches');
    loadMatches();
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
  document.body.classList.remove('discover-fit'); // re-applied by renderDiscoverList() for Discover
  _navItems.forEach(n => n.classList.toggle('active', n.dataset.view === view));
  _mobileNavItems.forEach(n => {
    const isActive = n.dataset.view === view;
    n.classList.toggle('active', isActive);
    if (n.classList.contains('mobile-nav-fab')) return;
    if (isActive) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
  });
  const titles = { discover: 'Discover', matches: 'Messages', likes: 'Likes You', explore: 'Explore', profile: 'My Profile' };
  document.getElementById('view-title').textContent = titles[view] || 'Discover';

  // On the Profile tab there's nothing to search or filter, so swap the
  // filter button out for a settings button instead.
  const isProfile = view === 'profile';
  document.getElementById('filter-trigger-btn').style.display = isProfile ? 'none' : '';
  document.getElementById('profile-settings-btn').style.display = isProfile ? '' : 'none';

  if (view === 'discover') { document.getElementById('panel-discover').classList.add('visible'); renderDiscoverList(); }
  else if (view === 'matches') { document.getElementById('panel-matches').classList.add('visible'); renderMatchesFull(); }
  else if (view === 'likes') { document.getElementById('panel-likes').classList.add('visible'); renderAdmirers(); }
  else if (view === 'explore') { document.getElementById('panel-explore').classList.add('visible'); renderExploreGrid(); }
  else if (view === 'profile') { document.getElementById('panel-profile').classList.add('visible'); fillProfileForm(); }
}

// ---------- Discover ----------

// Country narrowing now lives only in the filter panel (state.filters.country,
// applied client-side by matchesFilters) — this always loads the full
// discoverable set from the server.
async function loadDiscover() {
  const epoch = sessionEpoch;
  const data = await api('/api/discover');
  if (epoch !== sessionEpoch) return; // account changed while this request was in flight
  state.allCandidates = data.candidates || [];
  state.likedProfiles = data.likedProfiles || [];
  state.nearbyProfiles = data.nearbyProfiles || [];
  state.newProfiles = data.newProfiles || [];
  state.candidates = state.allCandidates.filter(c => matchesFilters(c, state.filters));
  state.nearbyProfiles = state.nearbyProfiles.filter(c => matchesFilters(c, state.filters));
  state.newProfiles = state.newProfiles.filter(c => matchesFilters(c, state.filters));
  state.likedProfiles = state.likedProfiles.filter(c => matchesFilters(c, state.filters));
}

// Fields that now have a real column on the user profile (filled in via
// the post-signup "complete your profile" screen or the Profile tab) are
// checked here for real. verified/onlineNow/distance still have no backing
// data (verified needs an admin flag, onlineNow needs presence tracking,
// distance needs geolocation) so they remain pass-through until those exist.
function matchesFilters(c, f) {
  if (f.showMe && f.showMe !== 'everyone') {
    if (f.showMe === 'men' && c.gender !== 'man') return false;
    if (f.showMe === 'women' && c.gender !== 'woman') return false;
    if (f.showMe === 'nonbinary' && (c.gender === 'man' || c.gender === 'woman')) return false;
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

function onTextFilterInput(key, el) {
  state.filters[key] = el.value;
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

  document.getElementById('f-filter-country').value = f.country;
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
  if (document.getElementById('panel-discover').classList.contains('visible')) renderDiscoverList();
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

// ---------- Interests panel (own "Edit" entry point, like About Me) ----------

function openInterestsPanel() {
  state.interestsDraft = buildInterestsDraftFromTags(state.user ? state.user.tags : []);
  renderInterestCategoryPicker('interests-panel-body', state.interestsDraft);
  attachInterestCategoryDelegation('interests-panel-body', () => state.interestsDraft);
  document.getElementById('interests-overlay').classList.add('open');
  document.getElementById('interests-panel').classList.add('open');
  document.getElementById('interests-panel').setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
}

function closeInterestsPanel() {
  document.getElementById('interests-overlay').classList.remove('open');
  document.getElementById('interests-panel').classList.remove('open');
  document.getElementById('interests-panel').setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}

function clearAllInterests() {
  state.interestsDraft = {};
  renderInterestCategoryPicker('interests-panel-body', state.interestsDraft);
}

async function saveInterestsAndClose() {
  const tags = flattenInterestsDraft(state.interestsDraft);
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify({ tags }) });
    state.user = data.user;
    refreshProfileViewMode();
    updateProfileCompletionDisplay();
    closeInterestsPanel();
  } catch (err) {
    alert(err.message || 'Could not save your interests. Please try again.');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  syncSettingsUI();
  attachChipDelegation(document.getElementById('filter-panel'), () => state.filters);
  attachChipDelegation(document.getElementById('details-form-body'), () => state.details, updateDetailsProgress);
  attachChipDelegation(document.getElementById('looking-for-form-body'), () => lookingForDraft);

  // Keep the select-based About Me fields in state while editing.
  const detailsBody = document.getElementById('details-form-body');
  if (detailsBody) {
    detailsBody.querySelectorAll('#d-education, #d-religion, #d-political').forEach(select => {
      select.addEventListener('change', () => {
        const key = select.id === 'd-education' ? 'education' : select.id === 'd-religion' ? 'religion' : 'political';
        state.details[key] = select.value;
        updateDetailsProgress();
      });
    });
  }

  updateFilterBadge();
});

// Builds the full rich profile card (photo + About Me/Interests/Vibes/
// Prompts/Compatibility Answers) — used inside the "view profile" modal
// opened from a Discover row.
// Minimal "may like" carousel photo: just the picture with name, age, and
// location overlaid — no bio/interests/vibes. Tapping it opens the full
// profile (buildCandidateCardHTML) in the detail modal.
// Interest tags are grouped into categories (see INTEREST_CATEGORIES above).
// This reverse-looks-up a tag's category and pairs it with a small icon, so
// a candidate's picked interests can render as icon+label pills — used on
// the Discover "may like" photo card, right under their location.
const TAG_CATEGORY_LOOKUP = (() => {
  const map = {};
  Object.keys(INTEREST_CATEGORIES).forEach(cat => {
    INTEREST_CATEGORIES[cat].forEach(tag => { map[tag] = cat; });
  });
  return map;
})();

const CATEGORY_ICONS = {
  'Pets': '<svg viewBox="0 0 24 24" width="11" height="11" aria-hidden="true" focusable="false"><circle cx="7" cy="7" r="2" fill="currentColor"/><circle cx="12" cy="5.5" r="2" fill="currentColor"/><circle cx="17" cy="7" r="2" fill="currentColor"/><circle cx="19" cy="12" r="2" fill="currentColor"/><path d="M12 12c-3.5 0-6.5 2.3-6.5 5.2 0 1.7 1.5 2.8 3.3 2.2.9-.3 1.8-.5 3.2-.5s2.3.2 3.2.5c1.8.6 3.3-.5 3.3-2.2 0-2.9-3-5.2-6.5-5.2Z" fill="currentColor"/></svg>',
  'Personality and traits': '<svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg>',
  'Self-care': '<svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 21s-7-4.35-9.5-9A5.5 5.5 0 0 1 12 6a5.5 5.5 0 0 1 9.5 6c-2.5 4.65-9.5 9-9.5 9Z"/></svg>',
  'Sports': '<svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="m3 19 6.5-11L13 14l3-5 5 10Z"/></svg>',
  'Creativity': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 21c1-4 3-6 6-7l9-9 3 3-9 9c-1 3-3 5-7 6a2 2 0 0 1-2-2Z"/></svg>',
  'Going out': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 4h14l-7 8Z"/><path d="M12 12v7M8 19h8"/></svg>',
  'Staying in': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 11 12 3l9 8"/><path d="M5 10v10h14V10"/></svg>',
  'Film and TV': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M7 21V9a5 5 0 0 1 10 0v12l-2-1.5-1.5 1.5L12 19.5 10.5 21 9 19.5Z"/><circle cx="10" cy="8" r="1" fill="currentColor" stroke="none"/><circle cx="14" cy="8" r="1" fill="currentColor" stroke="none"/></svg>',
  'Reading': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H12v18H6.5A2.5 2.5 0 0 1 4 18.5Z"/><path d="M20 5.5A2.5 2.5 0 0 0 17.5 3H12v18h5.5a2.5 2.5 0 0 0 2.5-2.5Z"/></svg>',
  'Music': '<svg viewBox="0 0 24 24" width="11" height="11" aria-hidden="true" focusable="false"><circle cx="6.5" cy="18" r="2.5" fill="currentColor"/><circle cx="17.5" cy="16" r="2.5" fill="currentColor"/><path d="M9 18V5l11-2v13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  'Food and drink': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 8h13v5a5 5 0 0 1-5 5H9a5 5 0 0 1-5-5Z"/><path d="M17 9h1.5a2.5 2.5 0 0 1 0 5H17"/><path d="M7 3.5c0 1-1 1-1 2s1 1 1 2M11 3.5c0 1-1 1-1 2s1 1 1 2"/></svg>',
  'Traveling': '<svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M21 16v-1.5l-8-5V4.5a1.5 1.5 0 0 0-3 0v5l-8 5V16l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5Z"/></svg>',
};

function interestTagIcon(tag) {
  const cat = TAG_CATEGORY_LOOKUP[tag];
  return (cat && CATEGORY_ICONS[cat]) || CATEGORY_ICONS['Personality and traits'];
}

// Up to "max" icon+label pills for a candidate's picked interests.
function buildInterestTagPillsHTML(tags, max = 4) {
  if (!tags || !tags.length) return '';
  return \`<div class="interest-tags-row">\${tags.slice(0, max).map(t =>
    \`<span class="interest-tag-pill">\${interestTagIcon(t)}\${escapeHtml(t)}</span>\`
  ).join('')}</div>\`;
}

function buildCandidateMiniPhotoHTML(c) {
  const photoStyle = c.photoUrl
    ? \`background-image:url('\${c.photoUrl}');background-size:cover;background-position:center;\`
    : \`background:linear-gradient(135deg, \${colorFor(c.name)}, #2a1620);\`;
  return \`
    <div class="swipe-photo discover-carousel-photo" style="\${photoStyle}">
      <div class="info-affordance" title="Tap to view full profile"><svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="8" r="1.3" fill="currentColor" stroke="none"/><path d="M12 11v5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></div>
      \${c.compatibility !== null && c.compatibility !== undefined ? \`<div class="photo-counter compat-badge" style="position:absolute;top:12px;right:12px;"><svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${c.compatibility}% Match</div>\` : ''}
      <div class="swipe-details">
        <div class="name-row">\${escapeHtml(c.name)}\${c.age ? ', ' + c.age : ''}</div>
        \${c.location ? \`<div class="meta"><span><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 21s7-6.5 7-11.5A7 7 0 1 0 5 9.5C5 14.5 12 21 12 21Z"/><circle cx="12" cy="9.5" r="2.2"/></svg> \${escapeHtml(c.location)}</span></div>\` : ''}
        \${buildInterestTagPillsHTML(c.tags)}
      </div>
    </div>\`;
}

function buildCandidateCardHTML(c) {
  const photoStyle = c.photoUrl
    ? \`background-image:url('\${c.photoUrl}');background-size:cover;background-position:center;\`
    : \`background:linear-gradient(135deg, \${colorFor(c.name)}, #2a1620);\`;
  return \`
    <div class="swipe-card">
      <div class="swipe-photo" style="\${photoStyle}">
        <div class="photo-tag"><svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${c.tags && c.tags.length ? escapeHtml(c.tags[0]) : 'New here'}</div>
        \${c.compatibility !== null && c.compatibility !== undefined ? \`<div class="photo-counter compat-badge" style="position:absolute;top:16px;right:16px;"><svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${c.compatibility}% Match</div>\` : ''}
        <div class="swipe-details">
          <div class="name-row">\${escapeHtml(c.name)}\${c.age ? ', ' + c.age : ''}</div>
          <div class="meta">\${c.location ? '<span><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 21s7-6.5 7-11.5A7 7 0 1 0 5 9.5C5 14.5 12 21 12 21Z"/><circle cx="12" cy="9.5" r="2.2"/></svg> ' + escapeHtml(c.location) + '</span>' : ''}</div>
        </div>
      </div>
      <div class="swipe-card-body">
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg></span>About Me</div>
          <p class="swipe-section-text \${c.bio ? '' : 'empty'}">\${c.bio ? escapeHtml(c.bio) : 'No bio yet.'}</p>
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
          <div class="interests-chips">\${c.tags.map(t => '<span class="interest-chip">' + escapeHtml(t) + '</span>').join('')}</div>
        </div>\` : ''}
        \${c.galleryUrls && c.galleryUrls.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="3" y="6" width="18" height="14" rx="2.5"/><circle cx="12" cy="13" r="3.5"/><path d="M8 6l1.4-2.4A1.5 1.5 0 0 1 10.7 3h2.6a1.5 1.5 0 0 1 1.3.76L16 6"/></svg></span>My Vibes</div>
          <div class="swipe-vibes-grid">\${c.galleryUrls.map((url, i) => '<div class="swipe-vibes-thumb" onclick="event.stopPropagation(); openPhotoLightbox(' + escapeHtml(JSON.stringify(c.galleryUrls)) + ', ' + i + ')"><img src="' + escapeHtml(url) + '" alt="Vibes photo ' + (i + 1) + '" loading="lazy" /></div>').join('')}</div>
        </div>\` : ''}
        \${c.prompts && c.prompts.filter(p => p && p.question && p.answer).length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></span>Prompts</div>
          \${c.prompts.filter(p => p && p.question && p.answer).map(p => '<div class="prompt-view-card"><div class="prompt-view-question">' + escapeHtml(p.question) + '</div><div class="prompt-view-answer">' + escapeHtml(p.answer) + '</div></div>').join('')}
        </div>\` : ''}
        \${c.quizAnswers && c.quizAnswers.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></span>Compatibility Answers</div>
          \${c.quizAnswers.map(q => '<div class="prompt-view-card"><div class="prompt-view-question">' + escapeHtml(q.question) + '</div><div class="prompt-view-answer">' + escapeHtml(q.answer) + '</div></div>').join('')}
        </div>\` : ''}
      </div>
    </div>
  \`;
}

// ---------- Discover — swipeable card stack ----------
// Renders up to 3 cards stacked with a slight offset; only the top card is
// draggable. Swipe (or drag past the threshold) right = like, left = pass.
function renderDiscoverSectionRow(c, allowLike) {
  const photo = c.photoUrl ? \`background-image:url('\${escapeHtml(c.photoUrl)}')\` : \`background:\${colorFor(c.name)}\`;
  const tags = (c.tags || []).slice(0, 3).map(t => \`<span>\${escapeHtml(t)}</span>\`).join('');
  return \`
    <div class="discover-row" onclick="openCandidateDetail('\${escapeHtml(c.id)}')">
      <div class="discover-row-photo" style="\${photo}"></div>
      <div class="discover-row-body">
        <div class="discover-row-name">\${escapeHtml(c.name)}\${c.age ? ', ' + c.age : ''}</div>
        <div class="discover-row-loc">\${escapeHtml(c.location || c.country || '')}</div>
        \${c.bio ? \`<div class="discover-row-bio">\${escapeHtml(c.bio)}</div>\` : ''}
        \${tags ? \`<div class="discover-row-tags">\${tags}</div>\` : ''}
      </div>
      \${allowLike ? \`<button class="discover-row-like" type="button" onclick="event.stopPropagation(); discoverSectionLike('\${escapeHtml(c.id)}')" aria-label="Like \${escapeHtml(c.name)}" title="Like">♥</button>\` : ''}
    </div>\`;
}

function renderDiscoverSection(profiles, allowLike) {
  if (!profiles || !profiles.length) return '';
  return \`<section class="discover-section">
    <div>\${profiles.map(c => renderDiscoverSectionRow(c, allowLike)).join('')}</div>
  </section>\`;
}

// Tab id -> heading shown above the cards, and the profile list it draws from.
const DISCOVER_TAB_META = {
  maylike: { label: 'Profiles You May Like', list: () => state.candidates, allowLike: null },
  liked: { label: 'Profiles You Liked', list: () => state.likedProfiles, allowLike: false },
  nearby: { label: 'Users Nearby', list: () => state.nearbyProfiles, allowLike: true },
  new: { label: 'New Users', list: () => state.newProfiles, allowLike: true },
};

function renderDiscoverList() {
  const stack = document.getElementById('discover-list');
  const hint = document.getElementById('discover-stack-hint');
  const actions = document.getElementById('discover-stack-actions');
  const heading = document.getElementById('discover-tab-heading');
  const count = document.getElementById('discover-tab-count');
  if (!stack) return;
  closeAllDiscoverMenus();

  const tab = state.activeDiscoverTab || 'maylike';
  const meta = DISCOVER_TAB_META[tab] || DISCOVER_TAB_META.maylike;
  const list = meta.list();

  // Phones: while the carousel has profiles, the whole screen is laid out
  // to fit exactly (see body.discover-fit in the CSS) so Like/Pass never
  // need scrolling to. Off for every other tab/view and for empty states.
  const discoverPanel = document.getElementById('panel-discover');
  document.body.classList.toggle('discover-fit',
    !!(discoverPanel && discoverPanel.classList.contains('visible')) && tab === 'maylike' && list.length > 0);

  // Keeps the carousel area a fixed height (card-sized) whether it's full
  // or showing "no more profiles" — only for the maylike tab; row-list
  // tabs (Liked/Nearby/New) size to their own content as before.
  stack.classList.toggle('discover-stack--carousel', tab === 'maylike');

  // The tab name above the cards updates immediately on every tab switch,
  // independent of whatever layout that tab's cards use below it.
  if (heading && count) {
    heading.childNodes[0].textContent = meta.label + ' ';
    count.textContent = list.length;
  }

  const navPrev = document.getElementById('discover-nav-prev');
  const navNext = document.getElementById('discover-nav-next');
  const exploreHint = document.getElementById('discover-explore-hint');
  const showCarouselUi = tab === 'maylike' && list.length > 0;
  if (hint) hint.style.display = showCarouselUi ? '' : 'none';
  if (actions) actions.style.display = showCarouselUi ? '' : 'none';
  if (exploreHint) exploreHint.style.display = showCarouselUi ? '' : 'none';
  if (navPrev) navPrev.style.display = showCarouselUi ? '' : 'none';
  if (navNext) navNext.style.display = showCarouselUi ? '' : 'none';

  if (tab !== 'maylike') {
    stack.innerHTML = renderDiscoverSection(list, meta.allowLike) || '<div class="empty-state">No profiles in this section right now.</div>';
    return;
  }

  if (!list.length) {
    stack.innerHTML = '<div class="empty-state">No more profiles right now. Check back later!</div>';
    return;
  }

  // Everyone in the queue scrolls left-to-right as a filmstrip of compact
  // photo cards (picture, name, age, location). Tapping a card opens the
  // full profile; the Pass/Like buttons below the carousel act on
  // whichever card is currently snapped into view (ringed in pink).
  const cards = list.map(c => \`
      <div class="discover-carousel-card" data-id="\${c.id}" onclick="openCandidateDetail('\${c.id}')">\${buildCandidateMiniPhotoHTML(c)}</div>\`).join('');

  stack.innerHTML = \`<section class="discover-section discover-like-section">
    <div class="discover-carousel" id="discover-carousel">\${cards}</div>
  </section>\`;

  const track = document.getElementById('discover-carousel');
  if (track) {
    track.addEventListener('scroll', updateCarouselCurrent, { passive: true });
    updateCarouselCurrent();
  }
}

// Tracks which carousel card is currently snapped into view, so the Pass/
// Like buttons below the carousel know which profile to act on.
function updateCarouselCurrent() {
  const track = document.getElementById('discover-carousel');
  if (!track) return;
  let closest = null, closestDist = Infinity;
  track.querySelectorAll('.discover-carousel-card').forEach(el => {
    const dist = Math.abs(el.offsetLeft - track.scrollLeft);
    if (dist < closestDist) { closestDist = dist; closest = el; }
  });
  track.querySelectorAll('.discover-carousel-card.is-current').forEach(el => el.classList.remove('is-current'));
  if (closest) {
    closest.classList.add('is-current');
    state.carouselCurrentId = closest.getAttribute('data-id');
  } else {
    state.carouselCurrentId = null;
  }
}

// Scrolls the "may like" filmstrip by roughly one card width. Purely a
// browsing aid for pointer/keyboard users — it never records a like/pass.
function scrollDiscoverCarousel(delta) {
  const track = document.getElementById('discover-carousel');
  if (!track) return;
  const card = track.querySelector('.discover-carousel-card');
  const amount = (card ? card.getBoundingClientRect().width : track.clientWidth) + 16;
  track.scrollBy({ left: delta * amount, behavior: 'smooth' });
}

function setDiscoverTab(tab) {
  if (!DISCOVER_TAB_META[tab]) return;
  state.activeDiscoverTab = tab;
  state.carouselCurrentId = null;
  document.querySelectorAll('.discover-category-tabs button').forEach(btn => {
    const isActive = btn.getAttribute('onclick') === \`setDiscoverTab('\${tab}')\`;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });
  renderDiscoverList();
}

async function discoverSectionLike(id) {
  const c = state.allCandidates.find(x => x.id === id);
  if (!c) return;
  try {
    const data = await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: c.id, direction: 'like' }) });
    state.candidates = state.candidates.filter(x => x.id !== id);
    state.allCandidates = state.allCandidates.filter(x => x.id !== id);
    state.nearbyProfiles = state.nearbyProfiles.filter(x => x.id !== id);
    state.newProfiles = state.newProfiles.filter(x => x.id !== id);
    state.likedProfiles = [c, ...state.likedProfiles.filter(x => x.id !== id)];
    renderDiscoverList();
    if (data.matched) {
      await loadMatches();
      alert("It's a match with " + c.name + "!");
    }
  } catch (err) {
    alert(err.message);
  }
}

// Reload button: re-fetches the Discover feed from the server (and the
// match list, so the Message button knows about brand-new matches) and
// re-renders the current tab.
async function reloadDiscover() {
  if (state.discoverReloading) return;
  const btns = document.querySelectorAll('.act-reload');
  state.discoverReloading = true;
  btns.forEach(b => { b.disabled = true; b.classList.add('spinning'); });
  try {
    await Promise.all([loadDiscover(), loadMatches()]);
    state.carouselCurrentId = null;
    renderDiscoverList();
  } catch (err) {
    alert(err && err.message ? err.message : 'Could not reload profiles. Please try again.');
  } finally {
    state.discoverReloading = false;
    btns.forEach(b => { b.disabled = false; b.classList.remove('spinning'); });
  }
}

// Message button: acts on the card currently in view. The server only lets
// two people message each other once they've matched, so if there's no
// match yet we explain that instead of opening an empty chat.
function messageCurrentCard() {
  if (!state.carouselCurrentId) return;
  messageCandidate(state.carouselCurrentId);
}

// Opens the chat with this person if you've already matched; otherwise
// explains that messaging unlocks after a match. Returns true if a chat
// was opened (the profile popup uses that to know whether to close).
function messageCandidate(id) {
  const match = (state.matches || []).find(m => m.user && m.user.id === id);
  if (match) {
    closeCandidateDetail();
    switchView('matches');
    openChat(match.matchKey);
    return true;
  }
  const c = getCandidateById(id);
  const name = c && c.name ? c.name : 'this person';
  alert('You can message ' + name + ' once you both like each other. Tap the heart to like them first!');
  return false;
}

// Fired by the Pass/Like buttons below the carousel — they always act on
// state.carouselCurrentId, the card currently snapped into view.
function swipeCurrentCard(direction) {
  if (!state.carouselCurrentId) return;
  const btn = document.querySelector(\`#discover-stack-actions .\${direction === 'like' ? 'act-like' : 'act-pass'}\`);
  if (btn) { btn.classList.remove('tap-pop'); void btn.offsetWidth; btn.classList.add('tap-pop'); }
  if (direction === 'like') carouselLikeCandidate(state.carouselCurrentId);
  else carouselPassCandidate(state.carouselCurrentId);
}

// After a card is removed from the "may like" queue (liked or passed),
// re-render and keep the filmstrip roughly where the user was rather than
// snapping back to the start.
function rerenderCarouselKeepingPosition(removedIdx) {
  renderDiscoverList();
  const track = document.getElementById('discover-carousel');
  if (!track) return;
  const cards = track.querySelectorAll('.discover-carousel-card');
  if (!cards.length) return;
  const target = cards[Math.min(removedIdx, cards.length - 1)];
  if (target) track.scrollLeft = target.offsetLeft;
  updateCarouselCurrent();
}

// The heart Like button below the carousel. Commits the like and drops the
// card out of the filmstrip.
async function carouselLikeCandidate(id) {
  if (state.swipeBusy) return;
  const idx = state.candidates.findIndex(x => x.id === id);
  if (idx === -1) return;
  const c = state.candidates[idx];
  state.swipeBusy = true;
  try {
    const data = await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: c.id, direction: 'like' }) });
    state.candidates.splice(idx, 1);
    state.allCandidates = state.allCandidates.filter(x => x.id !== c.id);
    state.likedProfiles = [c, ...state.likedProfiles.filter(x => x.id !== c.id)];
    rerenderCarouselKeepingPosition(idx);
    if (data.matched) {
      await loadMatches();
      alert("It's a match with " + c.name + "!");
    }
  } catch (err) {
    alert(err.message);
  } finally {
    state.swipeBusy = false;
  }
}

// The X Pass button below the carousel. Records the pass and drops the
// card out of the filmstrip (it won't be shown again).
async function carouselPassCandidate(id) {
  if (state.swipeBusy) return;
  const idx = state.candidates.findIndex(x => x.id === id);
  if (idx === -1) return;
  state.swipeBusy = true;
  try {
    await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: id, direction: 'pass' }) });
    state.candidates.splice(idx, 1);
    state.allCandidates = state.allCandidates.filter(x => x.id !== id);
    rerenderCarouselKeepingPosition(idx);
  } catch (err) {
    alert(err.message);
  } finally {
    state.swipeBusy = false;
  }
}


function toggleDiscoverRowMenu(event, id) {
  const menu = document.getElementById('row-menu-' + id);
  if (!menu) return;
  const wasOpen = menu.classList.contains('open');
  closeAllDiscoverMenus();
  if (!wasOpen) menu.classList.add('open');
}
function closeAllDiscoverMenus() {
  document.querySelectorAll('.discover-row-menu.open').forEach(m => m.classList.remove('open'));
}

let currentDetailCandidateId = null;

function getCandidateById(id) {
  return state.candidates.find(x => x.id === id)
    || state.likedProfiles.find(x => x.id === id)
    || state.nearbyProfiles.find(x => x.id === id)
    || state.newProfiles.find(x => x.id === id)
    || null;
}

function openCandidateDetail(id) {
  const c = getCandidateById(id);
  if (!c) return;
  currentDetailCandidateId = id;
  document.getElementById('candidate-detail-body').innerHTML = buildCandidateCardHTML(c);
  document.getElementById('candidate-detail-footer').innerHTML = \`
    <button type="button" class="act-reload" onclick="reloadDiscover().then(closeCandidateDetail)" aria-label="Reload profiles" title="Reload profiles"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20 11a8 8 0 0 0-14.5-4.5L4 8"/><path d="M4 4v4h4"/><path d="M4 13a8 8 0 0 0 14.5 4.5L20 16"/><path d="M20 20v-4h-4"/></svg></button>
    <button type="button" class="act-pass" onclick="discoverListAction('\${escapeHtml(id)}','pass'); closeCandidateDetail();" aria-label="Pass" title="Pass"><svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg></button>
    <button type="button" class="act-like" onclick="discoverListAction('\${escapeHtml(id)}','like'); closeCandidateDetail();" aria-label="Like" title="Like"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></button>
    <button type="button" class="act-message" onclick="messageCandidate('\${escapeHtml(id)}')" aria-label="Message" title="Message"><span class="act-emoji" aria-hidden="true">💬</span></button>
  \`;
  document.getElementById('candidate-detail-modal').classList.add('visible');
}
function closeCandidateDetail() {
  document.getElementById('candidate-detail-modal').classList.remove('visible');
  currentDetailCandidateId = null;
}

// ---------- Block / Report action sheet ----------
function openProfileActionSheet() {
  if (!currentDetailCandidateId) return;
  const c = getCandidateById(currentDetailCandidateId);
  const name = c ? c.name : 'this profile';
  document.getElementById('action-sheet-body').innerHTML = \`
    <button type="button" class="action-sheet-row danger" onclick="confirmBlockCurrentCandidate()">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M5.5 5.5l13 13"/></svg>
      Block \${escapeHtml(name)}
    </button>
    <button type="button" class="action-sheet-row danger" onclick="openReportSheet()">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 2.7 17a2 2 0 0 0 1.7 3h15.2a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>
      Report \${escapeHtml(name)}
    </button>
    <button type="button" class="action-sheet-row cancel" onclick="closeActionSheet()">Cancel</button>
  \`;
  document.getElementById('action-sheet-overlay').classList.add('open');
}

function closeActionSheet() {
  document.getElementById('action-sheet-overlay').classList.remove('open');
}

function removeCandidateEverywhere(id) {
  state.candidates = state.candidates.filter(x => x.id !== id);
  state.allCandidates = state.allCandidates.filter(x => x.id !== id);
  state.likedProfiles = state.likedProfiles.filter(x => x.id !== id);
  state.nearbyProfiles = state.nearbyProfiles.filter(x => x.id !== id);
  state.newProfiles = state.newProfiles.filter(x => x.id !== id);
}

async function confirmBlockCurrentCandidate() {
  const id = currentDetailCandidateId;
  if (!id) return;
  const c = getCandidateById(id);
  const name = c ? c.name : 'this person';
  closeActionSheet();
  if (!confirm(\`Block \${name}? You won't see each other in Discover anymore, and any match between you will be removed.\`)) return;
  try {
    await api('/api/block', { method: 'POST', body: JSON.stringify({ targetUserId: id }) });
    removeCandidateEverywhere(id);
    closeCandidateDetail();
    renderDiscoverList();
  } catch (err) {
    alert(err.message);
  }
}

const REPORT_REASONS = ['Inappropriate photos', 'Harassment or abuse', 'Fake profile', 'Spam or scam', 'Underage user', 'Something else'];

function openReportSheet() {
  const id = currentDetailCandidateId;
  const c = getCandidateById(id);
  const name = c ? c.name : 'this profile';
  document.getElementById('action-sheet-body').innerHTML = \`
    <div class="action-sheet-row" style="cursor:default;">Report \${escapeHtml(name)} — why?</div>
    <div class="report-reason-list">
      \${REPORT_REASONS.map(r => \`<button type="button" onclick="submitReportCurrentCandidate(\${escapeHtml(JSON.stringify(r))})">\${escapeHtml(r)}</button>\`).join('')}
    </div>
    <button type="button" class="action-sheet-row cancel" onclick="closeActionSheet()">Cancel</button>
  \`;
}

async function submitReportCurrentCandidate(reason) {
  const id = currentDetailCandidateId;
  if (!id) return;
  closeActionSheet();
  try {
    await api('/api/report', { method: 'POST', body: JSON.stringify({ reportedUserId: id, reason }) });
    alert('Thanks — your report has been submitted. Our team will review it.');
  } catch (err) {
    alert(err.message);
  }
}

// ---------- Photo lightbox (full-size vibes photos) ----------
let lightboxState = { urls: [], index: 0 };

function openPhotoLightbox(urls, index) {
  if (!Array.isArray(urls) || !urls.length) return;
  lightboxState = { urls, index: Math.min(Math.max(index, 0), urls.length - 1) };
  renderPhotoLightbox();
  document.getElementById('photo-lightbox').classList.add('visible');
  document.addEventListener('keydown', handlePhotoLightboxKeydown);
}

function closePhotoLightbox() {
  document.getElementById('photo-lightbox').classList.remove('visible');
  document.removeEventListener('keydown', handlePhotoLightboxKeydown);
}

function navPhotoLightbox(delta) {
  const max = lightboxState.urls.length - 1;
  const next = lightboxState.index + delta;
  if (next < 0 || next > max) return;
  lightboxState.index = next;
  renderPhotoLightbox();
}

function renderPhotoLightbox() {
  const { urls, index } = lightboxState;
  document.getElementById('photo-lightbox-img').src = urls[index];
  document.getElementById('photo-lightbox-prev').disabled = index <= 0;
  document.getElementById('photo-lightbox-next').disabled = index >= urls.length - 1;
  const counter = document.getElementById('photo-lightbox-counter');
  counter.style.display = urls.length > 1 ? '' : 'none';
  counter.textContent = (index + 1) + ' / ' + urls.length;
}

function handlePhotoLightboxKeydown(e) {
  if (e.key === 'Escape') closePhotoLightbox();
  else if (e.key === 'ArrowLeft') navPhotoLightbox(-1);
  else if (e.key === 'ArrowRight') navPhotoLightbox(1);
}

async function discoverListAction(id, direction) {
  const idx = state.candidates.findIndex(x => x.id === id);
  if (idx === -1) return;
  const c = state.candidates[idx];
  try {
    const data = await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: c.id, direction }) });
    state.candidates.splice(idx, 1);
    state.allCandidates = state.allCandidates.filter(x => x.id !== c.id);
    renderDiscoverList();
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
  const epoch = sessionEpoch;
  const data = await api('/api/matches');
  if (epoch !== sessionEpoch) return; // account changed while this request was in flight
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
        <div class="mname">\${escapeHtml(m.user.name)}</div>
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
          <div class="msg-top"><span class="mname">\${escapeHtml(m.user.name)}</span><span class="time">\${timeAgo(m.lastMessage.createdAt)}</span></div>
          <div class="msg-preview"><span class="text">\${escapeHtml(m.lastMessage.text)}</span>\${m.unread ? '<span class="unread-dot">' + m.unread + '</span>' : ''}</div>
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
        <div class="msg-top"><span class="mname">\${escapeHtml(m.user.name)}</span><span class="time">\${m.lastMessage ? timeAgo(m.lastMessage.createdAt) : 'Matched ' + timeAgo(m.createdAt)}</span></div>
        <div class="msg-preview"><span class="text">\${m.lastMessage ? escapeHtml(m.lastMessage.text) : 'Say hello'}</span>\${m.unread ? '<span class="unread-dot">' + m.unread + '</span>' : ''}</div>
      </div>
    </div>
  \`).join('');
}

async function openChat(matchKey) {
  state.activeChat = matchKey;
  hideTypingIndicator();
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
        \${match.compatibilityReasons && match.compatibilityReasons.length ? '<ul>' + match.compatibilityReasons.map(r => '<li>' + escapeHtml(r) + '</li>').join('') + '</ul>' : ''}
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
    chatMessageCache = {};
    data.messages.forEach(m => { chatMessageCache[m.id] = m; });
    const lastMineIdx = data.messages.map(m => m.fromUserId === state.user.id).lastIndexOf(true);
    el.innerHTML = data.messages.map((m, i) => {
      const mine = m.fromUserId === state.user.id;
      let html = '<div class="bubble ' + (mine ? 'mine' : 'theirs') + '" data-mid="' + escapeHtml(m.id) + '" data-mine="' + (mine ? '1' : '0') + '">' + escapeHtml(m.text) + '</div>';
      if (mine && i === lastMineIdx) html += '<div class="receipt">' + (m.read ? 'Seen' : 'Sent') + '</div>';
      return html;
    }).join('');
  }
  if (wasNearBottom) el.scrollTop = el.scrollHeight;
  await loadMatches();
}

// ---------- Typing indicator ----------
let typingHideTimer = null;
let lastTypingSentAt = 0;
function showTypingIndicator() {
  const t = document.getElementById('chat-typing');
  if (!t) return;
  t.style.display = 'block';
  clearTimeout(typingHideTimer);
  typingHideTimer = setTimeout(hideTypingIndicator, 4000);
}
function hideTypingIndicator() {
  clearTimeout(typingHideTimer);
  const t = document.getElementById('chat-typing');
  if (t) t.style.display = 'none';
}
document.getElementById('chat-input').addEventListener('input', () => {
  if (!state.activeChat) return;
  const now = Date.now();
  if (now - lastTypingSentAt < 2500) return;
  if (!document.getElementById('chat-input').value.trim()) return;
  lastTypingSentAt = now;
  api('/api/messages/' + state.activeChat + '/typing', { method: 'POST' }).catch(() => {});
});

// ---------- Chat menu: unmatch / report, and per-message delete / report ----------
let chatMessageCache = {};
const MESSAGE_REPORT_REASONS = ['Harassment or abuse', 'Inappropriate content', 'Threats or hate', 'Spam or scam', 'Something else'];

function getActiveMatch() {
  return state.matches.find(m => m.matchKey === state.activeChat) || null;
}

function openChatMenu() {
  const match = getActiveMatch();
  if (!match) return;
  const name = escapeHtml(match.user.name);
  document.getElementById('action-sheet-body').innerHTML =
    '<button type="button" class="action-sheet-row danger" onclick="confirmUnmatch()">Unmatch ' + name + '</button>' +
    '<button type="button" class="action-sheet-row danger" onclick="openChatReportSheet()">Report ' + name + '</button>' +
    '<button type="button" class="action-sheet-row cancel" onclick="closeActionSheet()">Cancel</button>';
  document.getElementById('action-sheet-overlay').classList.add('open');
}

async function confirmUnmatch() {
  const match = getActiveMatch();
  closeActionSheet();
  if (!match) return;
  if (!confirm('Unmatch ' + match.user.name + '? The chat will be removed for both of you and you will not see each other again.')) return;
  try {
    await api('/api/unmatch', { method: 'POST', body: JSON.stringify({ matchKey: match.matchKey }) });
    switchView('matches');
    await loadMatches();
    loadDiscover();
  } catch (err) {
    alert(err.message);
  }
}

function openChatReportSheet() {
  const match = getActiveMatch();
  if (!match) return;
  document.getElementById('action-sheet-body').innerHTML =
    '<div class="action-sheet-row" style="cursor:default;">Report ' + escapeHtml(match.user.name) + ' — why?</div>' +
    '<div class="report-reason-list">' +
    REPORT_REASONS.map(r => '<button type="button" onclick="submitChatReport(' + escapeHtml(JSON.stringify(r)) + ')">' + escapeHtml(r) + '</button>').join('') +
    '</div><button type="button" class="action-sheet-row cancel" onclick="closeActionSheet()">Cancel</button>';
}

async function submitChatReport(reason) {
  const match = getActiveMatch();
  closeActionSheet();
  if (!match) return;
  try {
    await api('/api/report', { method: 'POST', body: JSON.stringify({ reportedUserId: match.user.id, reason }) });
    alert('Thanks — your report has been submitted. Our team will review it.');
  } catch (err) {
    alert(err.message);
  }
}

function openMessageMenu(id, mine) {
  const msg = chatMessageCache[id];
  if (!msg) return;
  const body = document.getElementById('action-sheet-body');
  const idArg = escapeHtml(JSON.stringify(String(id)));
  if (mine) {
    body.innerHTML =
      '<button type="button" class="action-sheet-row danger" onclick="confirmDeleteMessage(' + idArg + ')">Delete message</button>' +
      '<button type="button" class="action-sheet-row cancel" onclick="closeActionSheet()">Cancel</button>';
  } else {
    body.innerHTML =
      '<button type="button" class="action-sheet-row danger" onclick="openMessageReportSheet(' + idArg + ')">Report message</button>' +
      '<button type="button" class="action-sheet-row cancel" onclick="closeActionSheet()">Cancel</button>';
  }
  document.getElementById('action-sheet-overlay').classList.add('open');
}

async function confirmDeleteMessage(id) {
  closeActionSheet();
  if (!state.activeChat) return;
  if (!confirm('Delete this message for both of you?')) return;
  try {
    await api('/api/messages/' + state.activeChat + '/' + encodeURIComponent(id), { method: 'DELETE' });
    await loadChatMessages(state.activeChat);
  } catch (err) {
    alert(err.message);
  }
}

function openMessageReportSheet(id) {
  const idArg = escapeHtml(JSON.stringify(String(id)));
  document.getElementById('action-sheet-body').innerHTML =
    '<div class="action-sheet-row" style="cursor:default;">Report this message — why?</div>' +
    '<div class="report-reason-list">' +
    MESSAGE_REPORT_REASONS.map(r => '<button type="button" onclick="submitMessageReport(' + idArg + ',' + escapeHtml(JSON.stringify(r)) + ')">' + escapeHtml(r) + '</button>').join('') +
    '</div><button type="button" class="action-sheet-row cancel" onclick="closeActionSheet()">Cancel</button>';
}

async function submitMessageReport(id, reason) {
  closeActionSheet();
  if (!state.activeChat) return;
  try {
    await api('/api/messages/' + state.activeChat + '/' + encodeURIComponent(id) + '/report', { method: 'POST', body: JSON.stringify({ reason }) });
    alert('Thanks — your report has been submitted. Our team will review it.');
  } catch (err) {
    alert(err.message);
  }
}

document.getElementById('chat-messages').addEventListener('click', (e) => {
  const bubble = e.target.closest && e.target.closest('.bubble[data-mid]');
  if (!bubble) return;
  openMessageMenu(bubble.getAttribute('data-mid'), bubble.getAttribute('data-mine') === '1');
});

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

// ---------- Explore — grid of all currently eligible profiles ----------
// Uses the same already-loaded, already-filtered pool as the Discover
// "may like" carousel (state.candidates, populated by loadDiscover() and
// re-applied whenever the filter panel changes) — just laid out as a
// browsable grid instead of one swipeable card at a time.
function buildExploreCardHTML(c) {
  const photo = c.photoUrl ? \`background-image:url('\${escapeHtml(c.photoUrl)}')\` : \`background:\${colorFor(c.name)}\`;
  return \`
    <div class="explore-card" onclick="openCandidateDetail('\${escapeHtml(c.id)}')">
      <div class="explore-card-photo" style="\${photo}">
        <div class="explore-card-info">
          <div class="explore-card-name">\${escapeHtml(c.name)}\${c.age ? ', ' + c.age : ''}</div>
          \${c.location ? \`<div class="explore-card-loc">\${escapeHtml(c.location)}</div>\` : ''}
        </div>
      </div>
    </div>\`;
}

function renderExploreGrid() {
  const grid = document.getElementById('explore-grid');
  if (!grid) return;
  const profiles = state.candidates || [];
  grid.innerHTML = profiles.length
    ? profiles.map(buildExploreCardHTML).join('')
    : '<div class="empty-state">No profiles available right now. Check back later!</div>';
}

// ---------- Likes You ----------

async function loadAdmirers() {
  const epoch = sessionEpoch;
  const data = await api('/api/likes-you');
  if (epoch !== sessionEpoch) return; // account changed while this request was in flight
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
      <div class="aname">\${escapeHtml(a.name)}\${a.age ? ', ' + a.age : ''}</div>
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
  const pctEl = document.getElementById('ph-strength-pct');
  if (!pctEl || !state.user) return;
  const strength = state.user.profileStrength;
  const pct = (strength && typeof strength.percentage === 'number')
    ? strength.percentage
    : computeCompletionClient(state.user);

  pctEl.textContent = pct + '%';
  document.getElementById('ph-strength-fill').style.width = pct + '%';

  const hintEl = document.getElementById('ph-strength-hint');
  if (!hintEl) return;
  if (pct >= 100) {
    hintEl.textContent = 'Your profile is fully complete!';
    return;
  }
  // Point people at whichever weighted section has the biggest gap between
  // its max weight and the points it's currently earning.
  const sections = (strength && strength.sections) || null;
  if (!sections) { hintEl.textContent = ''; return; }
  let weakest = null;
  for (const key in sections) {
    const s = sections[key];
    const gap = s.weight - s.points;
    if (gap > 0.01 && (!weakest || gap > weakest.gap)) weakest = { label: s.label, gap };
  }
  hintEl.textContent = weakest ? ('Add more to "' + weakest.label + '" to boost your score') : '';
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
  const screen = document.getElementById('details-screen');
  const isProfileEdit = origin === 'profile';
  screen.classList.toggle('profile-overlay-mode', isProfileEdit);
  const saveBtn = document.getElementById('details-save-btn');
  const cancelBtn = screen.querySelector('.q-skip');
  if (saveBtn) saveBtn.textContent = isProfileEdit ? 'Save' : 'Save & continue';
  if (cancelBtn) cancelBtn.textContent = isProfileEdit ? 'Cancel' : 'Skip for now';
  screen.classList.add('visible');
  if (isProfileEdit) document.body.style.overflow = 'hidden';
}

function closeDetailsScreen() {
  const screen = document.getElementById('details-screen');
  screen.classList.remove('visible', 'profile-overlay-mode');
  document.body.style.overflow = '';
}

async function proceedAfterDetails() {
  const origin = state.detailsOrigin;
  document.getElementById('details-screen').classList.remove('visible', 'profile-overlay-mode');
  document.body.style.overflow = '';
  if (origin === 'signup') {
    await enterDashboard();
  } else {
    document.getElementById('dashboard').classList.add('visible');
    updateProfileCompletionDisplay();
    switchView('profile');
  }
}

async function saveDetailsScreen() {
  const btn = document.getElementById('details-save-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify(state.details) });
    state.user = data.user;
    refreshProfileViewMode();
    await proceedAfterDetails();
  } catch (e) {
    alert(e.message || 'Could not save your profile details. Please try again.');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save & continue'; }
  }
}

async function skipDetailsScreen() {
  await proceedAfterDetails();
}

// ---------- "I'm looking for" editor (dating intentions only) ----------
// Deliberately separate from the details screen/state above — this only
// ever reads/writes datingIntentions, leaving every other profile field
// (and showDetailsScreen) untouched.
let lookingForDraft = { datingIntentions: [] };

function populateLookingForFormFromUser(user) {
  lookingForDraft = { datingIntentions: (user.datingIntentions || []).slice() };
  syncChipSelectedStatesIn(document.getElementById('looking-for-form-body'), lookingForDraft);
}

function showLookingForScreen() {
  populateLookingForFormFromUser(state.user || {});
  const screen = document.getElementById('looking-for-screen');
  screen.classList.add('profile-overlay-mode', 'visible');
  const saveBtn = document.getElementById('looking-for-save-btn');
  if (saveBtn) saveBtn.textContent = 'Save';
  document.body.style.overflow = 'hidden';
}

function closeLookingForScreen() {
  document.getElementById('looking-for-screen').classList.remove('visible', 'profile-overlay-mode');
  document.body.style.overflow = '';
}

async function saveLookingForScreen() {
  const btn = document.getElementById('looking-for-save-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify({ datingIntentions: lookingForDraft.datingIntentions }) });
    state.user = data.user;
    refreshProfileViewMode();
    closeLookingForScreen();
  } catch (e) {
    alert(e.message || 'Could not save your dating intentions. Please try again.');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
  }
}

// ---------- Profile ----------

function fillProfileForm() {
  document.getElementById('p-name').value = state.user.name || '';
  document.getElementById('p-age').value = state.user.age || '';
  document.getElementById('p-gender').value = state.user.gender || 'other';
  document.getElementById('p-country').value = state.user.country || '';
  document.getElementById('p-location').value = state.user.location || '';
  document.getElementById('p-bio').value = state.user.bio || '';
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
  el.innerHTML = tags.map(t => \`<span class="interest-chip">\${escapeHtml(t)}</span>\`).join('');
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
// Display text for each VALID_GENDERS value — kept separate from the
// generic titleCaseWords() helper so "non-binary" and "prefer_not_to_say"
// render correctly instead of "Non Binary" / "Prefer Not To Say".
const GENDER_LABELS = {
  man: 'Man',
  woman: 'Woman',
  'non-binary': 'Non-binary',
  genderqueer: 'Genderqueer',
  genderfluid: 'Genderfluid',
  agender: 'Agender',
  other: 'Other',
  prefer_not_to_say: 'Prefer not to say',
};
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
  if (u.languages && u.languages.length) items.push(['languages', escapeHtml(u.languages.join(', '))]);
  if (u.exercise) items.push(['exercise', titleCaseWords(u.exercise)]);
  if (u.drinking) items.push(['drinking', titleCaseWords(u.drinking)]);
  if (u.smoking) items.push(['smoking', titleCaseWords(u.smoking)]);
  if (u.religion) items.push(['religion', titleCaseWords(u.religion)]);
  if (u.political) items.push(['political', titleCaseWords(u.political)]);
  if (u.children) items.push(['children', titleCaseWords(u.children)]);
  if (u.wantsChildren) items.push(['wantsChildren', titleCaseWords(u.wantsChildren)]);
  if (u.gender) items.push(['gender', GENDER_LABELS[u.gender] || titleCaseWords(u.gender)]);
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
          <img src="\${escapeHtml(url)}" alt="My Vibes photo \${i + 1}" loading="lazy" onload="this.classList.add('loaded')" />
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
    <div class="vibes-slot vibes-slot-view" onclick="openPhotoLightbox(\${escapeHtml(JSON.stringify(gallery))}, \${i})">
      <img src="\${escapeHtml(url)}" alt="My Vibes photo \${i + 1}" loading="lazy" onload="this.classList.add('loaded')" />
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
      <div class="prompt-view-question">\${escapeHtml(p.question)}</div>
      <div class="prompt-view-answer">\${escapeHtml(p.answer)}</div>
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
      <textarea id="prompt-a-\${i}" maxlength="300" placeholder="Your answer">\${escapeHtml(existing.answer)}</textarea>
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
  event.target.value = ''; // allow re-selecting the same file later
  if (!file) return;
  if (file.size > 8 * 1024 * 1024) {
    document.getElementById('photo-upload-status').textContent = 'Image too large (max 8MB).';
    return;
  }
  const reader = new FileReader();
  reader.onload = () => openPhotoCrop(reader.result);
  reader.readAsDataURL(file);
}

// ---------- Profile photo crop tool ----------
// Every profile photo passes through this 3:4 crop step before it's
// uploaded. It's a small self-built pan/zoom cropper (drag to reposition,
// wheel or pinch to zoom) rather than a third-party library, so it doesn't
// need any change to the CSP or an external script dependency.
const photoCrop = {
  img: null,
  stageW: 0, stageH: 0,
  naturalW: 0, naturalH: 0,
  baseScale: 1, scale: 1, maxScale: 1,
  offsetX: 0, offsetY: 0,
  dragging: false, lastX: 0, lastY: 0,
  pinchDist: 0, pinchScale: 1,
};

function openPhotoCrop(dataUrl) {
  const img = new Image();
  img.onload = () => {
    const stage = document.getElementById('photo-crop-stage');
    // Make the modal visible FIRST — the stage is display:none until this
    // class is added, and measuring a hidden element's size always
    // returns 0x0, which is what was breaking the crop math.
    document.getElementById('photo-crop-overlay').classList.add('visible');
    const rect = stage.getBoundingClientRect();
    photoCrop.img = document.getElementById('photo-crop-img');
    photoCrop.stageW = rect.width;
    photoCrop.stageH = rect.height;
    photoCrop.naturalW = img.naturalWidth;
    photoCrop.naturalH = img.naturalHeight;
    photoCrop.baseScale = Math.max(rect.width / img.naturalWidth, rect.height / img.naturalHeight);
    photoCrop.maxScale = photoCrop.baseScale * 3;
    photoCrop.scale = photoCrop.baseScale;
    photoCrop.offsetX = (rect.width - img.naturalWidth * photoCrop.scale) / 2;
    photoCrop.offsetY = (rect.height - img.naturalHeight * photoCrop.scale) / 2;
    photoCrop.img.src = dataUrl;
    applyPhotoCropTransform();
    document.getElementById('photo-crop-confirm-btn').disabled = false;
  };
  img.src = dataUrl;
}

function cancelPhotoCrop() {
  document.getElementById('photo-crop-overlay').classList.remove('visible');
  photoCrop.img = null;
}

function clampPhotoCropOffsets() {
  const maxX = 0, minX = photoCrop.stageW - photoCrop.naturalW * photoCrop.scale;
  const maxY = 0, minY = photoCrop.stageH - photoCrop.naturalH * photoCrop.scale;
  photoCrop.offsetX = Math.min(maxX, Math.max(minX, photoCrop.offsetX));
  photoCrop.offsetY = Math.min(maxY, Math.max(minY, photoCrop.offsetY));
}

function applyPhotoCropTransform() {
  if (!photoCrop.img) return;
  clampPhotoCropOffsets();
  photoCrop.img.style.width = (photoCrop.naturalW * photoCrop.scale) + 'px';
  photoCrop.img.style.height = (photoCrop.naturalH * photoCrop.scale) + 'px';
  photoCrop.img.style.transform = 'translate(' + photoCrop.offsetX + 'px, ' + photoCrop.offsetY + 'px)';
}

function zoomPhotoCropAt(stageX, stageY, newScale) {
  newScale = Math.min(photoCrop.maxScale, Math.max(photoCrop.baseScale, newScale));
  // Keep whatever image point is under (stageX, stageY) fixed on screen
  // while the scale changes, so zooming feels anchored, not jumpy.
  const imgX = (stageX - photoCrop.offsetX) / photoCrop.scale;
  const imgY = (stageY - photoCrop.offsetY) / photoCrop.scale;
  photoCrop.scale = newScale;
  photoCrop.offsetX = stageX - imgX * newScale;
  photoCrop.offsetY = stageY - imgY * newScale;
  applyPhotoCropTransform();
}

(function initPhotoCropStageEvents() {
  // The stage element is static markup rendered once, so it's safe to wire
  // these listeners up immediately at script-load time.
  document.addEventListener('DOMContentLoaded', bind);
  if (document.readyState !== 'loading') bind();
  function bind() {
    const stage = document.getElementById('photo-crop-stage');
    if (!stage || stage.dataset.cropBound) return;
    stage.dataset.cropBound = '1';

    stage.addEventListener('pointerdown', (e) => {
      if (!photoCrop.img) return;
      photoCrop.dragging = true;
      photoCrop.lastX = e.clientX;
      photoCrop.lastY = e.clientY;
      stage.classList.add('dragging');
      stage.setPointerCapture(e.pointerId);
    });
    stage.addEventListener('pointermove', (e) => {
      if (!photoCrop.dragging || !photoCrop.img) return;
      photoCrop.offsetX += e.clientX - photoCrop.lastX;
      photoCrop.offsetY += e.clientY - photoCrop.lastY;
      photoCrop.lastX = e.clientX;
      photoCrop.lastY = e.clientY;
      applyPhotoCropTransform();
    });
    const endDrag = () => { photoCrop.dragging = false; stage.classList.remove('dragging'); };
    stage.addEventListener('pointerup', endDrag);
    stage.addEventListener('pointercancel', endDrag);

    stage.addEventListener('wheel', (e) => {
      if (!photoCrop.img) return;
      e.preventDefault();
      const rect = stage.getBoundingClientRect();
      const stageX = e.clientX - rect.left, stageY = e.clientY - rect.top;
      zoomPhotoCropAt(stageX, stageY, photoCrop.scale * (1 - e.deltaY * 0.0015));
    }, { passive: false });

    // Two-finger pinch to zoom on touch devices (pointer events cover the
    // drag case above for a single finger already).
    const activeTouches = new Map();
    stage.addEventListener('touchstart', (e) => {
      for (const t of e.changedTouches) activeTouches.set(t.identifier, t);
    }, { passive: true });
    stage.addEventListener('touchmove', (e) => {
      if (!photoCrop.img) return;
      for (const t of e.changedTouches) activeTouches.set(t.identifier, t);
      if (activeTouches.size < 2) return;
      e.preventDefault();
      const pts = Array.from(activeTouches.values()).slice(0, 2);
      const dist = Math.hypot(pts[0].clientX - pts[1].clientX, pts[0].clientY - pts[1].clientY);
      const rect = stage.getBoundingClientRect();
      const midX = (pts[0].clientX + pts[1].clientX) / 2 - rect.left;
      const midY = (pts[0].clientY + pts[1].clientY) / 2 - rect.top;
      if (photoCrop.pinchDist) {
        zoomPhotoCropAt(midX, midY, photoCrop.scale * (dist / photoCrop.pinchDist));
      }
      photoCrop.pinchDist = dist;
    }, { passive: false });
    const endTouch = (e) => {
      for (const t of e.changedTouches) activeTouches.delete(t.identifier);
      if (activeTouches.size < 2) photoCrop.pinchDist = 0;
    };
    stage.addEventListener('touchend', endTouch);
    stage.addEventListener('touchcancel', endTouch);
  }
})();

async function confirmPhotoCrop() {
  if (!photoCrop.img) return;
  const btn = document.getElementById('photo-crop-confirm-btn');
  btn.disabled = true;
  // Output at a fixed 3:4 pixel size regardless of source resolution or
  // on-screen stage size, so every uploaded profile photo is consistent.
  const OUT_W = 900, OUT_H = 1200;
  const canvas = document.createElement('canvas');
  canvas.width = OUT_W;
  canvas.height = OUT_H;
  const ctx = canvas.getContext('2d');
  const sx = -photoCrop.offsetX / photoCrop.scale;
  const sy = -photoCrop.offsetY / photoCrop.scale;
  const sWidth = photoCrop.stageW / photoCrop.scale;
  const sHeight = photoCrop.stageH / photoCrop.scale;
  const sourceImg = new Image();
  sourceImg.onload = async () => {
    ctx.drawImage(sourceImg, sx, sy, sWidth, sHeight, 0, 0, OUT_W, OUT_H);
    const croppedDataUrl = canvas.toDataURL('image/jpeg', 0.9);
    document.getElementById('photo-crop-overlay').classList.remove('visible');
    photoCrop.img = null;
    const status = document.getElementById('photo-upload-status');
    status.textContent = 'Uploading...';
    try {
      const data = await api('/api/profile/photo', { method: 'POST', body: JSON.stringify({ photo: croppedDataUrl }) });
      state.user = data.user;
      fillProfileForm();
      updateMeAvatars();
      status.textContent = 'Photo updated!';
      setTimeout(() => status.textContent = '', 1500);
    } catch (err) {
      status.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  };
  sourceImg.src = document.getElementById('photo-crop-img').src;
}

async function saveProfile() {
  const body = {
    name: document.getElementById('p-name').value,
    age: document.getElementById('p-age').value,
    gender: document.getElementById('p-gender').value,
    country: document.getElementById('p-country').value,
    location: document.getElementById('p-location').value,
    bio: document.getElementById('p-bio').value,
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
  if (email) email.textContent = (state.user && state.user.email) ? state.user.email : 'Not set';
  const phone = document.getElementById('settings-phone');
  if (phone) phone.textContent = (state.user && state.user.phone) ? state.user.phone : 'Not set';
  const discoverableToggle = document.getElementById('settings-discoverable-toggle');
  const locationToggle = document.getElementById('settings-location-toggle');
  // The toggle now reads "Pause my account", so it's on when the profile is hidden.
  if (discoverableToggle) discoverableToggle.classList.toggle('active', state.user?.discoverable === false);
  if (locationToggle) locationToggle.classList.toggle('active', state.user?.showLocation !== false);
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

async function togglePrivacySetting(field) {
  if (!state.user) return;
  const next = field === 'discoverable' ? state.user.discoverable === false : state.user.showLocation === false;
  try {
    const body = field === 'discoverable' ? { discoverable: next } : { showLocation: next };
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify(body) });
    state.user = data.user;
    syncSettingsUI();
    if (field === 'discoverable') await loadDiscover();
  } catch (err) {
    alert(err.message);
  }
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

// ---------- Change password ----------
function openChangePassword() {
  document.getElementById('cp-current-password').value = '';
  document.getElementById('cp-new-password').value = '';
  document.getElementById('change-password-error').style.display = 'none';
  document.getElementById('change-password-overlay').classList.add('open');
  document.getElementById('change-password-panel').classList.add('open');
}

function closeChangePassword() {
  document.getElementById('change-password-overlay').classList.remove('open');
  document.getElementById('change-password-panel').classList.remove('open');
}

async function submitChangePassword() {
  const currentPassword = document.getElementById('cp-current-password').value;
  const newPassword = document.getElementById('cp-new-password').value;
  const errEl = document.getElementById('change-password-error');
  errEl.style.display = 'none';
  if (!currentPassword || !newPassword) {
    errEl.textContent = 'Enter your current and new password.';
    errEl.style.display = 'block';
    return;
  }
  const btn = document.getElementById('change-password-btn');
  btn.disabled = true;
  try {
    await api('/api/change-password', { method: 'POST', body: JSON.stringify({ currentPassword, newPassword }) });
    closeChangePassword();
    closeProfileSettings();
    alert('Password updated.');
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

// ---------- Delete account ----------
function openDeleteAccount() {
  document.getElementById('da-password').value = '';
  document.getElementById('delete-account-error').style.display = 'none';
  document.getElementById('delete-account-overlay').classList.add('open');
  document.getElementById('delete-account-panel').classList.add('open');
}

function closeDeleteAccount() {
  document.getElementById('delete-account-overlay').classList.remove('open');
  document.getElementById('delete-account-panel').classList.remove('open');
}

async function submitDeleteAccount() {
  const password = document.getElementById('da-password').value;
  const errEl = document.getElementById('delete-account-error');
  errEl.style.display = 'none';
  if (!password) {
    errEl.textContent = 'Enter your password to confirm.';
    errEl.style.display = 'block';
    return;
  }
  if (!confirm('This permanently deletes your account, matches, and messages. This cannot be undone. Continue?')) {
    return;
  }
  const btn = document.getElementById('delete-account-btn');
  btn.disabled = true;
  try {
    await api('/api/account', { method: 'DELETE', body: JSON.stringify({ password }) });
    closeDeleteAccount();
    closeProfileSettings();
    sessionEpoch++; // invalidate any in-flight requests from this account
    if (state.eventSource) state.eventSource.close();
    state = createFreshState();
    document.getElementById('dashboard').classList.remove('visible');
    document.getElementById('auth-screen').style.display = 'flex';
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

// ---------- Blocked Users (Settings → Privacy) ----------
async function openBlockedUsersPanel() {
  document.getElementById('blocked-users-overlay').classList.add('open');
  document.getElementById('blocked-users-panel').classList.add('open');
  const body = document.getElementById('blocked-users-body');
  body.innerHTML = '<div class="field-hint">Loading…</div>';
  try {
    const data = await api('/api/blocked');
    renderBlockedUsersList(data.blocked || []);
  } catch (err) {
    body.innerHTML = \`<div class="field-hint">Couldn't load your blocked users. \${escapeHtml(err.message)}</div>\`;
  }
}

function renderBlockedUsersList(blocked) {
  const body = document.getElementById('blocked-users-body');
  if (!blocked.length) {
    body.innerHTML = '<div class="field-hint">You haven\\'t blocked anyone.</div>';
    return;
  }
  body.innerHTML = blocked.map(u => \`
    <div class="blocked-user-row" data-id="\${u.id}">
      \${u.photoUrl
        ? \`<div class="avatar" style="background-image:url('\${escapeHtml(u.photoUrl)}')"></div>\`
        : \`<div class="avatar" style="background:\${colorFor(u.name)};display:flex;align-items:center;justify-content:center;color:white;font-weight:700;">\${escapeHtml(initials(u.name))}</div>\`}
      <span class="name">\${escapeHtml(u.name)}\${u.age ? ', ' + u.age : ''}</span>
      <button type="button" onclick="unblockUserFromPanel('\${u.id}')">Unblock</button>
    </div>\`).join('');
}

async function unblockUserFromPanel(id) {
  try {
    await api('/api/unblock', { method: 'POST', body: JSON.stringify({ targetUserId: id }) });
    const row = document.querySelector(\`.blocked-user-row[data-id="\${id}"]\`);
    if (row) row.remove();
    if (!document.querySelector('.blocked-user-row')) {
      document.getElementById('blocked-users-body').innerHTML = '<div class="field-hint">You haven\\'t blocked anyone.</div>';
    }
    // The unblocked person may now be eligible to show back up in Discover.
    loadDiscover();
  } catch (err) {
    alert(err.message);
  }
}

function closeBlockedUsersPanel() {
  document.getElementById('blocked-users-overlay').classList.remove('open');
  document.getElementById('blocked-users-panel').classList.remove('open');
}

// ---------- Sexual Orientation & Interested In (Settings → Dating Preferences) ----------
// Both are private matching inputs — see VALID_ORIENTATIONS/VALID_INTERESTED_IN
// server-side and toOwnUser/toPublicUser: neither field is ever shown on a
// profile, only used to decide Discover eligibility.
const ORIENTATION_LABELS = {
  straight: 'Straight', gay: 'Gay', lesbian: 'Lesbian', bisexual: 'Bisexual',
  pansexual: 'Pansexual', asexual: 'Asexual', queer: 'Queer', questioning: 'Questioning',
  other: 'Other', prefer_not_to_say: 'Prefer not to say',
};
const INTERESTED_IN_LABELS = { men: 'Men', women: 'Women', nonbinary: 'Non-binary people' };

let orientationSelection = null;

function openOrientationPanel() {
  orientationSelection = state.user.orientation || null;
  renderOrientationOptions();
  document.getElementById('orientation-error').style.display = 'none';
  document.getElementById('orientation-overlay').classList.add('open');
  document.getElementById('orientation-panel').classList.add('open');
}

function renderOrientationOptions() {
  document.getElementById('orientation-options').innerHTML = Object.entries(ORIENTATION_LABELS).map(([value, label]) => \`
    <button type="button" class="\${orientationSelection === value ? 'selected' : ''}" onclick="selectOrientation('\${value}')">\${escapeHtml(label)}</button>\`).join('');
}

function selectOrientation(value) {
  orientationSelection = value;
  renderOrientationOptions();
}

async function saveOrientation() {
  const btn = document.getElementById('orientation-save-btn');
  const errEl = document.getElementById('orientation-error');
  errEl.style.display = 'none';
  btn.disabled = true;
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify({ orientation: orientationSelection }) });
    state.user = data.user;
    closeOrientationPanel();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

function closeOrientationPanel() {
  document.getElementById('orientation-overlay').classList.remove('open');
  document.getElementById('orientation-panel').classList.remove('open');
}

let interestedInSelection = new Set();

function openInterestedInPanel() {
  interestedInSelection = new Set(state.user.interestedIn || []);
  renderInterestedInOptions();
  document.getElementById('interested-in-error').style.display = 'none';
  document.getElementById('interested-in-overlay').classList.add('open');
  document.getElementById('interested-in-panel').classList.add('open');
}

function renderInterestedInOptions() {
  const allSelected = Object.keys(INTERESTED_IN_LABELS).every(k => interestedInSelection.has(k));
  const rows = Object.entries(INTERESTED_IN_LABELS).map(([value, label]) => \`
    <button type="button" class="\${interestedInSelection.has(value) ? 'selected' : ''}" onclick="toggleInterestedIn('\${value}')">\${escapeHtml(label)}</button>\`).join('');
  document.getElementById('interested-in-options').innerHTML = rows +
    \`<button type="button" class="\${allSelected ? 'selected' : ''}" onclick="selectEveryoneInterestedIn()">Everyone</button>\`;
}

function toggleInterestedIn(value) {
  if (interestedInSelection.has(value)) interestedInSelection.delete(value);
  else interestedInSelection.add(value);
  renderInterestedInOptions();
}

function selectEveryoneInterestedIn() {
  Object.keys(INTERESTED_IN_LABELS).forEach(k => interestedInSelection.add(k));
  renderInterestedInOptions();
}

async function saveInterestedIn() {
  const btn = document.getElementById('interested-in-save-btn');
  const errEl = document.getElementById('interested-in-error');
  errEl.style.display = 'none';
  if (!interestedInSelection.size) {
    errEl.textContent = 'Pick at least one option.';
    errEl.style.display = 'block';
    return;
  }
  btn.disabled = true;
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify({ interestedIn: [...interestedInSelection] }) });
    state.user = data.user;
    closeInterestedInPanel();
    loadDiscover();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

function closeInterestedInPanel() {
  document.getElementById('interested-in-overlay').classList.remove('open');
  document.getElementById('interested-in-panel').classList.remove('open');
}

// ---------- Boot ----------

// If the shared browser-wide session cookie changes underneath a tab
// (e.g. a different account was logged into in another tab open on the
// same site — cookies are never scoped to a single tab), silently
// re-painting this tab with the new identity risks a visible flash of
// someone else's name/photo/bio over this tab's still-rendered UI. Doing
// a full reload instead guarantees the DOM always starts from the blank
// placeholder markup and re-runs boot() end-to-end, so nothing ever
// shows mixed content from two different accounts at once.
async function revalidateIdentity() {
  if (!state.user) return;
  const knownUserId = state.user.id;
  let data;
  try {
    data = await api('/api/me');
  } catch (_) {
    return; // network hiccup or logged out elsewhere — not this check's job
  }
  if (!data.user || data.user.id !== knownUserId) {
    location.reload();
  }
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') revalidateIdentity();
});
window.addEventListener('focus', () => revalidateIdentity());
window.addEventListener('pageshow', (e) => {
  // event.persisted === true means the browser restored this page from
  // its back/forward cache instead of actually reloading it — boot()
  // never re-ran, so the DOM (and state.user) could still reflect
  // whichever account was active last time this tab was on screen.
  if (e.persisted) revalidateIdentity();
});

function hideBootLoader() {
  const el = document.getElementById('boot-loader');
  if (!el) return;
  el.classList.add('boot-loader-hidden');
  // Fully detach after the fade-out so it can't intercept clicks/taps.
  setTimeout(() => el.remove(), 300);
}

async function boot() {
  const epoch = sessionEpoch;
  let data;
  try {
    data = await api('/api/me');
  } catch (_) {
    setAuthMode('login');
    hideBootLoader();
    return;
  }
  if (epoch !== sessionEpoch) { hideBootLoader(); return; } // account changed while this request was in flight
  state.user = data.user;
  try {
    await enterDashboard();
  } catch (e) {
    // Logged in fine, but something in the dashboard failed to load.
    console.error('Dashboard failed to load:', e);
    document.getElementById('auth-screen').style.display = 'none';
    document.getElementById('dashboard').classList.add('visible');
  } finally {
    hideBootLoader();
  }
}
// ---------- Install as app (PWA) ----------
let deferredInstallPrompt = null;
function isStandaloneApp() {
  return window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
}
function isIOSDevice() {
  return /iphone|ipad|ipod/i.test(navigator.userAgent);
}
function updateInstallRow() {
  const row = document.getElementById('install-app-row');
  if (!row) return;
  row.style.display = (!isStandaloneApp() && (deferredInstallPrompt || isIOSDevice())) ? '' : 'none';
}
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstallPrompt = e;
  updateInstallRow();
});
window.addEventListener('appinstalled', () => {
  deferredInstallPrompt = null;
  updateInstallRow();
});
async function installApp() {
  if (deferredInstallPrompt) {
    deferredInstallPrompt.prompt();
    try { await deferredInstallPrompt.userChoice; } catch (e) { /* ignore */ }
    deferredInstallPrompt = null;
    updateInstallRow();
  } else if (isIOSDevice()) {
    alert('To install Swing: tap the Share button in Safari, then choose Add to Home Screen.');
  }
}
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => { navigator.serviceWorker.register('/sw.js').catch(() => {}); });
}
updateInstallRow();

boot();
</script>
</body>
</html>`;


// ---------- Installable app (PWA) ----------
// Lets people on Chrome/Android (and desktop Chrome/Edge) install Swing from
// the browser, and add it to the home screen on iOS Safari. Needs HTTPS in
// production (Render provides it).
const MANIFEST = {
  id: '/',
  name: 'Swing',
  short_name: 'Swing',
  description: 'Meet someone worth staying for.',
  start_url: '/',
  scope: '/',
  display: 'standalone',
  orientation: 'portrait',
  background_color: '#1e1033',
  theme_color: '#7c3aed',
  categories: ['social', 'lifestyle'],
  icons: [
    { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
    { src: '/icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
  ],
};

const ICON_PNGS = new Map([
  ['/icon-192.png', Buffer.from('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', 'base64')],
  ['/icon-512.png', Buffer.from('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', 'base64')],
  ['/icon-maskable-512.png', Buffer.from('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', 'base64')],
]);

// Deliberately minimal: never touches /api/ (live data, auth, SSE) or /admin.
// Page loads are network-first, falling back to the last-seen app shell when
// offline. Nothing user-specific is ever cached.
const SERVICE_WORKER_JS = [
  "const CACHE = 'swing-shell-v1';",
  "self.addEventListener('install', (e) => { self.skipWaiting(); });",
  "self.addEventListener('activate', (e) => {",
  "  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));",
  "});",
  "self.addEventListener('fetch', (e) => {",
  "  const req = e.request;",
  "  if (req.method !== 'GET') return;",
  "  const url = new URL(req.url);",
  "  if (url.origin !== self.location.origin) return;",
  "  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/admin')) return;",
  "  if (req.mode === 'navigate') {",
  "    e.respondWith(fetch(req).then((res) => {",
  "      if (res.ok && url.pathname === '/') { const copy = res.clone(); caches.open(CACHE).then((c) => c.put('/', copy)); }",
  "      return res;",
  "    }).catch(() => caches.match('/').then((r) => r || new Response('You are offline. Reconnect to use Swing.', { status: 503, headers: { 'Content-Type': 'text/plain' } }))));",
  "    return;",
  "  }",
  "  if (url.pathname.startsWith('/icon-')) {",
  "    e.respondWith(caches.match(req).then((hit) => hit || fetch(req).then((res) => { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); return res; })));",
  "  }",
  "});",
].join('\n');

// ---------- Server ----------

setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) {
    if (bucket.resetAt <= now) rateBuckets.delete(key);
  }
}, 5 * 60 * 1000).unref();

const server = http.createServer(async (req, res) => {
  let url;
  try {
    // Fixed base: a malformed Host header must not be able to throw here.
    url = new URL(req.url, 'http://localhost');
  } catch (_) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    return res.end('Bad request');
  }
  const { pathname } = url;
  applySecurityHeaders(res);

  // Reject cross-site state-changing requests. SameSite=Strict is the second
  // layer, but defense in depth matters for a dating app holding private data.
  if (isMutatingMethod(req.method) && !validateOrigin(req)) {
    return sendJSON(res, 403, { error: 'Cross-site request blocked' });
  }

  const ip = getClientIp(req);
  const apiRequest = pathname.startsWith('/api/');
  if (apiRequest) {
    const authPaths = ['/api/login', '/api/register', '/api/forgot-password', '/api/reset-password'];
    const generalLimit = authPaths.includes(pathname) ? 10 : (pathname === '/api/discover' ? 30 : 120);
    const windowMs = 60 * 1000;
    const key = `${pathname}:${ip}`;
    if (!rateLimit(key, generalLimit, windowMs)) {
      return sendJSON(res, 429, { error: 'Too many requests. Please try again shortly.' }, { 'Retry-After': '60' });
    }
    // Extra, longer-window cap specifically on the two account-recovery
    // endpoints — they're the ones an attacker would use to spam codes or
    // brute-force a reset code, so they get a stricter per-IP ceiling on
    // top of the per-minute one above.
    if (pathname === '/api/forgot-password' || pathname === '/api/reset-password') {
      if (!rateLimit(`recovery:${ip}`, 8, 15 * 60 * 1000)) {
        return sendJSON(res, 429, { error: 'Too many requests. Please try again later.' });
      }
    }
  }

  try {
    if (pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(FRONTEND_HTML);
    }

    if (pathname === '/manifest.webmanifest' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/manifest+json', 'Cache-Control': 'public, max-age=3600' });
      return res.end(JSON.stringify(MANIFEST));
    }
    if (pathname === '/sw.js' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/' });
      return res.end(SERVICE_WORKER_JS);
    }
    if (ICON_PNGS.has(pathname) && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' });
      return res.end(ICON_PNGS.get(pathname));
    }

    if (pathname === '/robots.txt' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('User-agent: *\nAllow: /\n');
    }

    if (pathname === '/api/health' && req.method === 'GET') {
      return sendJSON(res, 200, { ok: true, service: 'swing' });
    }

    if (pathname === '/api/register' && req.method === 'POST') {
      return await handleRegister(req, res);
    }
    if (pathname === '/api/login' && req.method === 'POST') {
      return await handleLogin(req, res);
    }
    if (pathname === '/api/forgot-password' && req.method === 'POST') {
      return await handleForgotPassword(req, res);
    }
    if (pathname === '/api/reset-password' && req.method === 'POST') {
      return await handleResetPassword(req, res);
    }
    if (pathname === '/api/me' && req.method === 'GET') {
      return await handleMe(req, res);
    }
    if (pathname === '/api/logout' && req.method === 'POST') {
      return await handleLogout(req, res);
    }
    if (pathname === '/api/change-password' && req.method === 'POST') {
      return await handleChangePassword(req, res);
    }
    if (pathname === '/api/account' && req.method === 'DELETE') {
      return await handleDeleteAccount(req, res);
    }
    if (pathname === '/api/stream' && req.method === 'GET') {
      return await handleStream(req, res);
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
    if (pathname === '/api/block' && req.method === 'POST') {
      return await handleBlock(req, res);
    }
    if (pathname === '/api/unblock' && req.method === 'POST') {
      return await handleUnblock(req, res);
    }
    if (pathname === '/api/blocked' && req.method === 'GET') {
      return await handleGetBlockedUsers(req, res);
    }
    if (pathname === '/api/report' && req.method === 'POST') {
      return await handleReport(req, res);
    }
    if (pathname === '/api/matches' && req.method === 'GET') {
      return await handleMatches(req, res);
    }

    if (pathname === '/admin' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(ADMIN_HTML);
    }
    if (pathname === '/api/admin/reports' && req.method === 'GET') {
      return await handleAdminReports(req, res);
    }
    const adminReportMatch = pathname.match(/^\/api\/admin\/reports\/([^/]+)$/);
    if (adminReportMatch && req.method === 'DELETE') {
      return await handleAdminDismissReport(req, res, decodeURIComponent(adminReportMatch[1]));
    }
    if (pathname === '/api/unmatch' && req.method === 'POST') {
      return await handleUnmatch(req, res);
    }
    const msgReportMatch = pathname.match(/^\/api\/messages\/([^/]+)\/([^/]+)\/report$/);
    if (msgReportMatch && req.method === 'POST') {
      return await handleReportMessage(req, res, decodeURIComponent(msgReportMatch[1]), decodeURIComponent(msgReportMatch[2]));
    }
    const typingMatch = pathname.match(/^\/api\/messages\/([^/]+)\/typing$/);
    if (typingMatch && req.method === 'POST') {
      return await handleTyping(req, res, decodeURIComponent(typingMatch[1]));
    }
    const msgDeleteMatch = pathname.match(/^\/api\/messages\/([^/]+)\/([^/]+)$/);
    if (msgDeleteMatch && req.method === 'DELETE') {
      return await handleDeleteMessage(req, res, decodeURIComponent(msgDeleteMatch[1]), decodeURIComponent(msgDeleteMatch[2]));
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
    // Client mistakes from readBody (bad JSON / body too large) are 4xx, not 500.
    if (err && (err.statusCode === 400 || err.statusCode === 413)) {
      if (res.headersSent) return;
      if (err.statusCode === 413) {
        // We stopped reading the oversized body, so close the connection afterwards.
        res.once('finish', () => { try { req.destroy(); } catch (_) { /* ignore */ } });
        return sendJSON(res, 413, { error: err.message }, { Connection: 'close' });
      }
      return sendJSON(res, 400, { error: err.message });
    }
    console.error('Request error:', err && err.message ? err.message : 'unknown error');
    if (!res.headersSent) sendJSON(res, 500, { error: 'Internal server error' });
  }
});

// Log-and-continue instead of letting one unexpected rejection/exception
// crash the whole process (which would drop every other user's in-flight
// request as a connection reset — an intermittent "Load failed" for
// everyone, not just whoever triggered the bug). This is a safety net,
// not a substitute for fixing the underlying bug if one of these fires.
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason && reason.message ? reason.message : reason);
});
// An uncaught exception leaves the process in an unknown state, so log it and
// exit; the host (Render etc.) restarts the service automatically. Unhandled
// promise rejections above stay log-only: request handlers already catch their
// own errors, so those are rare and not worth dropping every open connection.
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err && err.message ? err.message : err);
  setTimeout(() => process.exit(1), 100);
});

// Graceful shutdown on deploy/restart: stop accepting connections, close
// live-update streams so clients reconnect to the new instance immediately.
process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
  for (const set of sseClients.values()) for (const r of set) { try { r.end(); } catch (_) { /* ignore */ } }
  setTimeout(() => process.exit(0), 10000).unref();
});

server.listen(PORT, () => {
  console.log(`Swing running at http://localhost:${PORT}`);
});
