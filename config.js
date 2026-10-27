// Environment variables and shared constants (limits, valid option lists, cookie/session settings).

const PORT = process.env.PORT || 3000;

const cleanEnv = (v) => (v || '').trim().replace(/^["']|["']$/g, '');

// supabase-js appends /rest/v1 etc. itself, so the URL must be just the origin
// (https://<ref>.supabase.co). A pasted path or trailing slash causes PGRST125.
const SUPABASE_URL = (() => {
  const raw = cleanEnv(process.env.SUPABASE_URL);
  try { return new URL(raw).origin; } catch (e) { return raw; }
})();

const SUPABASE_SERVICE_ROLE_KEY = cleanEnv(process.env.SUPABASE_SERVICE_ROLE_KEY);

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

const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true' || IS_PRODUCTION || process.env.RENDER === 'true';

module.exports = {
  PORT,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  MAX_BODY_BYTES,
  MAX_TEXT_BYTES,
  MAX_MESSAGE_CHARS,
  MAX_BIO_CHARS,
  MAX_NAME_CHARS,
  MAX_LOCATION_CHARS,
  MAX_COUNTRY_CHARS,
  VALID_GENDERS,
  VALID_ORIENTATIONS,
  VALID_INTERESTED_IN,
  PHOTOS_BUCKET,
  SESSION_COOKIE,
  SESSION_TTL_MS,
  SESSION_RENEW_THRESHOLD_MS,
  IS_PRODUCTION,
  TRUST_PROXY,
  COOKIE_SECURE,
};
