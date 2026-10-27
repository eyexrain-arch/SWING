// Supabase client. SECURITY: uses the service role key — server only, never expose to the browser or commit it.
const { createClient } = require('@supabase/supabase-js');
const { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } = require('./config');

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables.');
  console.error('Set them before starting the server (see README).');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Used to scope the CSP's img-src to just our own Storage bucket instead of
// a blanket `https:` (see applySecurityHeaders below) — a wildcard there
// would let an XSS payload exfiltrate data via <img src="https://evil...">
// even with connect-src locked down, since image loads aren't covered by it.
const SUPABASE_ORIGIN = (() => {
  try { return new URL(SUPABASE_URL).origin; } catch (e) { return ''; }
})();

module.exports = {
  supabase,
  SUPABASE_ORIGIN,
};
