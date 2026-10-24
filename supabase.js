/**
 * Supabase client (service-role).
 * 
 * SECURITY NOTE: this server uses the Supabase *service role* key, not the
 * anon/publishable key. The key bypasses Row Level Security by design — this
 * server is the only thing that talks to Supabase and it enforces its own auth
 * checks on every request. NEVER expose it to the browser or commit it to
 * source control; it only belongs in an environment variable on the server.
 */

const { createClient } = require('@supabase/supabase-js');
const { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } = require('./config');

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

module.exports = { supabase };
