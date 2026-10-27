// Swing — Node.js dating app. Entry point (keep this file at the project root:
// package.json "main"/"start" and the Vercel deployment both point at it).
// All the real code lives in ./src — see README.md for the layout.
//
// Storage: Supabase (Postgres for data, Storage bucket "photos" for images).

const http = require('http');
const { handleRequest } = require('./src/app');
const { PORT } = require('./src/config');
const { rateBuckets } = require('./src/lib/rateLimit');
const { SUPABASE_ORIGIN, supabase } = require('./src/supabase');

setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) {
    if (bucket.resetAt <= now) rateBuckets.delete(key);
  }
}, 5 * 60 * 1000).unref();

const server = http.createServer(handleRequest);

// Log-and-continue instead of letting one unexpected rejection/exception
// crash the whole process (which would drop every other user's in-flight
// request as a connection reset — an intermittent "Load failed" for
// everyone, not just whoever triggered the bug). This is a safety net,
// not a substitute for fixing the underlying bug if one of these fires.
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection:', reason && reason.message ? reason.message : reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err && err.message ? err.message : err);
});

server.listen(PORT, () => {
  console.log(`Swing running at http://localhost:${PORT}`);
  checkSupabaseConnection();
});

// Startup self-check: a bad SUPABASE_SERVICE_ROLE_KEY otherwise only shows up
// later as a generic 500 on login. This prints the real reason right at boot.
async function checkSupabaseConnection() {
  try {
    const { error, status } = await supabase.from('users').select('id').limit(1);
    if (!error) {
      console.log('Supabase check: OK (service role key accepted).');
      return;
    }
    console.error(`Supabase check FAILED (HTTP ${status}): ${error.message || 'unknown error'}`);
    if (status === 401 || status === 403) {
      console.error('  -> The key was rejected. Make sure SUPABASE_SERVICE_ROLE_KEY is the service role/secret key');
      console.error(`     from the SAME project as SUPABASE_URL (${SUPABASE_ORIGIN}), with no extra spaces or quotes,`);
      console.error('     and that you restarted/redeployed after changing it.');
    }
  } catch (e) {
    console.error('Supabase check FAILED:', e && e.message ? e.message : e);
  }
}

