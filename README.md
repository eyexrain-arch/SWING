# Swing

Dating app — Node.js + Supabase. Run: `npm install && npm start`

Required env vars: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` (server-side only, never in the browser).
Optional: `PORT`, `NODE_ENV`, `TRUST_PROXY`, `COOKIE_SECURE`.

## Structure (by role)

```
server.js                  Entry point: security checks, rate limits, error handling, listen()
src/
  config.js                Env vars, limits, valid option lists
  supabase.js              Supabase client
  routes.js                URL -> handler table
  middleware/
    security.js            Security headers, origin check, client IP, rate limiter
    auth.js                requireAuth guard
    static.js              Serves /public
  handlers/                One file per feature (HTTP in/out)
    auth.js  account.js  profile.js  prompts.js  questionnaire.js
    photos.js  discover.js  safety.js  matches.js  messages.js  stream.js
  services/                Logic + data shared by handlers
    sessions.js  users.js  serializers.js  profileStrength.js
    questionnaire.js  photoStorage.js  sse.js
  lib/                     Small helpers: password, identity, cookies, http, utils
public/                    Browser app
  index.html               Markup only
  css/                     base, discover, profile, responsive, filters, settings, theme
  js/                      Classic scripts (shared globals) — load order is set in index.html
```

Where to look: a bug in an endpoint → `src/handlers/<feature>.js`; response shape → `services/serializers.js`;
a screen's look → `public/css/`; a screen's behaviour → `public/js/`.

SQL migration notes from the original file are preserved as comments next to the code they belong to.
