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

const sessions = new Map(); // token -> userId

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
    createdAt: row.created_at,
  };
}

async function getUserById(id) {
  const { data, error } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data;
}

async function getUserByToken(token) {
  const userId = sessions.get(token);
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
  sessions.set(token, created.id);

  sendJSON(res, 201, { token, user: toPublicUser(created) });
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
  sessions.set(token, user.id);
  sendJSON(res, 200, { token, user: toPublicUser(user) });
}

async function handleMe(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  sendJSON(res, 200, { user: toPublicUser(user) });
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

  const { data: updated, error } = await supabase
    .from('users').update(updates).eq('id', user.id).select().single();
  if (error) throw error;

  sendJSON(res, 200, { user: toPublicUser(updated) });
}

// ---------- Photo upload ----------

const ALLOWED_IMAGE_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
};

async function handleUploadPhoto(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 413, { error: err.message });
  }

  const { photo } = body; // expected: "data:image/jpeg;base64,...."
  if (!photo || typeof photo !== 'string') {
    return sendJSON(res, 400, { error: 'photo (base64 data URL) is required' });
  }

  const match = photo.match(/^data:(image\/[a-zA-Z+]+);base64,(.+)$/);
  if (!match) {
    return sendJSON(res, 400, { error: 'photo must be a base64 image data URL' });
  }
  const mimeType = match[1];
  const base64Data = match[2];
  const ext = ALLOWED_IMAGE_TYPES[mimeType];
  if (!ext) {
    return sendJSON(res, 400, { error: 'Unsupported image type. Use JPEG, PNG, WEBP, or GIF.' });
  }

  const buffer = Buffer.from(base64Data, 'base64');
  if (buffer.length > MAX_BODY_BYTES) {
    return sendJSON(res, 413, { error: 'Image too large (max 8MB)' });
  }

  const filename = `${user.id}-${Date.now()}.${ext}`;
  const { error: uploadErr } = await supabase.storage
    .from(PHOTOS_BUCKET)
    .upload(filename, buffer, { contentType: mimeType, upsert: true });
  if (uploadErr) throw uploadErr;

  const { data: urlData } = supabase.storage.from(PHOTOS_BUCKET).getPublicUrl(filename);
  const photoUrl = urlData.publicUrl;

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ photo_url: photoUrl }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  sendJSON(res, 200, { user: toPublicUser(updated) });
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
    .map(toPublicUser);

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

    results.push({
      matchKey: m.key,
      createdAt: m.created_at,
      user: other ? toPublicUser(other) : null,
      lastMessage: lastMsg ? { text: lastMsg.text, fromUserId: lastMsg.from_user_id, createdAt: lastMsg.created_at } : null,
      unread,
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
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
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
  button { font-family: inherit; cursor: pointer; }
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
  .landing-headline { font-size: 42px; line-height: 1.15; margin: 0 0 16px; font-weight: 700; }
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
  .landing-footer .globe-line { display: flex; align-items: center; gap: 10px; font-size: 14.5px; font-weight: 600; }
  .landing-footer .globe-line b { color: var(--pink-500); }
  .landing-footer .sub-line { color: #d8bfc7; font-size: 12.5px; }
  .landing-footer .join-badge {
    display: flex; align-items: center; gap: 8px; background: rgba(255,255,255,0.08); padding: 8px 16px;
    border-radius: 20px; font-size: 12.5px; color: #f6dbe7;
  }

  @media (max-width: 900px) {
    .landing-body { flex-direction: column; padding: 40px 24px 20px; gap: 32px; }
    .landing-left { text-align: center; }
    .landing-brand { justify-content: center; }
    .landing-features { justify-content: center; }
    .landing-headline { font-size: 30px; }
    .landing-footer { flex-direction: column; text-align: center; }
  }

  #dashboard { display: none; min-height: 100vh; }
  #dashboard.visible { display: flex; }

  .sidebar { width: 260px; flex-shrink: 0; background: linear-gradient(180deg, var(--maroon-800), var(--maroon-950)); color: #f6dbe7; padding: 28px 20px; display: flex; flex-direction: column; }
  .sidebar .brand .logo-font { font-size: 34px; color: #fff; display: flex; align-items: center; gap: 6px; }
  .sidebar .tagline { font-size: 12.5px; color: #d8a9bd; line-height: 1.4; margin: 6px 0 28px; }
  .nav-item { display: flex; align-items: center; gap: 12px; padding: 11px 14px; border-radius: 12px; color: #e9c6d5; font-size: 14.5px; font-weight: 500; margin-bottom: 4px; border: none; background: transparent; width: 100%; text-align: left; }
  .nav-item .icon { width: 18px; text-align: center; }
  .nav-item .badge { margin-left: auto; background: rgba(255,255,255,0.15); color: #fff; font-size: 11px; padding: 1px 8px; border-radius: 20px; font-weight: 600; }
  .nav-item.active { background: linear-gradient(90deg, var(--pink-600), #b3245a); color: #fff; }
  .nav-item.active .badge { background: rgba(255,255,255,0.25); }
  .nav-item:hover:not(.active) { background: rgba(255,255,255,0.06); }

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
  .top-avatar { width: 38px; height: 38px; border-radius: 50%; background: var(--pink-500); color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; }

  .content-grid { display: flex; gap: 24px; align-items: flex-start; }
  .discover-col { flex: 1; min-width: 0; }
  .side-col { width: 300px; flex-shrink: 0; }
  .view-panel { display: none; }
  .view-panel.visible { display: block; }

  .filter-tabs { display: flex; gap: 8px; margin-bottom: 18px; }
  .filter-tabs button { display: flex; align-items: center; gap: 6px; border: 1px solid var(--border); background: white; padding: 9px 16px; border-radius: 20px; font-size: 13.5px; font-weight: 500; color: var(--muted); }
  .filter-tabs button.active { background: var(--maroon-800); color: white; border-color: var(--maroon-800); }

  .swipe-card { background: white; border-radius: 22px; overflow: hidden; box-shadow: 0 10px 40px rgba(75,20,45,0.1); }
  .swipe-photo { position: relative; height: 460px; background-size: cover; background-position: center; display: flex; flex-direction: column; justify-content: flex-end; }
  .swipe-photo::after { content: ''; position: absolute; inset: 0; background: linear-gradient(180deg, transparent 40%, rgba(20,5,12,0.75) 100%); }
  .photo-tag { position: absolute; top: 16px; left: 16px; background: rgba(0,0,0,0.45); color: white; font-size: 12px; padding: 5px 12px; border-radius: 20px; z-index: 2; }
  .swipe-details { position: relative; z-index: 2; padding: 20px 22px; color: white; }
  .swipe-details .name-row { display: flex; align-items: center; gap: 8px; font-size: 26px; font-weight: 700; }
  .swipe-details .meta { display: flex; gap: 14px; font-size: 12.5px; opacity: 0.9; margin: 4px 0 10px; }
  .swipe-details .bio { font-size: 13.5px; opacity: 0.95; margin-bottom: 12px; max-width: 480px; }
  .tag-pills { display: flex; gap: 8px; flex-wrap: wrap; }
  .tag-pills span { background: rgba(255,255,255,0.18); backdrop-filter: blur(4px); padding: 5px 12px; border-radius: 20px; font-size: 12px; }
  .empty-state { background: white; border-radius: 22px; padding: 60px 30px; text-align: center; color: var(--muted); }

  .swipe-actions { display: flex; justify-content: center; align-items: center; gap: 18px; padding: 22px 0 6px; }
  .swipe-actions button { border: none; border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }
  .act-pass { width: 62px; height: 62px; background: white; color: #d8536b; font-size: 24px; }
  .act-like { width: 62px; height: 62px; background: linear-gradient(135deg, var(--pink-500), var(--pink-600)); color: white; font-size: 24px; }
  .swipe-hint { text-align: center; font-size: 12.5px; color: var(--muted); }

  .side-card { background: white; border-radius: 18px; padding: 18px; margin-bottom: 18px; }
  .side-card .side-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
  .side-card .side-head h3 { font-size: 16px; margin: 0; }
  .side-card .side-head a { font-size: 12.5px; color: var(--pink-600); text-decoration: none; font-weight: 500; cursor: pointer; }

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
  .chat-panel { background: white; border-radius: 22px; display: flex; flex-direction: column; height: 620px; }
  .chat-header { display: flex; align-items: center; gap: 12px; padding: 16px 20px; border-bottom: 1px solid var(--border); }
  .chat-header .back-btn { background: var(--cream); border: none; width: 34px; height: 34px; border-radius: 50%; font-size: 15px; }
  .chat-messages { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 10px; }
  .bubble { max-width: 65%; padding: 10px 14px; border-radius: 16px; font-size: 13.5px; line-height: 1.4; }
  .bubble.mine { align-self: flex-end; background: var(--pink-600); color: white; border-bottom-right-radius: 4px; }
  .bubble.theirs { align-self: flex-start; background: var(--cream); color: var(--ink); border-bottom-left-radius: 4px; }
  .chat-input-row { display: flex; gap: 10px; padding: 16px 20px; border-top: 1px solid var(--border); }
  .chat-input-row input { flex: 1; padding: 11px 14px; border: 1px solid var(--border); border-radius: 10px; outline: none; font-size: 13.5px; }
  .chat-input-row button { background: var(--pink-600); color: white; border: none; padding: 0 18px; border-radius: 10px; font-weight: 600; font-size: 13px; }

  /* Likes You grid */
  .admirer-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 14px; }
  .admirer-card { background: white; border-radius: 16px; padding: 16px; text-align: center; }
  .admirer-card .match-avatar { margin: 0 auto 8px; }
  .admirer-card .aname { font-weight: 600; font-size: 13.5px; }
  .admirer-card button { margin-top: 10px; width: 100%; padding: 8px; border: none; border-radius: 8px; background: var(--pink-600); color: white; font-size: 12.5px; font-weight: 600; }

  /* Profile view */
  .profile-form { background: white; border-radius: 18px; padding: 24px; max-width: 480px; }
  .profile-form label { display: block; font-size: 12.5px; font-weight: 600; color: var(--muted); margin-bottom: 4px; }
  .profile-form input, .profile-form textarea { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 14px; font-size: 14px; }
  .profile-form textarea { resize: vertical; min-height: 70px; }
  .profile-form button { background: var(--pink-600); color: white; border: none; padding: 11px 20px; border-radius: 10px; font-weight: 600; font-size: 13.5px; }
  .save-note { font-size: 12.5px; color: #4caf7a; margin-left: 10px; }

  .app-footer { display: flex; justify-content: space-between; align-items: center; margin-top: 26px; padding-top: 18px; border-top: 1px solid var(--border); font-size: 12px; color: var(--muted); }
  .app-footer .links { display: flex; gap: 18px; }

  .mobile-nav { display: none; }

  .browser-banner {
    display: none;
    background: var(--maroon-950); color: #f6dbe7; padding: 12px 16px;
    font-size: 12.5px; text-align: center; line-height: 1.4;
  }
  .browser-banner.visible { display: block; }
  .browser-banner b { color: #fff; }
  .browser-banner .copy-link-btn {
    display: inline-block; margin-top: 6px; background: var(--pink-600); color: white;
    border: none; padding: 6px 14px; border-radius: 8px; font-size: 12px; font-weight: 600;
  }

  @media (max-width: 1000px) { .side-col { display: none; } }
  @media (max-width: 720px) {
    .sidebar { display: none; }
    .main { padding: 14px 14px 84px; }
    .mobile-nav {
      display: flex; position: fixed; bottom: 0; left: 0; right: 0; z-index: 50;
      background: white; border-top: 1px solid var(--border);
      box-shadow: 0 -4px 16px rgba(0,0,0,0.06);
    }
    .mobile-nav button {
      flex: 1; border: none; background: transparent; padding: 10px 4px 8px;
      display: flex; flex-direction: column; align-items: center; gap: 3px;
      font-size: 10.5px; color: var(--muted); position: relative;
    }
    .mobile-nav button .icon { font-size: 18px; }
    .mobile-nav button.active { color: var(--pink-600); }
    .mobile-nav button .mnav-badge {
      position: absolute; top: 4px; right: 22%; background: var(--pink-600); color: white;
      font-size: 9px; font-weight: 700; min-width: 14px; height: 14px; border-radius: 7px;
      display: flex; align-items: center; justify-content: center; padding: 0 3px;
    }
    .chat-panel { height: calc(100vh - 200px); }
  }
</style>
</head>
<body>

<div id="browser-banner" class="browser-banner">
  You're viewing this inside an app's built-in browser, which can make chat feel slower than it should.
  For the best experience, open Swing in <b>Safari or Chrome</b> instead.
  <br/>
  <button class="copy-link-btn" onclick="copySwingLink()">Copy link</button>
</div>

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
      <div class="landing-brand"><span class="logo-font">Swing</span> ♡</div>
      <div class="landing-kicker">MEET • MATCH • CONNECT</div>
      <h1 class="landing-headline">Meet someone worth <span>staying for.</span></h1>
      <p class="landing-sub">Swing helps you find real connections with people who get you.</p>
      <div class="landing-features">
        <div class="landing-feature"><div class="ico">♡</div><div class="label">Meaningful Matches</div></div>
        <div class="landing-feature"><div class="ico">🛡</div><div class="label">Safe &amp; Private</div></div>
        <div class="landing-feature"><div class="ico">✦</div><div class="label">Built for real connections</div></div>
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
      <div class="globe-line">🌐 Connect around <b>the world.</b></div>
      <div class="sub-line">No matter where you are, real connections are everywhere.</div>
    </div>
    <div class="join-badge">✨ New here? Be one of the first to join.</div>
  </div>

</div>

<div id="dashboard">
  <aside class="sidebar">
    <div class="brand"><div class="logo-font">swing <span>♡</span></div></div>
    <div class="tagline">Meet someone worth<br/>staying for.</div>

    <button class="nav-item active" data-view="discover" onclick="switchView('discover')"><span class="icon">⌂</span> Discover</button>
    <button class="nav-item" data-view="matches" onclick="switchView('matches')"><span class="icon">♡</span> Matches <span class="badge" id="nav-matches-count">0</span></button>
    <button class="nav-item" data-view="matches" onclick="switchView('matches')"><span class="icon">💬</span> Messages <span class="badge" id="nav-messages-count">0</span></button>
    <button class="nav-item" data-view="likes" onclick="switchView('likes')"><span class="icon">★</span> Likes You <span class="badge" id="nav-likes-count">0</span></button>
    <button class="nav-item" data-view="profile" onclick="switchView('profile')"><span class="icon">☺</span> Profile</button>

    <div class="sidebar-spacer"></div>

    <div class="premium-card">
      <div class="title">♛ Go Premium</div>
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
      <div class="search-box">🔍 &nbsp;<input id="country-search" placeholder="Search by country..." style="border:none;outline:none;background:transparent;font-size:13.5px;width:100%;color:var(--ink);" /></div>
      <div class="top-actions">
        <button class="icon-btn" onclick="logout()">⏻</button>
        <div class="top-avatar" id="top-avatar">?</div>
      </div>
    </div>

    <div class="content-grid">
      <div class="discover-col">

        <div class="view-panel visible" id="panel-discover">
          <div class="filter-tabs"><button class="active">♡ For You</button></div>
          <div id="swipe-card"></div>
          <div class="swipe-actions">
            <button class="act-pass" onclick="swipeAction('pass')">✕</button>
            <button class="act-like" onclick="swipeAction('like')">♥</button>
          </div>
          <div class="swipe-hint" id="swipe-hint"></div>
        </div>

        <div class="view-panel" id="panel-matches">
          <div id="matches-full-list"></div>
        </div>

        <div class="view-panel" id="panel-chat">
          <div class="chat-panel">
            <div class="chat-header">
              <button class="back-btn" onclick="switchView('matches')">←</button>
              <div class="msg-avatar" id="chat-avatar" style="width:36px;height:36px;font-size:12px;"></div>
              <div style="font-weight:600;" id="chat-name"></div>
            </div>
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

        <div class="view-panel" id="panel-profile">
          <div class="profile-form">
            <label>Photo</label>
            <div style="display:flex;align-items:center;gap:14px;margin-bottom:16px;">
              <div class="match-avatar" id="p-photo-preview" style="width:72px;height:72px;font-size:24px;border-width:0;"></div>
              <div>
                <input type="file" id="p-photo-input" accept="image/png,image/jpeg,image/webp,image/gif" style="display:none;" onchange="handlePhotoSelect(event)" />
                <button type="button" onclick="document.getElementById('p-photo-input').click()" style="background:var(--cream);color:var(--ink);border:1px solid var(--border);padding:8px 14px;border-radius:8px;font-size:12.5px;font-weight:600;">Change photo</button>
                <div id="photo-upload-status" style="font-size:11.5px;color:var(--muted);margin-top:6px;"></div>
              </div>
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
            <button onclick="saveProfile()">Save changes</button>
            <span class="save-note" id="save-note" style="display:none;">Saved!</span>
          </div>
        </div>

      </div>

      <div class="side-col">
        <div class="side-card">
          <div class="side-head"><h3>Matches</h3><a onclick="switchView('matches')">See all</a></div>
          <div class="match-avatars" id="matches-list"></div>
        </div>
        <div class="side-card">
          <div class="side-head"><h3>Messages</h3><a onclick="switchView('matches')">See all</a></div>
          <div id="messages-list"></div>
        </div>
        <div class="promo-card">
          <h4>Get more with Swing Premium</h4>
          <p>Unlimited likes, see who likes you, boost profile & more!</p>
          <button>♛ Upgrade Now</button>
        </div>
      </div>
    </div>

    <div class="app-footer">
      <div>© 2026 Swing</div>
      <div class="links"><a href="#">About</a><a href="#">Safety</a><a href="#">Help</a><a href="#">Privacy</a><a href="#">Terms</a></div>
    </div>
  </main>

  <nav class="mobile-nav">
    <button class="mobile-nav-item active" data-view="discover" onclick="switchView('discover')"><span class="icon">⌂</span>Discover</button>
    <button class="mobile-nav-item" data-view="matches" onclick="switchView('matches')"><span class="icon">💬</span>Messages<span class="mnav-badge" id="mnav-messages-count" style="display:none;"></span></button>
    <button class="mobile-nav-item" data-view="likes" onclick="switchView('likes')"><span class="icon">★</span>Likes<span class="mnav-badge" id="mnav-likes-count" style="display:none;"></span></button>
    <button class="mobile-nav-item" data-view="profile" onclick="switchView('profile')"><span class="icon">☺</span>Profile</button>
  </nav>
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

let state = {
  token: localStorage.getItem('swing_token') || null,
  user: null,
  candidates: [],
  matches: [],
  admirers: [],
  activeChat: null,
  eventSource: null,
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
    } else {
      data = await api('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
    }
    localStorage.setItem('swing_token', data.token);
    state.token = data.token;
    state.user = data.user;
    await enterDashboard();
  } catch (err) {
    showError(err.message);
  }
});

function logout() {
  if (state.eventSource) state.eventSource.close();
  localStorage.removeItem('swing_token');
  state = { token: null, user: null, candidates: [], matches: [], admirers: [], activeChat: null, eventSource: null };
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

function switchView(view) {
  state.activeChat = null;
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('visible'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));
  document.querySelectorAll('.mobile-nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));
  const titles = { discover: 'Discover', matches: 'Messages', likes: 'Likes You', profile: 'My Profile' };
  document.getElementById('view-title').textContent = titles[view] || 'Discover';

  if (view === 'discover') { document.getElementById('panel-discover').classList.add('visible'); renderSwipeCard(); }
  else if (view === 'matches') { document.getElementById('panel-matches').classList.add('visible'); renderMatchesFull(); }
  else if (view === 'likes') { document.getElementById('panel-likes').classList.add('visible'); renderAdmirers(); }
  else if (view === 'profile') { document.getElementById('panel-profile').classList.add('visible'); fillProfileForm(); }
}

// ---------- Discover ----------

async function loadDiscover(country) {
  const q = country !== undefined ? country : (document.getElementById('country-search').value || '');
  const url = '/api/discover' + (q.trim() ? '?country=' + encodeURIComponent(q.trim()) : '');
  const data = await api(url);
  state.candidates = data.candidates;
}

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
        <div class="photo-tag">✨ \${c.tags && c.tags.length ? c.tags[0] : 'New here'}</div>
        <div class="swipe-details">
          <div class="name-row">\${c.name}\${c.age ? ', ' + c.age : ''}</div>
          <div class="meta">\${c.location ? '<span>📍 ' + c.location + '</span>' : ''}</div>
          <div class="bio">\${c.bio || 'No bio yet.'}</div>
          <div class="tag-pills">\${(c.tags||[]).map(t => '<span>' + t + '</span>').join('')}</div>
        </div>
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
    renderSwipeCard();
    if (data.matched) {
      await loadMatches();
      alert("It's a match with " + c.name + "! 🎉");
    }
  } catch (err) {
    alert(err.message);
  }
}

// ---------- Matches / Messages ----------

async function loadMatches() {
  const data = await api('/api/matches');
  state.matches = data.matches;
  document.getElementById('nav-matches-count').textContent = state.matches.length;
  const unreadTotal = state.matches.reduce((sum, m) => sum + m.unread, 0);
  document.getElementById('nav-messages-count').textContent = unreadTotal;
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
        <div class="match-avatar" style="\${avatarStyleAttr(m.user)}">\${avatarInitials(m.user)}<span class="heart-badge">♥</span></div>
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
        <div class="msg-preview"><span class="text">\${m.lastMessage ? m.lastMessage.text : 'Say hello 👋'}</span>\${m.unread ? '<span class="unread-dot">' + m.unread + '</span>' : ''}</div>
      </div>
    </div>
  \`).join('');
}

async function openChat(matchKey) {
  state.activeChat = matchKey;
  const match = state.matches.find(m => m.matchKey === matchKey);
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('visible'));
  document.getElementById('panel-chat').classList.add('visible');
  document.getElementById('view-title').textContent = match ? match.user.name : 'Chat';
  document.getElementById('chat-name').textContent = match ? match.user.name : '';
  const av = document.getElementById('chat-avatar');
  av.textContent = match ? avatarInitials(match.user) : '?';
  av.setAttribute('style', 'width:36px;height:36px;font-size:12px;' + (match ? avatarStyleAttr(match.user) : 'background:#ccc;'));
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
    el.innerHTML = '<div class="muted-note" style="text-align:center;margin-top:20px;">You matched! Say hello 👋</div>';
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
      <button onclick="likeBack('\${a.id}')">Like back ♥</button>
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
      alert("It's a match! 🎉");
    }
  } catch (err) {
    alert(err.message);
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
  document.getElementById('p-tags').value = (state.user.tags || []).join(', ');
  const preview = document.getElementById('p-photo-preview');
  preview.textContent = avatarInitials(state.user);
  preview.setAttribute('style', 'width:72px;height:72px;font-size:24px;border-width:0;' + avatarStyleAttr(state.user));
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
    const note = document.getElementById('save-note');
    note.style.display = 'inline';
    setTimeout(() => note.style.display = 'none', 1500);
  } catch (err) {
    alert(err.message);
  }
}

// ---------- In-app browser detection ----------

function detectInAppBrowser() {
  const ua = navigator.userAgent || '';
  const patterns = [
    /Instagram/i,
    /FBAN|FBAV|FB_IAB/i,   // Facebook / Messenger
    /TikTok|musical_ly/i,
    /Twitter/i,
    /LinkedInApp/i,
    /Snapchat/i,
    /MicroMessenger/i,     // WeChat
    /Line\//i,
  ];
  return patterns.some(p => p.test(ua));
}

function copySwingLink() {
  const url = window.location.href;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(() => {
      alert('Link copied! Paste it into Safari or Chrome.');
    }).catch(() => {
      prompt('Copy this link and paste it into Safari or Chrome:', url);
    });
  } else {
    prompt('Copy this link and paste it into Safari or Chrome:', url);
  }
}

if (detectInAppBrowser()) {
  document.getElementById('browser-banner').classList.add('visible');
}

// ---------- Boot ----------

async function boot() {
  if (state.token) {
    try {
      const data = await api('/api/me');
      state.user = data.user;
      await enterDashboard();
    } catch (e) {
      localStorage.removeItem('swing_token');
      state.token = null;
      setAuthMode('login');
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
    if (pathname === '/api/stream' && req.method === 'GET') {
      return await handleStream(req, res, url.searchParams);
    }
    if (pathname === '/api/profile' && req.method === 'PUT') {
      return await handleUpdateProfile(req, res);
    }
    if (pathname === '/api/profile/photo' && req.method === 'POST') {
      return await handleUploadPhoto(req, res);
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
