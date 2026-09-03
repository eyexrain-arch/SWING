// Swing — single-file Node.js dating app
// Storage: local JSON file (data.json). No external dependencies.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

// ---------- Storage ----------

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const initial = { users: [], likes: [], matches: [], messages: [] };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  data.users = data.users || [];
  data.likes = data.likes || [];
  data.matches = data.matches || [];
  data.messages = data.messages || [];
  return data;
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

let db = loadData();

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

function getUserByToken(token) {
  const userId = sessions.get(token);
  if (!userId) return null;
  return db.users.find(u => u.id === userId) || null;
}

function publicUser(u) {
  const { passwordHash, passwordSalt, ...rest } = u;
  return rest;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => (body += chunk));
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
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function getAuthToken(req) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length);
}

function pairKey(id1, id2) {
  return [id1, id2].sort().join('::');
}

function requireAuth(req, res) {
  const token = getAuthToken(req);
  const user = token ? getUserByToken(token) : null;
  if (!user) {
    sendJSON(res, 401, { error: 'Not authenticated' });
    return null;
  }
  return user;
}

// ---------- Auth ----------

async function handleRegister(req, res) {
  const body = await readBody(req);
  const { name, email, password, age, bio, location, tags } = body;

  if (!name || !email || !password) {
    return sendJSON(res, 400, { error: 'name, email, and password are required' });
  }
  if (password.length < 6) {
    return sendJSON(res, 400, { error: 'password must be at least 6 characters' });
  }
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return sendJSON(res, 409, { error: 'An account with that email already exists' });
  }

  const { salt, hash } = hashPassword(password);
  const user = {
    id: crypto.randomUUID(),
    name,
    age: age || null,
    bio: bio || '',
    location: location || '',
    tags: Array.isArray(tags) ? tags : (tags ? String(tags).split(',').map(t => t.trim()).filter(Boolean) : []),
    email,
    passwordSalt: salt,
    passwordHash: hash,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  saveData(db);

  const token = makeToken();
  sessions.set(token, user.id);

  sendJSON(res, 201, { token, user: publicUser(user) });
}

async function handleLogin(req, res) {
  const body = await readBody(req);
  const { email, password } = body;
  if (!email || !password) {
    return sendJSON(res, 400, { error: 'email and password are required' });
  }
  const user = db.users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
  if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    return sendJSON(res, 401, { error: 'Invalid email or password' });
  }
  const token = makeToken();
  sessions.set(token, user.id);
  sendJSON(res, 200, { token, user: publicUser(user) });
}

async function handleMe(req, res) {
  const user = requireAuth(req, res);
  if (!user) return;
  sendJSON(res, 200, { user: publicUser(user) });
}

async function handleUpdateProfile(req, res) {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req);
  const { name, age, bio, location, tags } = body;
  if (name !== undefined) user.name = name;
  if (age !== undefined) user.age = age;
  if (bio !== undefined) user.bio = bio;
  if (location !== undefined) user.location = location;
  if (tags !== undefined) user.tags = Array.isArray(tags) ? tags : String(tags).split(',').map(t => t.trim()).filter(Boolean);
  saveData(db);
  sendJSON(res, 200, { user: publicUser(user) });
}

// ---------- Discover / Likes / Matches ----------

async function handleDiscover(req, res) {
  const user = requireAuth(req, res);
  if (!user) return;

  const swipedIds = new Set(
    db.likes.filter(l => l.fromUserId === user.id).map(l => l.toUserId)
  );

  const candidates = db.users
    .filter(u => u.id !== user.id && !swipedIds.has(u.id))
    .map(publicUser);

  sendJSON(res, 200, { candidates });
}

async function handleLike(req, res) {
  const user = requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req);
  const { targetUserId, direction } = body; // direction: 'like' | 'pass'

  if (!targetUserId || !['like', 'pass'].includes(direction)) {
    return sendJSON(res, 400, { error: 'targetUserId and direction (like|pass) are required' });
  }
  const targetUser = db.users.find(u => u.id === targetUserId);
  if (!targetUser) {
    return sendJSON(res, 404, { error: 'Target user not found' });
  }

  db.likes = db.likes.filter(
    l => !(l.fromUserId === user.id && l.toUserId === targetUserId)
  );
  db.likes.push({
    fromUserId: user.id,
    toUserId: targetUserId,
    direction,
    createdAt: new Date().toISOString(),
  });

  let matched = false;
  let matchKey = null;
  if (direction === 'like') {
    const reciprocal = db.likes.find(
      l => l.fromUserId === targetUserId && l.toUserId === user.id && l.direction === 'like'
    );
    if (reciprocal) {
      const key = pairKey(user.id, targetUserId);
      if (!db.matches.find(m => m.key === key)) {
        db.matches.push({
          key,
          userIds: [user.id, targetUserId],
          createdAt: new Date().toISOString(),
        });
        matched = true;
      }
      matchKey = key;
    }
  }

  saveData(db);
  sendJSON(res, 200, { matched, matchKey });
}

async function handleLikesYou(req, res) {
  const user = requireAuth(req, res);
  if (!user) return;

  const myMatchedIds = new Set(
    db.matches.filter(m => m.userIds.includes(user.id)).flatMap(m => m.userIds)
  );

  const admirers = db.likes
    .filter(l => l.toUserId === user.id && l.direction === 'like' && !myMatchedIds.has(l.fromUserId))
    .map(l => db.users.find(u => u.id === l.fromUserId))
    .filter(Boolean)
    .map(publicUser);

  sendJSON(res, 200, { admirers });
}

async function handleMatches(req, res) {
  const user = requireAuth(req, res);
  if (!user) return;

  const myMatches = db.matches
    .filter(m => m.userIds.includes(user.id))
    .map(m => {
      const otherId = m.userIds.find(id => id !== user.id);
      const other = db.users.find(u => u.id === otherId);
      const convo = db.messages.filter(msg => msg.matchKey === m.key);
      const lastMsg = convo[convo.length - 1] || null;
      const unread = convo.filter(msg => msg.toUserId === user.id && !msg.read).length;
      return {
        matchKey: m.key,
        createdAt: m.createdAt,
        user: other ? publicUser(other) : null,
        lastMessage: lastMsg,
        unread,
      };
    })
    .sort((a, b) => {
      const aTime = a.lastMessage ? a.lastMessage.createdAt : a.createdAt;
      const bTime = b.lastMessage ? b.lastMessage.createdAt : b.createdAt;
      return new Date(bTime) - new Date(aTime);
    });

  sendJSON(res, 200, { matches: myMatches });
}

// ---------- Messages ----------

function getMatchForUsers(matchKey, userId) {
  const match = db.matches.find(m => m.key === matchKey);
  if (!match || !match.userIds.includes(userId)) return null;
  return match;
}

async function handleGetMessages(req, res, matchKey) {
  const user = requireAuth(req, res);
  if (!user) return;

  const match = getMatchForUsers(matchKey, user.id);
  if (!match) {
    return sendJSON(res, 404, { error: 'Match not found' });
  }

  const convo = db.messages.filter(m => m.matchKey === matchKey);
  // mark messages sent to me as read
  let changed = false;
  convo.forEach(m => {
    if (m.toUserId === user.id && !m.read) {
      m.read = true;
      changed = true;
    }
  });
  if (changed) saveData(db);

  sendJSON(res, 200, { messages: convo });
}

async function handlePostMessage(req, res, matchKey) {
  const user = requireAuth(req, res);
  if (!user) return;

  const match = getMatchForUsers(matchKey, user.id);
  if (!match) {
    return sendJSON(res, 404, { error: 'Match not found' });
  }

  const body = await readBody(req);
  const { text } = body;
  if (!text || !text.trim()) {
    return sendJSON(res, 400, { error: 'text is required' });
  }

  const toUserId = match.userIds.find(id => id !== user.id);
  const message = {
    id: crypto.randomUUID(),
    matchKey,
    fromUserId: user.id,
    toUserId,
    text: text.trim(),
    read: false,
    createdAt: new Date().toISOString(),
  };
  db.messages.push(message);
  saveData(db);

  sendJSON(res, 201, { message });
}

// ---------- Frontend ----------

const FRONTEND_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Swing — Meet someone worth staying for</title>
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
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: radial-gradient(circle at 20% 20%, var(--maroon-700), var(--maroon-950) 70%);
  }
  .auth-card { width: 100%; max-width: 400px; background: var(--card); border-radius: 20px; padding: 36px 32px; box-shadow: 0 20px 60px rgba(0,0,0,0.35); max-height: 90vh; overflow-y: auto; }
  .auth-card .logo-font { font-size: 40px; color: var(--pink-600); display: block; text-align: center; margin-bottom: 4px; }
  .auth-sub { text-align: center; color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .auth-tabs { display: flex; background: var(--pink-100); border-radius: 10px; padding: 4px; margin-bottom: 20px; }
  .auth-tabs button { flex: 1; border: none; background: transparent; padding: 9px; border-radius: 8px; font-size: 13px; font-weight: 600; color: var(--muted); }
  .auth-tabs button.active { background: var(--pink-600); color: white; }
  .auth-card input, .auth-card textarea { width: 100%; padding: 12px 14px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 12px; font-size: 14px; outline: none; }
  .auth-card textarea { resize: vertical; min-height: 60px; }
  .auth-card input:focus, .auth-card textarea:focus { border-color: var(--pink-500); }
  .auth-submit { width: 100%; padding: 13px; border: none; border-radius: 10px; background: var(--pink-600); color: white; font-weight: 600; font-size: 14px; margin-top: 4px; }
  .auth-submit:hover { background: var(--pink-500); }
  .auth-error { color: var(--pink-600); font-size: 13px; margin-bottom: 10px; text-align: center; }
  .field-hint { font-size: 11.5px; color: var(--muted); margin: -6px 0 12px 2px; }

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

  @media (max-width: 1000px) { .side-col { display: none; } }
  @media (max-width: 720px) { .sidebar { display: none; } .main { padding: 18px; } }
</style>
</head>
<body>

<div id="auth-screen">
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
      <input id="f-location" name="location" placeholder="Location (e.g. Manila, Philippines)" style="display:none;" />
      <textarea id="f-bio" name="bio" placeholder="Short bio" style="display:none;"></textarea>
      <input id="f-tags" name="tags" placeholder="Interests, comma separated (e.g. Coffee, Hiking)" style="display:none;" />
      <input id="f-email" name="email" type="email" placeholder="Email" required />
      <input id="f-password" name="password" type="password" placeholder="Password" required />
      <button type="submit" class="auth-submit" id="auth-submit-btn">Log in</button>
    </form>
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
      <div class="search-box">🔍 &nbsp;Search people</div>
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
            <label>Name</label><input id="p-name" />
            <label>Age</label><input id="p-age" type="number" min="18" />
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
</div>

<script>
const PALETTE = ['#ec4c7e','#8b5cf6','#e3a13f','#3fa5e3','#4caf7a','#d63868'];
function colorFor(name) { let h=0; for (const c of (name||'?')) h = (h*31 + c.charCodeAt(0)) % PALETTE.length; return PALETTE[h]; }
function initials(name) { return (name || '?').trim().charAt(0).toUpperCase(); }
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
};

async function api(pathName, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
  const res = await fetch(pathName, { ...options, headers });
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
  ['f-name','f-age','f-location','f-bio','f-tags'].forEach(id => {
    document.getElementById(id).style.display = mode === 'register' ? 'block' : 'none';
  });
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
      const location = document.getElementById('f-location').value;
      const bio = document.getElementById('f-bio').value;
      const tags = document.getElementById('f-tags').value;
      data = await api('/api/register', { method: 'POST', body: JSON.stringify({ name, email, password, age, location, bio, tags }) });
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
  localStorage.removeItem('swing_token');
  state = { token: null, user: null, candidates: [], matches: [], admirers: [], activeChat: null };
  document.getElementById('dashboard').classList.remove('visible');
  document.getElementById('auth-screen').style.display = 'flex';
}

// ---------- Dashboard ----------

async function enterDashboard() {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('dashboard').classList.add('visible');
  document.getElementById('me-name').textContent = state.user.name;
  document.getElementById('me-avatar').textContent = initials(state.user.name);
  document.getElementById('me-avatar').style.background = colorFor(state.user.name);
  document.getElementById('top-avatar').textContent = initials(state.user.name);
  document.getElementById('top-avatar').style.background = colorFor(state.user.name);

  await Promise.all([loadDiscover(), loadMatches(), loadAdmirers()]);
  switchView('discover');
}

function switchView(view) {
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('visible'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === view));
  const titles = { discover: 'Discover', matches: 'Messages', likes: 'Likes You', profile: 'My Profile' };
  document.getElementById('view-title').textContent = titles[view] || 'Discover';

  if (view === 'discover') { document.getElementById('panel-discover').classList.add('visible'); renderSwipeCard(); }
  else if (view === 'matches') { document.getElementById('panel-matches').classList.add('visible'); renderMatchesFull(); }
  else if (view === 'likes') { document.getElementById('panel-likes').classList.add('visible'); renderAdmirers(); }
  else if (view === 'profile') { document.getElementById('panel-profile').classList.add('visible'); fillProfileForm(); }
}

// ---------- Discover ----------

async function loadDiscover() {
  const data = await api('/api/discover');
  state.candidates = data.candidates;
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
  card.innerHTML = \`
    <div class="swipe-card">
      <div class="swipe-photo" style="background:linear-gradient(135deg, \${colorFor(c.name)}, #2a1620);">
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
        <div class="match-avatar" style="background:\${colorFor(m.user.name)};">\${initials(m.user.name)}<span class="heart-badge">♥</span></div>
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
        <div class="msg-avatar" style="background:\${colorFor(m.user.name)};">\${initials(m.user.name)}</div>
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
      <div class="msg-avatar" style="background:\${colorFor(m.user.name)};width:46px;height:46px;font-size:15px;">\${initials(m.user.name)}</div>
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
  av.textContent = match ? initials(match.user.name) : '?';
  av.style.background = match ? colorFor(match.user.name) : '#ccc';
  await loadChatMessages(matchKey);
}

async function loadChatMessages(matchKey) {
  const data = await api('/api/messages/' + matchKey);
  const el = document.getElementById('chat-messages');
  if (!data.messages.length) {
    el.innerHTML = '<div class="muted-note" style="text-align:center;margin-top:20px;">You matched! Say hello 👋</div>';
  } else {
    el.innerHTML = data.messages.map(m => \`
      <div class="bubble \${m.fromUserId === state.user.id ? 'mine' : 'theirs'}">\${m.text}</div>
    \`).join('');
  }
  el.scrollTop = el.scrollHeight;
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
}

function renderAdmirers() {
  const el = document.getElementById('admirer-grid');
  if (!state.admirers.length) {
    el.innerHTML = '<div class="empty-state">No one has liked you yet. Keep your profile fresh!</div>';
    return;
  }
  el.innerHTML = state.admirers.map(a => \`
    <div class="admirer-card">
      <div class="match-avatar" style="background:\${colorFor(a.name)};">\${initials(a.name)}</div>
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
  document.getElementById('p-location').value = state.user.location || '';
  document.getElementById('p-bio').value = state.user.bio || '';
  document.getElementById('p-tags').value = (state.user.tags || []).join(', ');
}

async function saveProfile() {
  const body = {
    name: document.getElementById('p-name').value,
    age: document.getElementById('p-age').value,
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

    if (pathname === '/api/register' && req.method === 'POST') {
      return await handleRegister(req, res);
    }
    if (pathname === '/api/login' && req.method === 'POST') {
      return await handleLogin(req, res);
    }
    if (pathname === '/api/me' && req.method === 'GET') {
      return await handleMe(req, res);
    }
    if (pathname === '/api/profile' && req.method === 'PUT') {
      return await handleUpdateProfile(req, res);
    }
    if (pathname === '/api/discover' && req.method === 'GET') {
      return await handleDiscover(req, res);
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
