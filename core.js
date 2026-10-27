// Client JS: Helpers, global state, filter defaults, interests helpers, api()
module.exports = `// Escapes user-supplied text before it's interpolated into innerHTML.
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

`;
