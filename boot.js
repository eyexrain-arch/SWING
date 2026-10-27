// Client JS: Boot sequence
module.exports = `// ---------- Boot ----------

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
boot();
`;
