// Dashboard: enter dashboard, live updates (SSE), view switching
// NOTE: classic script (not an ES module) — shares globals with the other files in /js,
// so keep the load order from index.html.
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

