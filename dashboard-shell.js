// HTML: Dashboard: sidebar and start of <main>
module.exports = `<div id="dashboard">
  <aside class="sidebar">
    <div class="brand"><div class="logo-font">swing <span class="brand-heart"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></span></div></div>
    <div class="tagline">Meet someone worth<br/>staying for.</div>

    <button class="nav-item active" data-view="discover" onclick="switchView('discover')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v9a1 1 0 0 0 1 1H9a1 1 0 0 0 1-1v-4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v4a1 1 0 0 0 1 1h2.5a1 1 0 0 0 1-1v-9"/></svg></span> Discover</button>
    <button class="nav-item" data-view="matches" onclick="switchView('matches')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 11.5a8.4 8.4 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.4 8.4 0 0 1-3.8-.9L3 21l1.9-5.7a8.4 8.4 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6A8.4 8.4 0 0 1 12.5 3h.5a8.48 8.48 0 0 1 8 8v.5Z"/></svg></span> Matches <span class="badge" id="nav-matches-count" style="display:none;">0</span></button>
    <button class="nav-item" data-view="likes" onclick="switchView('likes')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 2.5 15 9l7 .9-5.1 4.8L18.2 21 12 17.4 5.8 21l1.3-6.3L2 9.9 9 9z"/></svg></span> Likes You <span class="badge" id="nav-likes-count">0</span></button>
    <button class="nav-item" data-view="explore" onclick="switchView('explore')"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="m15.5 8.5-2 5-5 2 2-5Z"/></svg></span> Explore</button>
    <button class="nav-item" data-view="profile" onclick="switchView('profile')" aria-label="Profile"><span class="icon"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="3.6"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/></svg></span> Profile</button>

    <div class="sidebar-spacer"></div>

    <div class="premium-card">
      <div class="title"><svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M3 8.5 7 11l5-7 5 7 4-2.5-1.6 10.5H4.6L3 8.5Z"/></svg> Go Premium</div>
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
      <div class="top-actions">
        <button class="icon-btn filter-btn" id="filter-trigger-btn" onclick="openFilterPanel()" aria-label="Filters" title="Filters" aria-haspopup="dialog" aria-expanded="false">
          <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><line x1="4" y1="6" x2="20" y2="6"/><circle cx="9" cy="6" r="2.1" fill="white" stroke="currentColor"/><line x1="4" y1="12" x2="20" y2="12"/><circle cx="16" cy="12" r="2.1" fill="white" stroke="currentColor"/><line x1="4" y1="18" x2="20" y2="18"/><circle cx="11" cy="18" r="2.1" fill="white" stroke="currentColor"/></svg>
          <span class="dot" id="filter-badge" style="display:none;">0</span>
        </button>
        <button class="icon-btn" id="profile-settings-btn" onclick="openProfileSettings()" aria-label="Settings" title="Settings" style="display:none;">
          <span aria-hidden="true">⚙️</span>
        </button>
        <div class="top-avatar" id="top-avatar">?</div>
      </div>
    </div>

    <div class="content-grid">
      <div class="discover-col">

`;
