// HTML: End of <main> and mobile navigation
module.exports = `  </main>

  <nav class="mobile-nav" aria-label="Primary">
    <button class="mobile-nav-item active" data-view="discover" onclick="switchView('discover')" aria-label="Discover" aria-current="page">
      <span class="icon">
        <svg class="icon-outline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v9a1 1 0 0 0 1 1H9a1 1 0 0 0 1-1v-4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v4a1 1 0 0 0 1 1h2.5a1 1 0 0 0 1-1v-9"/></svg>
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><path d="M12 3.2 3 11.2v1.3h2.2V20a1 1 0 0 0 1 1H10v-6.2h4V21h3.8a1 1 0 0 0 1-1v-7.5H21v-1.3z"/></svg>
      </span>
      <span class="nav-dot"></span>
    </button>
    <button class="mobile-nav-item" data-view="matches" onclick="switchView('matches')" aria-label="Messages">
      <span class="icon">
        <svg class="icon-outline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 11.5a8.4 8.4 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.4 8.4 0 0 1-3.8-.9L3 21l1.9-5.7a8.4 8.4 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6A8.4 8.4 0 0 1 12.5 3h.5a8.48 8.48 0 0 1 8 8v.5Z"/></svg>
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><path d="M12.5 2.5h-.5A9 9 0 0 0 3 11.5a8.9 8.9 0 0 0 .9 4L2 21.5l6.2-1.8a8.9 8.9 0 0 0 3.8.9 9 9 0 0 0 9-9v-.5a9 9 0 0 0-8.5-8.6z"/></svg>
      </span>
      <span class="nav-dot"></span>
      <span class="mnav-badge" id="mnav-messages-count" style="display:none;"></span>
    </button>
    <button class="mobile-nav-item mobile-nav-fab" data-view="explore" onclick="switchView('explore')" aria-label="Explore">
      <span class="icon">
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm3.8 5.7-2.1 5.6a1 1 0 0 1-.6.6l-5.6 2.1a.5.5 0 0 1-.6-.6l2.1-5.6a1 1 0 0 1 .6-.6l5.6-2.1a.5.5 0 0 1 .6.6Z"/></svg>
      </span>
    </button>
    <button class="mobile-nav-item" data-view="likes" onclick="switchView('likes')" aria-label="Likes you">
      <span class="icon">
        <svg class="icon-outline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 2.5 15 9l7 .9-5.1 4.8L18.2 21 12 17.4 5.8 21l1.3-6.3L2 9.9 9 9z"/></svg>
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><path d="M12 2.5 15 9l7 .9-5.1 4.8L18.2 21 12 17.4 5.8 21l1.3-6.3L2 9.9 9 9z"/></svg>
      </span>
      <span class="nav-dot"></span>
      <span class="mnav-badge" id="mnav-likes-count" style="display:none;"></span>
    </button>
    <button class="mobile-nav-item" data-view="profile" onclick="switchView('profile')" aria-label="Profile">
      <span class="icon">
        <svg class="icon-outline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="3.6"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/></svg>
        <svg class="icon-filled" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" focusable="false"><circle cx="12" cy="7.8" r="4"/><path d="M3.8 20.6c.7-4.4 4-7.1 8.2-7.1s7.5 2.7 8.2 7.1a1 1 0 0 1-1 1.2H4.8a1 1 0 0 1-1-1.2z"/></svg>
      </span>
      <span class="nav-dot"></span>
    </button>
  </nav>

`;
