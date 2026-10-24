// Discover: swipeable card stack, list/sections, like/pass actions, candidate detail
// NOTE: classic script (not an ES module) — shares globals with the other files in /js,
// so keep the load order from index.html.
// ---------- Discover — swipeable card stack ----------
// Renders up to 3 cards stacked with a slight offset; only the top card is
// draggable. Swipe (or drag past the threshold) right = like, left = pass.
function renderDiscoverSectionRow(c, allowLike) {
  const photo = c.photoUrl ? `background-image:url('${escapeHtml(c.photoUrl)}')` : `background:${colorFor(c.name)}`;
  const tags = (c.tags || []).slice(0, 3).map(t => `<span>${escapeHtml(t)}</span>`).join('');
  return `
    <div class="discover-row" onclick="openCandidateDetail('${escapeHtml(c.id)}')">
      <div class="discover-row-photo" style="${photo}"></div>
      <div class="discover-row-body">
        <div class="discover-row-name">${escapeHtml(c.name)}${c.age ? ', ' + c.age : ''}</div>
        <div class="discover-row-loc">${escapeHtml(c.location || c.country || '')}</div>
        ${c.bio ? `<div class="discover-row-bio">${escapeHtml(c.bio)}</div>` : ''}
        ${tags ? `<div class="discover-row-tags">${tags}</div>` : ''}
      </div>
      ${allowLike ? `<button class="discover-row-like" type="button" onclick="event.stopPropagation(); discoverSectionLike('${escapeHtml(c.id)}')" aria-label="Like ${escapeHtml(c.name)}" title="Like">♥</button>` : ''}
    </div>`;
}

function renderDiscoverSection(profiles, allowLike) {
  if (!profiles || !profiles.length) return '';
  return `<section class="discover-section">
    <div>${profiles.map(c => renderDiscoverSectionRow(c, allowLike)).join('')}</div>
  </section>`;
}

// Tab id -> heading shown above the cards, and the profile list it draws from.
const DISCOVER_TAB_META = {
  maylike: { label: 'Profiles You May Like', list: () => state.candidates, allowLike: null },
  liked: { label: 'Profiles You Liked', list: () => state.likedProfiles, allowLike: false },
  nearby: { label: 'Users Nearby', list: () => state.nearbyProfiles, allowLike: true },
  new: { label: 'New Users', list: () => state.newProfiles, allowLike: true },
};

function renderDiscoverList() {
  const stack = document.getElementById('discover-list');
  const hint = document.getElementById('discover-stack-hint');
  const actions = document.getElementById('discover-stack-actions');
  const heading = document.getElementById('discover-tab-heading');
  const count = document.getElementById('discover-tab-count');
  if (!stack) return;
  closeAllDiscoverMenus();

  const tab = state.activeDiscoverTab || 'maylike';
  const meta = DISCOVER_TAB_META[tab] || DISCOVER_TAB_META.maylike;
  const list = meta.list();

  // Keeps the carousel area a fixed height (card-sized) whether it's full
  // or showing "no more profiles" — only for the maylike tab; row-list
  // tabs (Liked/Nearby/New) size to their own content as before.
  stack.classList.toggle('discover-stack--carousel', tab === 'maylike');

  // The tab name above the cards updates immediately on every tab switch,
  // independent of whatever layout that tab's cards use below it.
  if (heading && count) {
    heading.childNodes[0].textContent = meta.label + ' ';
    count.textContent = list.length;
  }

  const navPrev = document.getElementById('discover-nav-prev');
  const navNext = document.getElementById('discover-nav-next');
  const exploreHint = document.getElementById('discover-explore-hint');
  const showCarouselUi = tab === 'maylike' && list.length > 0;
  if (hint) hint.style.display = showCarouselUi ? '' : 'none';
  if (actions) actions.style.display = showCarouselUi ? '' : 'none';
  if (exploreHint) exploreHint.style.display = showCarouselUi ? '' : 'none';
  if (navPrev) navPrev.style.display = showCarouselUi ? '' : 'none';
  if (navNext) navNext.style.display = showCarouselUi ? '' : 'none';

  if (tab !== 'maylike') {
    stack.innerHTML = renderDiscoverSection(list, meta.allowLike) || '<div class="empty-state">No profiles in this section right now.</div>';
    return;
  }

  if (!list.length) {
    stack.innerHTML = '<div class="empty-state">No more profiles right now. Check back later!</div>';
    return;
  }

  // Everyone in the queue scrolls left-to-right as a filmstrip of compact
  // photo cards (picture, name, age, location). Tapping a card opens the
  // full profile; the Pass/Like buttons below the carousel act on
  // whichever card is currently snapped into view (ringed in pink).
  const cards = list.map(c => `
      <div class="discover-carousel-card" data-id="${c.id}" onclick="openCandidateDetail('${c.id}')">${buildCandidateMiniPhotoHTML(c)}</div>`).join('');

  stack.innerHTML = `<section class="discover-section discover-like-section">
    <div class="discover-carousel" id="discover-carousel">${cards}</div>
  </section>`;

  const track = document.getElementById('discover-carousel');
  if (track) {
    track.addEventListener('scroll', updateCarouselCurrent, { passive: true });
    updateCarouselCurrent();
  }
}

// Tracks which carousel card is currently snapped into view, so the Pass/
// Like buttons below the carousel know which profile to act on.
function updateCarouselCurrent() {
  const track = document.getElementById('discover-carousel');
  if (!track) return;
  let closest = null, closestDist = Infinity;
  track.querySelectorAll('.discover-carousel-card').forEach(el => {
    const dist = Math.abs(el.offsetLeft - track.scrollLeft);
    if (dist < closestDist) { closestDist = dist; closest = el; }
  });
  track.querySelectorAll('.discover-carousel-card.is-current').forEach(el => el.classList.remove('is-current'));
  if (closest) {
    closest.classList.add('is-current');
    state.carouselCurrentId = closest.getAttribute('data-id');
  } else {
    state.carouselCurrentId = null;
  }
}

// Scrolls the "may like" filmstrip by roughly one card width. Purely a
// browsing aid for pointer/keyboard users — it never records a like/pass.
function scrollDiscoverCarousel(delta) {
  const track = document.getElementById('discover-carousel');
  if (!track) return;
  const card = track.querySelector('.discover-carousel-card');
  const amount = (card ? card.getBoundingClientRect().width : track.clientWidth) + 16;
  track.scrollBy({ left: delta * amount, behavior: 'smooth' });
}

function setDiscoverTab(tab) {
  if (!DISCOVER_TAB_META[tab]) return;
  state.activeDiscoverTab = tab;
  state.carouselCurrentId = null;
  document.querySelectorAll('.discover-category-tabs button').forEach(btn => {
    const isActive = btn.getAttribute('onclick') === `setDiscoverTab('${tab}')`;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
  });
  renderDiscoverList();
}

async function discoverSectionLike(id) {
  const c = state.allCandidates.find(x => x.id === id);
  if (!c) return;
  try {
    const data = await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: c.id, direction: 'like' }) });
    state.candidates = state.candidates.filter(x => x.id !== id);
    state.allCandidates = state.allCandidates.filter(x => x.id !== id);
    state.nearbyProfiles = state.nearbyProfiles.filter(x => x.id !== id);
    state.newProfiles = state.newProfiles.filter(x => x.id !== id);
    state.likedProfiles = [c, ...state.likedProfiles.filter(x => x.id !== id)];
    renderDiscoverList();
    if (data.matched) {
      await loadMatches();
      alert("It's a match with " + c.name + "!");
    }
  } catch (err) {
    alert(err.message);
  }
}

// Fired by the Pass/Like buttons below the carousel — they always act on
// state.carouselCurrentId, the card currently snapped into view.
function swipeCurrentCard(direction) {
  if (!state.carouselCurrentId) return;
  const btn = document.querySelector(`#discover-stack-actions .${direction === 'like' ? 'act-like' : 'act-pass'}`);
  if (btn) { btn.classList.remove('tap-pop'); void btn.offsetWidth; btn.classList.add('tap-pop'); }
  if (direction === 'like') carouselLikeCandidate(state.carouselCurrentId);
  else carouselPassCandidate(state.carouselCurrentId);
}

// After a card is removed from the "may like" queue (liked or passed),
// re-render and keep the filmstrip roughly where the user was rather than
// snapping back to the start.
function rerenderCarouselKeepingPosition(removedIdx) {
  renderDiscoverList();
  const track = document.getElementById('discover-carousel');
  if (!track) return;
  const cards = track.querySelectorAll('.discover-carousel-card');
  if (!cards.length) return;
  const target = cards[Math.min(removedIdx, cards.length - 1)];
  if (target) track.scrollLeft = target.offsetLeft;
  updateCarouselCurrent();
}

// The heart Like button below the carousel. Commits the like and drops the
// card out of the filmstrip.
async function carouselLikeCandidate(id) {
  if (state.swipeBusy) return;
  const idx = state.candidates.findIndex(x => x.id === id);
  if (idx === -1) return;
  const c = state.candidates[idx];
  state.swipeBusy = true;
  try {
    const data = await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: c.id, direction: 'like' }) });
    state.candidates.splice(idx, 1);
    state.allCandidates = state.allCandidates.filter(x => x.id !== c.id);
    state.likedProfiles = [c, ...state.likedProfiles.filter(x => x.id !== c.id)];
    rerenderCarouselKeepingPosition(idx);
    if (data.matched) {
      await loadMatches();
      alert("It's a match with " + c.name + "!");
    }
  } catch (err) {
    alert(err.message);
  } finally {
    state.swipeBusy = false;
  }
}

// The X Pass button below the carousel. Records the pass and drops the
// card out of the filmstrip (it won't be shown again).
async function carouselPassCandidate(id) {
  if (state.swipeBusy) return;
  const idx = state.candidates.findIndex(x => x.id === id);
  if (idx === -1) return;
  state.swipeBusy = true;
  try {
    await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: id, direction: 'pass' }) });
    state.candidates.splice(idx, 1);
    state.allCandidates = state.allCandidates.filter(x => x.id !== id);
    rerenderCarouselKeepingPosition(idx);
  } catch (err) {
    alert(err.message);
  } finally {
    state.swipeBusy = false;
  }
}


function toggleDiscoverRowMenu(event, id) {
  const menu = document.getElementById('row-menu-' + id);
  if (!menu) return;
  const wasOpen = menu.classList.contains('open');
  closeAllDiscoverMenus();
  if (!wasOpen) menu.classList.add('open');
}
function closeAllDiscoverMenus() {
  document.querySelectorAll('.discover-row-menu.open').forEach(m => m.classList.remove('open'));
}

let currentDetailCandidateId = null;

function getCandidateById(id) {
  return state.candidates.find(x => x.id === id)
    || state.likedProfiles.find(x => x.id === id)
    || state.nearbyProfiles.find(x => x.id === id)
    || state.newProfiles.find(x => x.id === id)
    || null;
}

function openCandidateDetail(id) {
  const c = getCandidateById(id);
  if (!c) return;
  currentDetailCandidateId = id;
  document.getElementById('candidate-detail-body').innerHTML = buildCandidateCardHTML(c);
  document.getElementById('candidate-detail-footer').innerHTML = `
    <button class="act-like" onclick="discoverListAction('${id}','like'); closeCandidateDetail();" aria-label="Like" title="Like"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></button>
  `;
  document.getElementById('candidate-detail-modal').classList.add('visible');
}
function closeCandidateDetail() {
  document.getElementById('candidate-detail-modal').classList.remove('visible');
  currentDetailCandidateId = null;
}

