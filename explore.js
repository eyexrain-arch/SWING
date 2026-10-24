// Explore grid
// NOTE: classic script (not an ES module) — shares globals with the other files in /js,
// so keep the load order from index.html.
// ---------- Explore — grid of all currently eligible profiles ----------
// Uses the same already-loaded, already-filtered pool as the Discover
// "may like" carousel (state.candidates, populated by loadDiscover() and
// re-applied whenever the filter panel changes) — just laid out as a
// browsable grid instead of one swipeable card at a time.
function buildExploreCardHTML(c) {
  const photo = c.photoUrl ? `background-image:url('${escapeHtml(c.photoUrl)}')` : `background:${colorFor(c.name)}`;
  return `
    <div class="explore-card" onclick="openCandidateDetail('${escapeHtml(c.id)}')">
      <div class="explore-card-photo" style="${photo}">
        <div class="explore-card-info">
          <div class="explore-card-name">${escapeHtml(c.name)}${c.age ? ', ' + c.age : ''}</div>
          ${c.location ? `<div class="explore-card-loc">${escapeHtml(c.location)}</div>` : ''}
        </div>
      </div>
    </div>`;
}

function renderExploreGrid() {
  const grid = document.getElementById('explore-grid');
  if (!grid) return;
  const profiles = state.candidates || [];
  grid.innerHTML = profiles.length
    ? profiles.map(buildExploreCardHTML).join('')
    : '<div class="empty-state">No profiles available right now. Check back later!</div>';
}

