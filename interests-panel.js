// Client JS: Interests panel and candidate card builders
module.exports = `// ---------- Interests panel (own "Edit" entry point, like About Me) ----------

function openInterestsPanel() {
  state.interestsDraft = buildInterestsDraftFromTags(state.user ? state.user.tags : []);
  renderInterestCategoryPicker('interests-panel-body', state.interestsDraft);
  attachInterestCategoryDelegation('interests-panel-body', () => state.interestsDraft);
  document.getElementById('interests-overlay').classList.add('open');
  document.getElementById('interests-panel').classList.add('open');
  document.getElementById('interests-panel').setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
}

function closeInterestsPanel() {
  document.getElementById('interests-overlay').classList.remove('open');
  document.getElementById('interests-panel').classList.remove('open');
  document.getElementById('interests-panel').setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}

function clearAllInterests() {
  state.interestsDraft = {};
  renderInterestCategoryPicker('interests-panel-body', state.interestsDraft);
}

async function saveInterestsAndClose() {
  const tags = flattenInterestsDraft(state.interestsDraft);
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify({ tags }) });
    state.user = data.user;
    refreshProfileViewMode();
    updateProfileCompletionDisplay();
    closeInterestsPanel();
  } catch (err) {
    alert(err.message || 'Could not save your interests. Please try again.');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  syncSettingsUI();
  attachChipDelegation(document.getElementById('filter-panel'), () => state.filters);
  attachChipDelegation(document.getElementById('details-form-body'), () => state.details, updateDetailsProgress);
  attachChipDelegation(document.getElementById('looking-for-form-body'), () => lookingForDraft);

  // Keep the select-based About Me fields in state while editing.
  const detailsBody = document.getElementById('details-form-body');
  if (detailsBody) {
    detailsBody.querySelectorAll('#d-education, #d-religion, #d-political').forEach(select => {
      select.addEventListener('change', () => {
        const key = select.id === 'd-education' ? 'education' : select.id === 'd-religion' ? 'religion' : 'political';
        state.details[key] = select.value;
        updateDetailsProgress();
      });
    });
  }

  updateFilterBadge();
});

// Builds the full rich profile card (photo + About Me/Interests/Vibes/
// Prompts/Compatibility Answers) — used inside the "view profile" modal
// opened from a Discover row.
// Minimal "may like" carousel photo: just the picture with name, age, and
// location overlaid — no bio/interests/vibes. Tapping it opens the full
// profile (buildCandidateCardHTML) in the detail modal.
// Interest tags are grouped into categories (see INTEREST_CATEGORIES above).
// This reverse-looks-up a tag's category and pairs it with a small icon, so
// a candidate's picked interests can render as icon+label pills — used on
// the Discover "may like" photo card, right under their location.
const TAG_CATEGORY_LOOKUP = (() => {
  const map = {};
  Object.keys(INTEREST_CATEGORIES).forEach(cat => {
    INTEREST_CATEGORIES[cat].forEach(tag => { map[tag] = cat; });
  });
  return map;
})();

const CATEGORY_ICONS = {
  'Pets': '<svg viewBox="0 0 24 24" width="11" height="11" aria-hidden="true" focusable="false"><circle cx="7" cy="7" r="2" fill="currentColor"/><circle cx="12" cy="5.5" r="2" fill="currentColor"/><circle cx="17" cy="7" r="2" fill="currentColor"/><circle cx="19" cy="12" r="2" fill="currentColor"/><path d="M12 12c-3.5 0-6.5 2.3-6.5 5.2 0 1.7 1.5 2.8 3.3 2.2.9-.3 1.8-.5 3.2-.5s2.3.2 3.2.5c1.8.6 3.3-.5 3.3-2.2 0-2.9-3-5.2-6.5-5.2Z" fill="currentColor"/></svg>',
  'Personality and traits': '<svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg>',
  'Self-care': '<svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 21s-7-4.35-9.5-9A5.5 5.5 0 0 1 12 6a5.5 5.5 0 0 1 9.5 6c-2.5 4.65-9.5 9-9.5 9Z"/></svg>',
  'Sports': '<svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="m3 19 6.5-11L13 14l3-5 5 10Z"/></svg>',
  'Creativity': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 21c1-4 3-6 6-7l9-9 3 3-9 9c-1 3-3 5-7 6a2 2 0 0 1-2-2Z"/></svg>',
  'Going out': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 4h14l-7 8Z"/><path d="M12 12v7M8 19h8"/></svg>',
  'Staying in': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 11 12 3l9 8"/><path d="M5 10v10h14V10"/></svg>',
  'Film and TV': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M7 21V9a5 5 0 0 1 10 0v12l-2-1.5-1.5 1.5L12 19.5 10.5 21 9 19.5Z"/><circle cx="10" cy="8" r="1" fill="currentColor" stroke="none"/><circle cx="14" cy="8" r="1" fill="currentColor" stroke="none"/></svg>',
  'Reading': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H12v18H6.5A2.5 2.5 0 0 1 4 18.5Z"/><path d="M20 5.5A2.5 2.5 0 0 0 17.5 3H12v18h5.5a2.5 2.5 0 0 0 2.5-2.5Z"/></svg>',
  'Music': '<svg viewBox="0 0 24 24" width="11" height="11" aria-hidden="true" focusable="false"><circle cx="6.5" cy="18" r="2.5" fill="currentColor"/><circle cx="17.5" cy="16" r="2.5" fill="currentColor"/><path d="M9 18V5l11-2v13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  'Food and drink': '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 8h13v5a5 5 0 0 1-5 5H9a5 5 0 0 1-5-5Z"/><path d="M17 9h1.5a2.5 2.5 0 0 1 0 5H17"/><path d="M7 3.5c0 1-1 1-1 2s1 1 1 2M11 3.5c0 1-1 1-1 2s1 1 1 2"/></svg>',
  'Traveling': '<svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M21 16v-1.5l-8-5V4.5a1.5 1.5 0 0 0-3 0v5l-8 5V16l8-2.5V19l-2 1.5V22l3.5-1 3.5 1v-1.5L13 19v-5.5Z"/></svg>',
};

function interestTagIcon(tag) {
  const cat = TAG_CATEGORY_LOOKUP[tag];
  return (cat && CATEGORY_ICONS[cat]) || CATEGORY_ICONS['Personality and traits'];
}

// Up to "max" icon+label pills for a candidate's picked interests.
function buildInterestTagPillsHTML(tags, max = 4) {
  if (!tags || !tags.length) return '';
  return \`<div class="interest-tags-row">\${tags.slice(0, max).map(t =>
    \`<span class="interest-tag-pill">\${interestTagIcon(t)}\${escapeHtml(t)}</span>\`
  ).join('')}</div>\`;
}

function buildCandidateMiniPhotoHTML(c) {
  const photoStyle = c.photoUrl
    ? \`background-image:url('\${c.photoUrl}');background-size:cover;background-position:center;\`
    : \`background:linear-gradient(135deg, \${colorFor(c.name)}, #2a1620);\`;
  return \`
    <div class="swipe-photo discover-carousel-photo" style="\${photoStyle}">
      <div class="info-affordance" title="Tap to view full profile"><svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="8" r="1.3" fill="currentColor" stroke="none"/><path d="M12 11v5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></div>
      \${c.compatibility !== null && c.compatibility !== undefined ? \`<div class="photo-counter compat-badge" style="position:absolute;top:12px;right:12px;"><svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${c.compatibility}% Match</div>\` : ''}
      <div class="swipe-details">
        <div class="name-row">\${escapeHtml(c.name)}\${c.age ? ', ' + c.age : ''}</div>
        \${c.location ? \`<div class="meta"><span><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 21s7-6.5 7-11.5A7 7 0 1 0 5 9.5C5 14.5 12 21 12 21Z"/><circle cx="12" cy="9.5" r="2.2"/></svg> \${escapeHtml(c.location)}</span></div>\` : ''}
        \${buildInterestTagPillsHTML(c.tags)}
      </div>
    </div>\`;
}

function buildCandidateCardHTML(c) {
  const photoStyle = c.photoUrl
    ? \`background-image:url('\${c.photoUrl}');background-size:cover;background-position:center;\`
    : \`background:linear-gradient(135deg, \${colorFor(c.name)}, #2a1620);\`;
  return \`
    <div class="swipe-card">
      <div class="swipe-photo" style="\${photoStyle}">
        <div class="photo-tag"><svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${c.tags && c.tags.length ? escapeHtml(c.tags[0]) : 'New here'}</div>
        \${c.compatibility !== null && c.compatibility !== undefined ? \`<div class="photo-counter compat-badge" style="position:absolute;top:16px;right:16px;"><svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${c.compatibility}% Match</div>\` : ''}
        <div class="swipe-details">
          <div class="name-row">\${escapeHtml(c.name)}\${c.age ? ', ' + c.age : ''}</div>
          <div class="meta">\${c.location ? '<span><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 21s7-6.5 7-11.5A7 7 0 1 0 5 9.5C5 14.5 12 21 12 21Z"/><circle cx="12" cy="9.5" r="2.2"/></svg> ' + escapeHtml(c.location) + '</span>' : ''}</div>
        </div>
      </div>
      <div class="swipe-card-body">
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg></span>About Me</div>
          <p class="swipe-section-text \${c.bio ? '' : 'empty'}">\${c.bio ? escapeHtml(c.bio) : 'No bio yet.'}</p>
          <div class="about-pills-grid">\${buildAboutPillsHTML(c)}</div>
        </div>
        \${c.datingIntentions && c.datingIntentions.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle">\${LOOKING_FOR_ICON}</span>I'm looking for</div>
          <div class="about-pills-grid">\${buildLookingForPillsHTML(c)}</div>
        </div>\` : ''}
        \${c.tags && c.tags.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></span>Interests</div>
          <div class="interests-chips">\${c.tags.map(t => '<span class="interest-chip">' + escapeHtml(t) + '</span>').join('')}</div>
        </div>\` : ''}
        \${c.galleryUrls && c.galleryUrls.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="3" y="6" width="18" height="14" rx="2.5"/><circle cx="12" cy="13" r="3.5"/><path d="M8 6l1.4-2.4A1.5 1.5 0 0 1 10.7 3h2.6a1.5 1.5 0 0 1 1.3.76L16 6"/></svg></span>My Vibes</div>
          <div class="swipe-vibes-grid">\${c.galleryUrls.map((url, i) => '<div class="swipe-vibes-thumb" onclick="event.stopPropagation(); openPhotoLightbox(' + escapeHtml(JSON.stringify(c.galleryUrls)) + ', ' + i + ')"><img src="' + escapeHtml(url) + '" alt="Vibes photo ' + (i + 1) + '" loading="lazy" /></div>').join('')}</div>
        </div>\` : ''}
        \${c.prompts && c.prompts.filter(p => p && p.question && p.answer).length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></span>Prompts</div>
          \${c.prompts.filter(p => p && p.question && p.answer).map(p => '<div class="prompt-view-card"><div class="prompt-view-question">' + escapeHtml(p.question) + '</div><div class="prompt-view-answer">' + escapeHtml(p.answer) + '</div></div>').join('')}
        </div>\` : ''}
        \${c.quizAnswers && c.quizAnswers.length ? \`
        <div class="swipe-section">
          <div class="swipe-section-title"><span class="icon-circle"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></span>Compatibility Answers</div>
          \${c.quizAnswers.map(q => '<div class="prompt-view-card"><div class="prompt-view-question">' + escapeHtml(q.question) + '</div><div class="prompt-view-answer">' + escapeHtml(q.answer) + '</div></div>').join('')}
        </div>\` : ''}
      </div>
    </div>
  \`;
}

`;
