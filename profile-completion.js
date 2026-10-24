// Complete-your-profile step and "I'm looking for" editor
// NOTE: classic script (not an ES module) — shares globals with the other files in /js,
// so keep the load order from index.html.
// ---------- Complete your profile (extended details) ----------
// Mirrors PROFILE_COMPLETION_FIELDS on the server so the progress bar here
// and the "Profile strength" bar on the Profile tab agree with what the
// backend reports back after a save.
const PROFILE_STRENGTH_SECTIONS = [
  { key: 'profilePhoto', weight: 10, fields: [u => u.photoUrl] },
  { key: 'nameAndAge', weight: 10, fields: [u => u.name, u => u.age] },
  { key: 'bio', weight: 10, fields: [u => u.bio] },
  { key: 'locationAndQuiz', weight: 20, fields: [
    u => u.location,
    u => u.questionnaire?.relationship_goal,
    u => u.questionnaire?.wants_kids,
    u => u.questionnaire?.personality,
    u => u.questionnaire?.top_value,
    u => u.questionnaire?.conflict_style,
    u => u.questionnaire?.social_style,
    u => u.questionnaire?.career_priority,
    u => u.questionnaire?.communication_style,
    u => u.questionnaire?.personal_space,
    u => u.questionnaire?.lifestyle_pace,
    u => u.questionnaire?.dealbreakers,
  ] },
  { key: 'interestsAndQuickInfo', weight: 10, fields: [u => u.tags, u => u.languages] },
  { key: 'lookingFor', weight: 10, fields: [u => u.datingIntentions] },
  { key: 'lifestyle', weight: 5, fields: [
    u => u.education, u => u.heightCm, u => u.exercise, u => u.drinking,
    u => u.smoking, u => u.religion, u => u.political, u => u.children,
    u => u.wantsChildren,
  ] },
  { key: 'additionalPhotosOrVibe', weight: 15, fields: [
    u => u.galleryUrls?.[0], u => u.galleryUrls?.[1], u => u.galleryUrls?.[2],
  ] },
  { key: 'prompts', weight: 10, fields: [
    u => u.prompts?.[0], u => u.prompts?.[1], u => u.prompts?.[2],
  ] },
];
function isProfileValueCompletedClient(value) {
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'boolean') return true;
  return value !== null && value !== undefined && String(value).trim().length > 0;
}
function computeProfileStrengthClient(u) {
  let total = 0;
  for (const section of PROFILE_STRENGTH_SECTIONS) {
    const completed = section.fields.reduce((n, get) => {
      let value = null;
      try { value = get(u || {}); } catch (_) {}
      return n + (isProfileValueCompletedClient(value) ? 1 : 0);
    }, 0);
    total += section.weight * (completed / section.fields.length);
  }
  return Math.min(100, Math.round(total));
}
function computeCompletionClient(u) {
  return computeProfileStrengthClient(u);
}

function updateProfileCompletionDisplay() {
  const pctEl = document.getElementById('ph-strength-pct');
  if (!pctEl || !state.user) return;
  const strength = state.user.profileStrength;
  const pct = (strength && typeof strength.percentage === 'number')
    ? strength.percentage
    : computeCompletionClient(state.user);

  pctEl.textContent = pct + '%';
  document.getElementById('ph-strength-fill').style.width = pct + '%';

  const hintEl = document.getElementById('ph-strength-hint');
  if (!hintEl) return;
  if (pct >= 100) {
    hintEl.textContent = 'Your profile is fully complete!';
    return;
  }
  // Point people at whichever weighted section has the biggest gap between
  // its max weight and the points it's currently earning.
  const sections = (strength && strength.sections) || null;
  if (!sections) { hintEl.textContent = ''; return; }
  let weakest = null;
  for (const key in sections) {
    const s = sections[key];
    const gap = s.weight - s.points;
    if (gap > 0.01 && (!weakest || gap > weakest.gap)) weakest = { label: s.label, gap };
  }
  hintEl.textContent = weakest ? ('Add more to "' + weakest.label + '" to boost your score') : '';
}

function defaultDetails() {
  return {
    languages: [], education: '', heightCm: 170, exercise: '',
    drinking: '', smoking: '', religion: '', political: '',
    children: '', wantsChildren: '', datingIntentions: [],
  };
}

function populateDetailsFormFromUser(user) {
  state.details = {
    languages: (user.languages || []).slice(),
    education: user.education || '',
    heightCm: user.heightCm || 170,
    exercise: user.exercise || '',
    drinking: user.drinking || '',
    smoking: user.smoking || '',
    religion: user.religion || '',
    political: user.political || '',
    children: user.children || '',
    wantsChildren: user.wantsChildren || '',
    datingIntentions: (user.datingIntentions || []).slice(),
  };
  document.getElementById('d-education').value = state.details.education;
  document.getElementById('d-religion').value = state.details.religion;
  document.getElementById('d-political').value = state.details.political;
  document.getElementById('d-height').value = state.details.heightCm;
  document.getElementById('d-height-val').textContent = state.details.heightCm + ' cm';
  syncChipSelectedStatesIn(document.getElementById('details-form-body'), state.details);
  updateDetailsProgress();
}

function onDetailsHeightInput() {
  const v = parseInt(document.getElementById('d-height').value, 10);
  state.details.heightCm = v;
  document.getElementById('d-height-val').textContent = v + ' cm';
  updateDetailsProgress();
}

function updateDetailsProgress() {
  const fill = document.getElementById('details-progress-fill');
  if (!fill || !state.user) return;
  const merged = Object.assign({}, state.user, state.details);
  fill.style.width = computeCompletionClient(merged) + '%';
}

function showDetailsScreen(origin) {
  state.detailsOrigin = origin;
  populateDetailsFormFromUser(state.user || {});
  const screen = document.getElementById('details-screen');
  const isProfileEdit = origin === 'profile';
  screen.classList.toggle('profile-overlay-mode', isProfileEdit);
  const saveBtn = document.getElementById('details-save-btn');
  const cancelBtn = screen.querySelector('.q-skip');
  if (saveBtn) saveBtn.textContent = isProfileEdit ? 'Save' : 'Save & continue';
  if (cancelBtn) cancelBtn.textContent = isProfileEdit ? 'Cancel' : 'Skip for now';
  screen.classList.add('visible');
  if (isProfileEdit) document.body.style.overflow = 'hidden';
}

function closeDetailsScreen() {
  const screen = document.getElementById('details-screen');
  screen.classList.remove('visible', 'profile-overlay-mode');
  document.body.style.overflow = '';
}

async function proceedAfterDetails() {
  const origin = state.detailsOrigin;
  document.getElementById('details-screen').classList.remove('visible', 'profile-overlay-mode');
  document.body.style.overflow = '';
  if (origin === 'signup') {
    await enterDashboard();
  } else {
    document.getElementById('dashboard').classList.add('visible');
    updateProfileCompletionDisplay();
    switchView('profile');
  }
}

async function saveDetailsScreen() {
  const btn = document.getElementById('details-save-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify(state.details) });
    state.user = data.user;
    refreshProfileViewMode();
    await proceedAfterDetails();
  } catch (e) {
    alert(e.message || 'Could not save your profile details. Please try again.');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save & continue'; }
  }
}

async function skipDetailsScreen() {
  await proceedAfterDetails();
}

// ---------- "I'm looking for" editor (dating intentions only) ----------
// Deliberately separate from the details screen/state above — this only
// ever reads/writes datingIntentions, leaving every other profile field
// (and showDetailsScreen) untouched.
let lookingForDraft = { datingIntentions: [] };

function populateLookingForFormFromUser(user) {
  lookingForDraft = { datingIntentions: (user.datingIntentions || []).slice() };
  syncChipSelectedStatesIn(document.getElementById('looking-for-form-body'), lookingForDraft);
}

function showLookingForScreen() {
  populateLookingForFormFromUser(state.user || {});
  const screen = document.getElementById('looking-for-screen');
  screen.classList.add('profile-overlay-mode', 'visible');
  const saveBtn = document.getElementById('looking-for-save-btn');
  if (saveBtn) saveBtn.textContent = 'Save';
  document.body.style.overflow = 'hidden';
}

function closeLookingForScreen() {
  document.getElementById('looking-for-screen').classList.remove('visible', 'profile-overlay-mode');
  document.body.style.overflow = '';
}

async function saveLookingForScreen() {
  const btn = document.getElementById('looking-for-save-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify({ datingIntentions: lookingForDraft.datingIntentions }) });
    state.user = data.user;
    refreshProfileViewMode();
    closeLookingForScreen();
  } catch (e) {
    alert(e.message || 'Could not save your dating intentions. Please try again.');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
  }
}

