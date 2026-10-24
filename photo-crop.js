// Profile photo crop tool
// NOTE: classic script (not an ES module) — shares globals with the other files in /js,
// so keep the load order from index.html.
// ---------- Profile photo crop tool ----------
// Every profile photo passes through this 3:4 crop step before it's
// uploaded. It's a small self-built pan/zoom cropper (drag to reposition,
// wheel or pinch to zoom) rather than a third-party library, so it doesn't
// need any change to the CSP or an external script dependency.
const photoCrop = {
  img: null,
  stageW: 0, stageH: 0,
  naturalW: 0, naturalH: 0,
  baseScale: 1, scale: 1, maxScale: 1,
  offsetX: 0, offsetY: 0,
  dragging: false, lastX: 0, lastY: 0,
  pinchDist: 0, pinchScale: 1,
};

function openPhotoCrop(dataUrl) {
  const img = new Image();
  img.onload = () => {
    const stage = document.getElementById('photo-crop-stage');
    // Make the modal visible FIRST — the stage is display:none until this
    // class is added, and measuring a hidden element's size always
    // returns 0x0, which is what was breaking the crop math.
    document.getElementById('photo-crop-overlay').classList.add('visible');
    const rect = stage.getBoundingClientRect();
    photoCrop.img = document.getElementById('photo-crop-img');
    photoCrop.stageW = rect.width;
    photoCrop.stageH = rect.height;
    photoCrop.naturalW = img.naturalWidth;
    photoCrop.naturalH = img.naturalHeight;
    photoCrop.baseScale = Math.max(rect.width / img.naturalWidth, rect.height / img.naturalHeight);
    photoCrop.maxScale = photoCrop.baseScale * 3;
    photoCrop.scale = photoCrop.baseScale;
    photoCrop.offsetX = (rect.width - img.naturalWidth * photoCrop.scale) / 2;
    photoCrop.offsetY = (rect.height - img.naturalHeight * photoCrop.scale) / 2;
    photoCrop.img.src = dataUrl;
    applyPhotoCropTransform();
    document.getElementById('photo-crop-confirm-btn').disabled = false;
  };
  img.src = dataUrl;
}

function cancelPhotoCrop() {
  document.getElementById('photo-crop-overlay').classList.remove('visible');
  photoCrop.img = null;
}

function clampPhotoCropOffsets() {
  const maxX = 0, minX = photoCrop.stageW - photoCrop.naturalW * photoCrop.scale;
  const maxY = 0, minY = photoCrop.stageH - photoCrop.naturalH * photoCrop.scale;
  photoCrop.offsetX = Math.min(maxX, Math.max(minX, photoCrop.offsetX));
  photoCrop.offsetY = Math.min(maxY, Math.max(minY, photoCrop.offsetY));
}

function applyPhotoCropTransform() {
  if (!photoCrop.img) return;
  clampPhotoCropOffsets();
  photoCrop.img.style.width = (photoCrop.naturalW * photoCrop.scale) + 'px';
  photoCrop.img.style.height = (photoCrop.naturalH * photoCrop.scale) + 'px';
  photoCrop.img.style.transform = 'translate(' + photoCrop.offsetX + 'px, ' + photoCrop.offsetY + 'px)';
}

function zoomPhotoCropAt(stageX, stageY, newScale) {
  newScale = Math.min(photoCrop.maxScale, Math.max(photoCrop.baseScale, newScale));
  // Keep whatever image point is under (stageX, stageY) fixed on screen
  // while the scale changes, so zooming feels anchored, not jumpy.
  const imgX = (stageX - photoCrop.offsetX) / photoCrop.scale;
  const imgY = (stageY - photoCrop.offsetY) / photoCrop.scale;
  photoCrop.scale = newScale;
  photoCrop.offsetX = stageX - imgX * newScale;
  photoCrop.offsetY = stageY - imgY * newScale;
  applyPhotoCropTransform();
}

(function initPhotoCropStageEvents() {
  // The stage element is static markup rendered once, so it's safe to wire
  // these listeners up immediately at script-load time.
  document.addEventListener('DOMContentLoaded', bind);
  if (document.readyState !== 'loading') bind();
  function bind() {
    const stage = document.getElementById('photo-crop-stage');
    if (!stage || stage.dataset.cropBound) return;
    stage.dataset.cropBound = '1';

    stage.addEventListener('pointerdown', (e) => {
      if (!photoCrop.img) return;
      photoCrop.dragging = true;
      photoCrop.lastX = e.clientX;
      photoCrop.lastY = e.clientY;
      stage.classList.add('dragging');
      stage.setPointerCapture(e.pointerId);
    });
    stage.addEventListener('pointermove', (e) => {
      if (!photoCrop.dragging || !photoCrop.img) return;
      photoCrop.offsetX += e.clientX - photoCrop.lastX;
      photoCrop.offsetY += e.clientY - photoCrop.lastY;
      photoCrop.lastX = e.clientX;
      photoCrop.lastY = e.clientY;
      applyPhotoCropTransform();
    });
    const endDrag = () => { photoCrop.dragging = false; stage.classList.remove('dragging'); };
    stage.addEventListener('pointerup', endDrag);
    stage.addEventListener('pointercancel', endDrag);

    stage.addEventListener('wheel', (e) => {
      if (!photoCrop.img) return;
      e.preventDefault();
      const rect = stage.getBoundingClientRect();
      const stageX = e.clientX - rect.left, stageY = e.clientY - rect.top;
      zoomPhotoCropAt(stageX, stageY, photoCrop.scale * (1 - e.deltaY * 0.0015));
    }, { passive: false });

    // Two-finger pinch to zoom on touch devices (pointer events cover the
    // drag case above for a single finger already).
    const activeTouches = new Map();
    stage.addEventListener('touchstart', (e) => {
      for (const t of e.changedTouches) activeTouches.set(t.identifier, t);
    }, { passive: true });
    stage.addEventListener('touchmove', (e) => {
      if (!photoCrop.img) return;
      for (const t of e.changedTouches) activeTouches.set(t.identifier, t);
      if (activeTouches.size < 2) return;
      e.preventDefault();
      const pts = Array.from(activeTouches.values()).slice(0, 2);
      const dist = Math.hypot(pts[0].clientX - pts[1].clientX, pts[0].clientY - pts[1].clientY);
      const rect = stage.getBoundingClientRect();
      const midX = (pts[0].clientX + pts[1].clientX) / 2 - rect.left;
      const midY = (pts[0].clientY + pts[1].clientY) / 2 - rect.top;
      if (photoCrop.pinchDist) {
        zoomPhotoCropAt(midX, midY, photoCrop.scale * (dist / photoCrop.pinchDist));
      }
      photoCrop.pinchDist = dist;
    }, { passive: false });
    const endTouch = (e) => {
      for (const t of e.changedTouches) activeTouches.delete(t.identifier);
      if (activeTouches.size < 2) photoCrop.pinchDist = 0;
    };
    stage.addEventListener('touchend', endTouch);
    stage.addEventListener('touchcancel', endTouch);
  }
})();

async function confirmPhotoCrop() {
  if (!photoCrop.img) return;
  const btn = document.getElementById('photo-crop-confirm-btn');
  btn.disabled = true;
  // Output at a fixed 3:4 pixel size regardless of source resolution or
  // on-screen stage size, so every uploaded profile photo is consistent.
  const OUT_W = 900, OUT_H = 1200;
  const canvas = document.createElement('canvas');
  canvas.width = OUT_W;
  canvas.height = OUT_H;
  const ctx = canvas.getContext('2d');
  const sx = -photoCrop.offsetX / photoCrop.scale;
  const sy = -photoCrop.offsetY / photoCrop.scale;
  const sWidth = photoCrop.stageW / photoCrop.scale;
  const sHeight = photoCrop.stageH / photoCrop.scale;
  const sourceImg = new Image();
  sourceImg.onload = async () => {
    ctx.drawImage(sourceImg, sx, sy, sWidth, sHeight, 0, 0, OUT_W, OUT_H);
    const croppedDataUrl = canvas.toDataURL('image/jpeg', 0.9);
    document.getElementById('photo-crop-overlay').classList.remove('visible');
    photoCrop.img = null;
    const status = document.getElementById('photo-upload-status');
    status.textContent = 'Uploading...';
    try {
      const data = await api('/api/profile/photo', { method: 'POST', body: JSON.stringify({ photo: croppedDataUrl }) });
      state.user = data.user;
      fillProfileForm();
      updateMeAvatars();
      status.textContent = 'Photo updated!';
      setTimeout(() => status.textContent = '', 1500);
    } catch (err) {
      status.textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  };
  sourceImg.src = document.getElementById('photo-crop-img').src;
}

async function saveProfile() {
  const body = {
    name: document.getElementById('p-name').value,
    age: document.getElementById('p-age').value,
    gender: document.getElementById('p-gender').value,
    country: document.getElementById('p-country').value,
    location: document.getElementById('p-location').value,
    bio: document.getElementById('p-bio').value,
  };
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify(body) });
    state.user = data.user;
    document.getElementById('me-name').textContent = state.user.name;
    refreshProfileViewMode();
    updateProfileCompletionDisplay();
    const note = document.getElementById('save-note');
    note.style.display = 'inline';
    setTimeout(() => { note.style.display = 'none'; exitProfileEditMode(); }, 700);
  } catch (err) {
    alert(err.message);
  }
}

function getSwingSettings() {
  try {
    return {
      theme: localStorage.getItem('swing_theme') || 'system',
      reducedMotion: localStorage.getItem('swing_reduced_motion') === '1'
    };
  } catch (e) {
    return { theme: 'system', reducedMotion: false };
  }
}

function applySwingTheme(theme) {
  const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.body.classList.toggle('settings-dark', !!isDark);
  document.documentElement.dataset.swingTheme = theme;
  document.querySelectorAll('[data-theme-choice]').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-theme-choice') === theme);
  });
}

function applyReducedMotion(enabled) {
  document.body.classList.toggle('settings-reduced-motion', enabled);
  const styleId = 'swing-reduced-motion-style';
  let style = document.getElementById(styleId);
  if (enabled && !style) {
    style = document.createElement('style');
    style.id = styleId;
    style.textContent = '* { scroll-behavior: auto !important; } *, *::before, *::after { animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; transition-duration: 0.001ms !important; }';
    document.head.appendChild(style);
  } else if (!enabled && style) {
    style.remove();
  }
  const toggle = document.getElementById('settings-motion-toggle');
  if (toggle) toggle.classList.toggle('active', enabled);
}

function syncSettingsUI() {
  const settings = getSwingSettings();
  applySwingTheme(settings.theme);
  applyReducedMotion(settings.reducedMotion);
  const email = document.getElementById('settings-email');
  if (email) email.textContent = (state.user && state.user.email) ? state.user.email : 'Not set';
  const phone = document.getElementById('settings-phone');
  if (phone) phone.textContent = (state.user && state.user.phone) ? state.user.phone : 'Not set';
  const discoverableToggle = document.getElementById('settings-discoverable-toggle');
  const locationToggle = document.getElementById('settings-location-toggle');
  if (discoverableToggle) discoverableToggle.classList.toggle('active', state.user?.discoverable !== false);
  if (locationToggle) locationToggle.classList.toggle('active', state.user?.showLocation !== false);
}

function openProfileSettings() {
  const panel = document.getElementById('settings-panel');
  const overlay = document.getElementById('settings-overlay');
  if (!panel || !overlay) return;
  syncSettingsUI();
  panel.classList.add('open');
  overlay.classList.add('open');
  panel.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
}

function closeProfileSettings() {
  const panel = document.getElementById('settings-panel');
  const overlay = document.getElementById('settings-overlay');
  if (!panel || !overlay) return;
  panel.classList.remove('open');
  overlay.classList.remove('open');
  panel.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}

async function togglePrivacySetting(field) {
  if (!state.user) return;
  const next = field === 'discoverable' ? state.user.discoverable === false : state.user.showLocation === false;
  try {
    const body = field === 'discoverable' ? { discoverable: next } : { showLocation: next };
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify(body) });
    state.user = data.user;
    syncSettingsUI();
    if (field === 'discoverable') await loadDiscover();
  } catch (err) {
    alert(err.message);
  }
}

function setSwingTheme(theme) {
  if (!['system', 'light', 'dark'].includes(theme)) return;
  try { localStorage.setItem('swing_theme', theme); } catch (e) { /* ignore */ }
  applySwingTheme(theme);
}

const swingSystemThemeMedia = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
if (swingSystemThemeMedia) {
  const syncSystemTheme = () => {
    const theme = getSwingSettings().theme;
    if (theme === 'system') applySwingTheme('system');
  };
  if (swingSystemThemeMedia.addEventListener) swingSystemThemeMedia.addEventListener('change', syncSystemTheme);
  else if (swingSystemThemeMedia.addListener) swingSystemThemeMedia.addListener(syncSystemTheme);
}

function toggleReducedMotion() {
  const next = !getSwingSettings().reducedMotion;
  try { localStorage.setItem('swing_reduced_motion', next ? '1' : '0'); } catch (e) { /* ignore */ }
  applyReducedMotion(next);
}

function resetFiltersFromSettings() {
  if (!confirm('Reset all Discover filters to their defaults?')) return;
  state.filters = defaultFilters();
  try { localStorage.setItem('swing_filters', JSON.stringify(state.filters)); } catch (e) { /* ignore */ }
  if (typeof syncFilterControls === 'function') syncFilterControls();
  updateFilterBadge();
  recomputeAndRenderCandidates();
  closeProfileSettings();
}

function logoutFromSettings() {
  closeProfileSettings();
  logout();
}

