// My Vibes gallery
// NOTE: classic script (not an ES module) — shares globals with the other files in /js,
// so keep the load order from index.html.
// ---------- My Vibes gallery ----------
let vibesPendingIndex = null;   // slot index being replaced, or null = adding a new photo
let vibesUploadingIndex = null; // slot index currently mid-upload (drives the spinner)

function triggerVibesUpload(replaceIndex) {
  vibesPendingIndex = (typeof replaceIndex === 'number') ? replaceIndex : null;
  const input = document.getElementById('vibes-photo-input');
  input.value = '';
  input.click();
}

async function handleVibesPhotoSelect(event) {
  const file = event.target.files[0];
  if (!file) return;
  const statusEl = document.getElementById('vibes-status');
  statusEl.textContent = '';

  if (file.size > 8 * 1024 * 1024) {
    statusEl.textContent = 'Image too large (max 8MB).';
    return;
  }

  const gallery = state.user.galleryUrls || [];
  const isReplace = vibesPendingIndex !== null;
  if (!isReplace && gallery.length >= 3) {
    statusEl.textContent = 'You can upload up to 3 photos.';
    return;
  }

  const targetIndex = isReplace ? vibesPendingIndex : gallery.length;
  vibesUploadingIndex = targetIndex;
  renderVibesGalleryEdit(state.user);
  statusEl.textContent = 'Uploading...';

  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const dataUrl = reader.result;
      const data = isReplace
        ? await api('/api/profile/gallery/' + targetIndex, { method: 'PUT', body: JSON.stringify({ photo: dataUrl }) })
        : await api('/api/profile/gallery', { method: 'POST', body: JSON.stringify({ photo: dataUrl }) });
      state.user = data.user;
      statusEl.textContent = '';
      renderVibesGalleryView(state.user);
    } catch (err) {
      statusEl.textContent = err.message || 'Upload failed. Please try again.';
    } finally {
      vibesUploadingIndex = null;
      vibesPendingIndex = null;
      renderVibesGalleryEdit(state.user);
    }
  };
  reader.onerror = () => {
    statusEl.textContent = 'Could not read that file. Please try again.';
    vibesUploadingIndex = null;
    vibesPendingIndex = null;
    renderVibesGalleryEdit(state.user);
  };
  reader.readAsDataURL(file);
}

async function deleteVibesPhoto(index) {
  if (!confirm('Remove this photo from My Vibes?')) return;
  const statusEl = document.getElementById('vibes-status');
  try {
    const data = await api('/api/profile/gallery/' + index, { method: 'DELETE' });
    state.user = data.user;
    statusEl.textContent = '';
    renderVibesGalleryEdit(state.user);
    renderVibesGalleryView(state.user);
  } catch (err) {
    statusEl.textContent = err.message || 'Could not delete photo.';
  }
}

async function moveVibesPhoto(index, direction) {
  const gallery = state.user.galleryUrls || [];
  const to = index + direction;
  if (to < 0 || to >= gallery.length) return;
  const statusEl = document.getElementById('vibes-status');
  try {
    const data = await api('/api/profile/gallery/reorder', { method: 'POST', body: JSON.stringify({ from: index, to }) });
    state.user = data.user;
    statusEl.textContent = '';
    renderVibesGalleryEdit(state.user);
    renderVibesGalleryView(state.user);
  } catch (err) {
    statusEl.textContent = err.message || 'Could not reorder photos.';
  }
}

// Edit-mode gallery: filled slots + empty "Add Photo" slots, with
// replace / delete / reorder controls. Lives inside the Edit Profile screen.
function renderVibesGalleryEdit(u) {
  const grid = document.getElementById('vibes-grid');
  const counter = document.getElementById('vibes-counter');
  if (!grid) return;
  const gallery = (u && u.galleryUrls) || [];
  counter.textContent = gallery.length + '/3 photos';

  let html = '';
  for (let i = 0; i < 3; i++) {
    const url = gallery[i];
    const loading = vibesUploadingIndex === i;
    if (url) {
      html += `
        <div class="vibes-slot">
          <img src="${escapeHtml(url)}" alt="My Vibes photo ${i + 1}" loading="lazy" onload="this.classList.add('loaded')" />
          <div class="vibes-slot-actions">
            ${i > 0 ? `<button type="button" onclick="moveVibesPhoto(${i}, -1)" aria-label="Move left" title="Move left"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M15 5l-7 7 7 7"/></svg></button>` : ''}
            ${i < gallery.length - 1 ? `<button type="button" onclick="moveVibesPhoto(${i}, 1)" aria-label="Move right" title="Move right"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M9 5l7 7-7 7"/></svg></button>` : ''}
            <button type="button" onclick="triggerVibesUpload(${i})" aria-label="Replace photo" title="Replace">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 4v5h5M20 20v-5h-5"/><path d="M5.5 15A7 7 0 0 0 19 12M18.5 9A7 7 0 0 0 5 12"/></svg>
            </button>
            <button type="button" onclick="deleteVibesPhoto(${i})" aria-label="Delete photo" title="Delete">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>
            </button>
          </div>
          ${loading ? '<div class="vibes-slot-loading"><div class="vibes-spinner"></div></div>' : ''}
        </div>`;
    } else if (loading) {
      html += '<div class="vibes-slot vibes-slot-empty"><div class="vibes-spinner"></div></div>';
    } else {
      html += `
        <button type="button" class="vibes-slot vibes-slot-empty" onclick="triggerVibesUpload(null)">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 5v14M5 12h14"/></svg>
          <span style="font-size:11.5px;font-weight:600;">Add Photo</span>
        </button>`;
    }
  }
  grid.innerHTML = html;
}

// View-mode gallery: read-only, shows only the photos that exist — no
// add/replace/delete controls, since photo management now lives in Edit
// Profile. Keeps the main profile page looking like a finished profile.
function renderVibesGalleryView(u) {
  const grid = document.getElementById('ph-vibes-grid');
  const counter = document.getElementById('ph-vibes-counter');
  if (!grid) return;
  const gallery = (u && u.galleryUrls) || [];
  counter.textContent = gallery.length + '/3 photos';
  if (!gallery.length) {
    grid.innerHTML = '<p class="quick-info-card-text empty">No photos yet — add some from Edit Profile.</p>';
    return;
  }
  grid.innerHTML = gallery.map((url, i) => `
    <div class="vibes-slot vibes-slot-view" onclick="openPhotoLightbox(${escapeHtml(JSON.stringify(gallery))}, ${i})">
      <img src="${escapeHtml(url)}" alt="My Vibes photo ${i + 1}" loading="lazy" onload="this.classList.add('loaded')" />
    </div>
  `).join('');
}

