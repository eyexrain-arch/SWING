// Photo lightbox (full-size vibes photos)
// NOTE: classic script (not an ES module) — shares globals with the other files in /js,
// so keep the load order from index.html.
// ---------- Photo lightbox (full-size vibes photos) ----------
let lightboxState = { urls: [], index: 0 };

function openPhotoLightbox(urls, index) {
  if (!Array.isArray(urls) || !urls.length) return;
  lightboxState = { urls, index: Math.min(Math.max(index, 0), urls.length - 1) };
  renderPhotoLightbox();
  document.getElementById('photo-lightbox').classList.add('visible');
  document.addEventListener('keydown', handlePhotoLightboxKeydown);
}

function closePhotoLightbox() {
  document.getElementById('photo-lightbox').classList.remove('visible');
  document.removeEventListener('keydown', handlePhotoLightboxKeydown);
}

function navPhotoLightbox(delta) {
  const max = lightboxState.urls.length - 1;
  const next = lightboxState.index + delta;
  if (next < 0 || next > max) return;
  lightboxState.index = next;
  renderPhotoLightbox();
}

function renderPhotoLightbox() {
  const { urls, index } = lightboxState;
  document.getElementById('photo-lightbox-img').src = urls[index];
  document.getElementById('photo-lightbox-prev').disabled = index <= 0;
  document.getElementById('photo-lightbox-next').disabled = index >= urls.length - 1;
  const counter = document.getElementById('photo-lightbox-counter');
  counter.style.display = urls.length > 1 ? '' : 'none';
  counter.textContent = (index + 1) + ' / ' + urls.length;
}

function handlePhotoLightboxKeydown(e) {
  if (e.key === 'Escape') closePhotoLightbox();
  else if (e.key === 'ArrowLeft') navPhotoLightbox(-1);
  else if (e.key === 'ArrowRight') navPhotoLightbox(1);
}

async function discoverListAction(id, direction) {
  const idx = state.candidates.findIndex(x => x.id === id);
  if (idx === -1) return;
  const c = state.candidates[idx];
  try {
    const data = await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: c.id, direction }) });
    state.candidates.splice(idx, 1);
    state.allCandidates = state.allCandidates.filter(x => x.id !== c.id);
    renderDiscoverList();
    if (data.matched) {
      await loadMatches();
      alert("It's a match with " + c.name + "!");
    }
  } catch (err) {
    alert(err.message);
  }
}


