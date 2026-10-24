// Likes You
// NOTE: classic script (not an ES module) — shares globals with the other files in /js,
// so keep the load order from index.html.
// ---------- Likes You ----------

async function loadAdmirers() {
  const epoch = sessionEpoch;
  const data = await api('/api/likes-you');
  if (epoch !== sessionEpoch) return; // account changed while this request was in flight
  state.admirers = data.admirers;
  document.getElementById('nav-likes-count').textContent = state.admirers.length;
  const mnavLikes = document.getElementById('mnav-likes-count');
  if (state.admirers.length > 0) { mnavLikes.textContent = state.admirers.length; mnavLikes.style.display = 'flex'; }
  else { mnavLikes.style.display = 'none'; }
}

function renderAdmirers() {
  const el = document.getElementById('admirer-grid');
  if (!state.admirers.length) {
    el.innerHTML = '<div class="empty-state">No one has liked you yet. Keep your profile fresh!</div>';
    return;
  }
  el.innerHTML = state.admirers.map(a => `
    <div class="admirer-card">
      <div class="match-avatar" style="${avatarStyleAttr(a)}">${avatarInitials(a)}</div>
      <div class="aname">${escapeHtml(a.name)}${a.age ? ', ' + a.age : ''}</div>
      <button onclick="likeBack('${a.id}')" aria-label="Like this person back">Like back <svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></button>
    </div>
  `).join('');
}

async function likeBack(userId) {
  try {
    const data = await api('/api/like', { method: 'POST', body: JSON.stringify({ targetUserId: userId, direction: 'like' }) });
    await loadAdmirers();
    renderAdmirers();
    if (data.matched) {
      await loadMatches();
      alert("It's a match!");
    }
  } catch (err) {
    alert(err.message);
  }
}

