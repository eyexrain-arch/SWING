// Settings: change password, delete account, blocked users, orientation / interested-in
// NOTE: classic script (not an ES module) — shares globals with the other files in /js,
// so keep the load order from index.html.
// ---------- Change password ----------
function openChangePassword() {
  document.getElementById('cp-current-password').value = '';
  document.getElementById('cp-new-password').value = '';
  document.getElementById('change-password-error').style.display = 'none';
  document.getElementById('change-password-overlay').classList.add('open');
  document.getElementById('change-password-panel').classList.add('open');
}

function closeChangePassword() {
  document.getElementById('change-password-overlay').classList.remove('open');
  document.getElementById('change-password-panel').classList.remove('open');
}

async function submitChangePassword() {
  const currentPassword = document.getElementById('cp-current-password').value;
  const newPassword = document.getElementById('cp-new-password').value;
  const errEl = document.getElementById('change-password-error');
  errEl.style.display = 'none';
  if (!currentPassword || !newPassword) {
    errEl.textContent = 'Enter your current and new password.';
    errEl.style.display = 'block';
    return;
  }
  const btn = document.getElementById('change-password-btn');
  btn.disabled = true;
  try {
    await api('/api/change-password', { method: 'POST', body: JSON.stringify({ currentPassword, newPassword }) });
    closeChangePassword();
    closeProfileSettings();
    alert('Password updated.');
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

// ---------- Delete account ----------
function openDeleteAccount() {
  document.getElementById('da-password').value = '';
  document.getElementById('delete-account-error').style.display = 'none';
  document.getElementById('delete-account-overlay').classList.add('open');
  document.getElementById('delete-account-panel').classList.add('open');
}

function closeDeleteAccount() {
  document.getElementById('delete-account-overlay').classList.remove('open');
  document.getElementById('delete-account-panel').classList.remove('open');
}

async function submitDeleteAccount() {
  const password = document.getElementById('da-password').value;
  const errEl = document.getElementById('delete-account-error');
  errEl.style.display = 'none';
  if (!password) {
    errEl.textContent = 'Enter your password to confirm.';
    errEl.style.display = 'block';
    return;
  }
  if (!confirm('This permanently deletes your account, matches, and messages. This cannot be undone. Continue?')) {
    return;
  }
  const btn = document.getElementById('delete-account-btn');
  btn.disabled = true;
  try {
    await api('/api/account', { method: 'DELETE', body: JSON.stringify({ password }) });
    closeDeleteAccount();
    closeProfileSettings();
    sessionEpoch++; // invalidate any in-flight requests from this account
    if (state.eventSource) state.eventSource.close();
    state = createFreshState();
    document.getElementById('dashboard').classList.remove('visible');
    document.getElementById('auth-screen').style.display = 'flex';
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

// ---------- Blocked Users (Settings → Privacy) ----------
async function openBlockedUsersPanel() {
  document.getElementById('blocked-users-overlay').classList.add('open');
  document.getElementById('blocked-users-panel').classList.add('open');
  const body = document.getElementById('blocked-users-body');
  body.innerHTML = '<div class="field-hint">Loading…</div>';
  try {
    const data = await api('/api/blocked');
    renderBlockedUsersList(data.blocked || []);
  } catch (err) {
    body.innerHTML = `<div class="field-hint">Couldn't load your blocked users. ${escapeHtml(err.message)}</div>`;
  }
}

function renderBlockedUsersList(blocked) {
  const body = document.getElementById('blocked-users-body');
  if (!blocked.length) {
    body.innerHTML = '<div class="field-hint">You haven\'t blocked anyone.</div>';
    return;
  }
  body.innerHTML = blocked.map(u => `
    <div class="blocked-user-row" data-id="${u.id}">
      ${u.photoUrl
        ? `<div class="avatar" style="background-image:url('${escapeHtml(u.photoUrl)}')"></div>`
        : `<div class="avatar" style="background:${colorFor(u.name)};display:flex;align-items:center;justify-content:center;color:white;font-weight:700;">${escapeHtml(initials(u.name))}</div>`}
      <span class="name">${escapeHtml(u.name)}${u.age ? ', ' + u.age : ''}</span>
      <button type="button" onclick="unblockUserFromPanel('${u.id}')">Unblock</button>
    </div>`).join('');
}

async function unblockUserFromPanel(id) {
  try {
    await api('/api/unblock', { method: 'POST', body: JSON.stringify({ targetUserId: id }) });
    const row = document.querySelector(`.blocked-user-row[data-id="${id}"]`);
    if (row) row.remove();
    if (!document.querySelector('.blocked-user-row')) {
      document.getElementById('blocked-users-body').innerHTML = '<div class="field-hint">You haven\'t blocked anyone.</div>';
    }
    // The unblocked person may now be eligible to show back up in Discover.
    loadDiscover();
  } catch (err) {
    alert(err.message);
  }
}

function closeBlockedUsersPanel() {
  document.getElementById('blocked-users-overlay').classList.remove('open');
  document.getElementById('blocked-users-panel').classList.remove('open');
}

// ---------- Sexual Orientation & Interested In (Settings → Dating Preferences) ----------
// Both are private matching inputs — see VALID_ORIENTATIONS/VALID_INTERESTED_IN
// server-side and toOwnUser/toPublicUser: neither field is ever shown on a
// profile, only used to decide Discover eligibility.
const ORIENTATION_LABELS = {
  straight: 'Straight', gay: 'Gay', lesbian: 'Lesbian', bisexual: 'Bisexual',
  pansexual: 'Pansexual', asexual: 'Asexual', queer: 'Queer', questioning: 'Questioning',
  other: 'Other', prefer_not_to_say: 'Prefer not to say',
};
const INTERESTED_IN_LABELS = { men: 'Men', women: 'Women', nonbinary: 'Non-binary people' };

let orientationSelection = null;

function openOrientationPanel() {
  orientationSelection = state.user.orientation || null;
  renderOrientationOptions();
  document.getElementById('orientation-error').style.display = 'none';
  document.getElementById('orientation-overlay').classList.add('open');
  document.getElementById('orientation-panel').classList.add('open');
}

function renderOrientationOptions() {
  document.getElementById('orientation-options').innerHTML = Object.entries(ORIENTATION_LABELS).map(([value, label]) => `
    <button type="button" class="${orientationSelection === value ? 'selected' : ''}" onclick="selectOrientation('${value}')">${escapeHtml(label)}</button>`).join('');
}

function selectOrientation(value) {
  orientationSelection = value;
  renderOrientationOptions();
}

async function saveOrientation() {
  const btn = document.getElementById('orientation-save-btn');
  const errEl = document.getElementById('orientation-error');
  errEl.style.display = 'none';
  btn.disabled = true;
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify({ orientation: orientationSelection }) });
    state.user = data.user;
    closeOrientationPanel();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

function closeOrientationPanel() {
  document.getElementById('orientation-overlay').classList.remove('open');
  document.getElementById('orientation-panel').classList.remove('open');
}

let interestedInSelection = new Set();

function openInterestedInPanel() {
  interestedInSelection = new Set(state.user.interestedIn || []);
  renderInterestedInOptions();
  document.getElementById('interested-in-error').style.display = 'none';
  document.getElementById('interested-in-overlay').classList.add('open');
  document.getElementById('interested-in-panel').classList.add('open');
}

function renderInterestedInOptions() {
  const allSelected = Object.keys(INTERESTED_IN_LABELS).every(k => interestedInSelection.has(k));
  const rows = Object.entries(INTERESTED_IN_LABELS).map(([value, label]) => `
    <button type="button" class="${interestedInSelection.has(value) ? 'selected' : ''}" onclick="toggleInterestedIn('${value}')">${escapeHtml(label)}</button>`).join('');
  document.getElementById('interested-in-options').innerHTML = rows +
    `<button type="button" class="${allSelected ? 'selected' : ''}" onclick="selectEveryoneInterestedIn()">Everyone</button>`;
}

function toggleInterestedIn(value) {
  if (interestedInSelection.has(value)) interestedInSelection.delete(value);
  else interestedInSelection.add(value);
  renderInterestedInOptions();
}

function selectEveryoneInterestedIn() {
  Object.keys(INTERESTED_IN_LABELS).forEach(k => interestedInSelection.add(k));
  renderInterestedInOptions();
}

async function saveInterestedIn() {
  const btn = document.getElementById('interested-in-save-btn');
  const errEl = document.getElementById('interested-in-error');
  errEl.style.display = 'none';
  if (!interestedInSelection.size) {
    errEl.textContent = 'Pick at least one option.';
    errEl.style.display = 'block';
    return;
  }
  btn.disabled = true;
  try {
    const data = await api('/api/profile', { method: 'PUT', body: JSON.stringify({ interestedIn: [...interestedInSelection] }) });
    state.user = data.user;
    closeInterestedInPanel();
    loadDiscover();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

function closeInterestedInPanel() {
  document.getElementById('interested-in-overlay').classList.remove('open');
  document.getElementById('interested-in-panel').classList.remove('open');
}

