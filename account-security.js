// Client JS: Change password and delete account
module.exports = `// ---------- Change password ----------
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

`;
