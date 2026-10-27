// Client JS: Matches and chat
module.exports = `// ---------- Matches / Messages ----------

async function loadMatches() {
  const epoch = sessionEpoch;
  const data = await api('/api/matches');
  if (epoch !== sessionEpoch) return; // account changed while this request was in flight
  state.matches = data.matches;
  const unreadTotal = state.matches.reduce((sum, m) => sum + m.unread, 0);
  const navMatches = document.getElementById('nav-matches-count');
  if (unreadTotal > 0) { navMatches.textContent = unreadTotal; navMatches.style.display = 'inline-block'; }
  else { navMatches.style.display = 'none'; }
  const mnavMsg = document.getElementById('mnav-messages-count');
  if (unreadTotal > 0) { mnavMsg.textContent = unreadTotal; mnavMsg.style.display = 'flex'; }
  else { mnavMsg.style.display = 'none'; }
  renderMatchesSidebar();
  if (document.getElementById('panel-matches').classList.contains('visible')) renderMatchesFull();
}

function renderMatchesSidebar() {
  const avatarsEl = document.getElementById('matches-list');
  if (!state.matches.length) {
    avatarsEl.innerHTML = '<div class="muted-note">No matches yet — start swiping!</div>';
  } else {
    avatarsEl.innerHTML = state.matches.slice(0, 6).map(m => \`
      <div class="match-avatar-wrap" onclick="openChat('\${m.matchKey}')">
        <div class="match-avatar" style="\${avatarStyleAttr(m.user)}">\${avatarInitials(m.user)}<span class="heart-badge"><svg viewBox="0 0 24 24" width="9" height="9" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></span></div>
        <div class="mname">\${escapeHtml(m.user.name)}</div>
      </div>
    \`).join('');
  }

  const msgsEl = document.getElementById('messages-list');
  const withMsgs = state.matches.filter(m => m.lastMessage);
  if (!withMsgs.length) {
    msgsEl.innerHTML = '<div class="muted-note">No messages yet.</div>';
  } else {
    msgsEl.innerHTML = withMsgs.slice(0, 5).map(m => \`
      <div class="msg-item" onclick="openChat('\${m.matchKey}')">
        <div class="msg-avatar" style="\${avatarStyleAttr(m.user)}">\${avatarInitials(m.user)}</div>
        <div class="msg-body">
          <div class="msg-top"><span class="mname">\${escapeHtml(m.user.name)}</span><span class="time">\${timeAgo(m.lastMessage.createdAt)}</span></div>
          <div class="msg-preview"><span class="text">\${escapeHtml(m.lastMessage.text)}</span>\${m.unread ? '<span class="unread-dot">' + m.unread + '</span>' : ''}</div>
        </div>
      </div>
    \`).join('');
  }
}

function renderMatchesFull() {
  const el = document.getElementById('matches-full-list');
  if (!state.matches.length) {
    el.innerHTML = '<div class="empty-state">No matches yet. Head to Discover and start swiping!</div>';
    return;
  }
  el.innerHTML = state.matches.map(m => \`
    <div class="msg-item" style="background:white;border-radius:14px;padding:12px 14px;margin-bottom:10px;border:none;" onclick="openChat('\${m.matchKey}')">
      <div class="msg-avatar" style="\${avatarStyleAttr(m.user)}width:46px;height:46px;font-size:15px;">\${avatarInitials(m.user)}</div>
      <div class="msg-body">
        <div class="msg-top"><span class="mname">\${escapeHtml(m.user.name)}</span><span class="time">\${m.lastMessage ? timeAgo(m.lastMessage.createdAt) : 'Matched ' + timeAgo(m.createdAt)}</span></div>
        <div class="msg-preview"><span class="text">\${m.lastMessage ? escapeHtml(m.lastMessage.text) : 'Say hello'}</span>\${m.unread ? '<span class="unread-dot">' + m.unread + '</span>' : ''}</div>
      </div>
    </div>
  \`).join('');
}

async function openChat(matchKey) {
  state.activeChat = matchKey;
  document.body.classList.add('chat-open');
  const match = state.matches.find(m => m.matchKey === matchKey);
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('visible'));
  document.getElementById('panel-chat').classList.add('visible');
  document.getElementById('view-title').textContent = match ? match.user.name : 'Chat';
  document.getElementById('chat-name').textContent = match ? match.user.name : '';
  const av = document.getElementById('chat-avatar');
  av.textContent = match ? avatarInitials(match.user) : '?';
  av.setAttribute('style', 'width:36px;height:36px;font-size:12px;' + (match ? avatarStyleAttr(match.user) : 'background:#ccc;'));

  const compatEl = document.getElementById('chat-compat-panel');
  if (match && match.compatibility !== null && match.compatibility !== undefined) {
    compatEl.innerHTML = \`
      <div class="compat-panel">
        <div class="compat-percent"><svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> \${match.compatibility}% Compatible</div>
        \${match.compatibilityReasons && match.compatibilityReasons.length ? '<ul>' + match.compatibilityReasons.map(r => '<li>' + escapeHtml(r) + '</li>').join('') + '</ul>' : ''}
      </div>
    \`;
  } else {
    compatEl.innerHTML = '';
  }

  await loadChatMessages(matchKey);
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState !== 'visible' || !state.user) return;
  if (state.activeChat) {
    loadChatMessages(state.activeChat);
  } else {
    loadMatches();
  }
  // Coming back from the background is also a good moment to make sure
  // the live connection didn't quietly die while we were away.
  if (state.eventSource && state.eventSource.readyState === EventSource.CLOSED) {
    connectLiveUpdates();
  }
});

async function loadChatMessages(matchKey) {
  const data = await api('/api/messages/' + matchKey);
  const el = document.getElementById('chat-messages');
  const wasNearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  if (!data.messages.length) {
    el.innerHTML = '<div class="muted-note" style="text-align:center;margin-top:20px;">You matched! Say hello</div>';
  } else {
    el.innerHTML = data.messages.map(m => \`
      <div class="bubble \${m.fromUserId === state.user.id ? 'mine' : 'theirs'}">\${escapeHtml(m.text)}</div>
    \`).join('');
  }
  if (wasNearBottom) el.scrollTop = el.scrollHeight;
  await loadMatches();
}

async function sendMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text || !state.activeChat) return;
  input.value = '';
  try {
    await api('/api/messages/' + state.activeChat, { method: 'POST', body: JSON.stringify({ text }) });
    await loadChatMessages(state.activeChat);
  } catch (err) {
    alert(err.message);
  }
}
document.getElementById('chat-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendMessage();
});

// Keep the input + send button visible above the on-screen keyboard.
// Relying on 100dvh alone isn't reliable across all mobile browsers, so
// on focus (and whenever the visual viewport resizes, i.e. the keyboard
// opens/closes) we explicitly scroll the row into view.
function keepInputVisible(inputEl) {
  const scrollIntoView = () => {
    setTimeout(() => {
      inputEl.scrollIntoView({ block: 'end', behavior: 'smooth' });
    }, 100);
  };
  inputEl.addEventListener('focus', scrollIntoView);
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', () => {
      if (document.activeElement === inputEl) scrollIntoView();
    });
  }
}
keepInputVisible(document.getElementById('chat-input'));

`;
