// Client JS: Candidate detail, block / report action sheets
module.exports = `// ---------- Block / Report action sheet ----------
function openProfileActionSheet() {
  if (!currentDetailCandidateId) return;
  const c = getCandidateById(currentDetailCandidateId);
  const name = c ? c.name : 'this profile';
  document.getElementById('action-sheet-body').innerHTML = \`
    <button type="button" class="action-sheet-row danger" onclick="confirmBlockCurrentCandidate()">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M5.5 5.5l13 13"/></svg>
      Block \${escapeHtml(name)}
    </button>
    <button type="button" class="action-sheet-row danger" onclick="openReportSheet()">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 2.7 17a2 2 0 0 0 1.7 3h15.2a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg>
      Report \${escapeHtml(name)}
    </button>
    <button type="button" class="action-sheet-row cancel" onclick="closeActionSheet()">Cancel</button>
  \`;
  document.getElementById('action-sheet-overlay').classList.add('open');
}

function closeActionSheet() {
  document.getElementById('action-sheet-overlay').classList.remove('open');
}

function removeCandidateEverywhere(id) {
  state.candidates = state.candidates.filter(x => x.id !== id);
  state.allCandidates = state.allCandidates.filter(x => x.id !== id);
  state.likedProfiles = state.likedProfiles.filter(x => x.id !== id);
  state.nearbyProfiles = state.nearbyProfiles.filter(x => x.id !== id);
  state.newProfiles = state.newProfiles.filter(x => x.id !== id);
}

async function confirmBlockCurrentCandidate() {
  const id = currentDetailCandidateId;
  if (!id) return;
  const c = getCandidateById(id);
  const name = c ? c.name : 'this person';
  closeActionSheet();
  if (!confirm(\`Block \${name}? You won't see each other in Discover anymore, and any match between you will be removed.\`)) return;
  try {
    await api('/api/block', { method: 'POST', body: JSON.stringify({ targetUserId: id }) });
    removeCandidateEverywhere(id);
    closeCandidateDetail();
    renderDiscoverList();
  } catch (err) {
    alert(err.message);
  }
}

const REPORT_REASONS = ['Inappropriate photos', 'Harassment or abuse', 'Fake profile', 'Spam or scam', 'Underage user', 'Something else'];

function openReportSheet() {
  const id = currentDetailCandidateId;
  const c = getCandidateById(id);
  const name = c ? c.name : 'this profile';
  document.getElementById('action-sheet-body').innerHTML = \`
    <div class="action-sheet-row" style="cursor:default;">Report \${escapeHtml(name)} — why?</div>
    <div class="report-reason-list">
      \${REPORT_REASONS.map(r => \`<button type="button" onclick="submitReportCurrentCandidate(\${escapeHtml(JSON.stringify(r))})">\${escapeHtml(r)}</button>\`).join('')}
    </div>
    <button type="button" class="action-sheet-row cancel" onclick="closeActionSheet()">Cancel</button>
  \`;
}

async function submitReportCurrentCandidate(reason) {
  const id = currentDetailCandidateId;
  if (!id) return;
  closeActionSheet();
  try {
    await api('/api/report', { method: 'POST', body: JSON.stringify({ reportedUserId: id, reason }) });
    alert('Thanks — your report has been submitted. Our team will review it.');
  } catch (err) {
    alert(err.message);
  }
}

`;
