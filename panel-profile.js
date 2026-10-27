// HTML: Profile panel (view + edit mode)
module.exports = `        <div class="view-panel" id="panel-profile">

          <!-- ===== View mode ===== -->
          <div class="profile-view" id="profile-view-mode">
            <div class="profile-header-card">
              <div class="profile-photo-wrap">
                <div class="match-avatar" id="ph-photo-preview"></div>
                <button type="button" class="profile-photo-camera-btn" onclick="document.getElementById('p-photo-input').click()" aria-label="Change photo" title="Change photo">
                  <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 8h3l1.5-2h7L17 8h3a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1Z"/><circle cx="12" cy="13" r="3.4"/></svg>
                </button>
                <input type="file" id="p-photo-input" accept="image/png,image/jpeg,image/webp,image/gif" style="display:none;" onchange="handlePhotoSelect(event)" />
              </div>
              <div id="photo-upload-status" style="font-size:11.5px;color:var(--muted);margin-top:2px;"></div>

              <div class="profile-name-row">
                <h2 id="ph-name">—</h2>
                <span class="profile-verified-badge" id="ph-verified-badge" style="display:none;" title="Verified">
                  <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M4 12l5 5L20 6"/></svg>
                </span>
              </div>
              <div class="profile-meta-line" id="ph-meta">&nbsp;</div>
              <p class="profile-tagline" id="ph-tagline"></p>

              <div class="profile-strength-block" id="ph-strength-block">
                <div class="profile-strength-row">
                  <span class="profile-strength-label">Profile Strength</span>
                  <span class="profile-strength-pct" id="ph-strength-pct">0%</span>
                </div>
                <div class="profile-strength-track"><div class="profile-strength-fill" id="ph-strength-fill" style="width:0%;"></div></div>
                <div class="profile-strength-hint" id="ph-strength-hint"></div>
              </div>

              <button type="button" class="profile-edit-btn" onclick="enterProfileEditMode()">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>
                Edit Profile
              </button>
            </div>

            <div class="about-card">
              <div class="about-card-header" style="justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:9px;">
                  <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="8" r="3.4"/><path d="M4.8 20a7.2 7.2 0 0 1 14.4 0"/></svg></span>
                  <h3>About Me</h3>
                </div>
                <button type="button" class="about-card-edit-link" onclick="showDetailsScreen('profile')">Edit</button>
              </div>
              <p class="about-card-text" id="ph-bio-text">—</p>
              <div class="about-pills-grid" id="ph-about-pills"></div>
            </div>

            <div class="about-card">
              <div class="about-card-header" style="justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:9px;">
                  <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></span>
                  <h3>Interests</h3>
                </div>
                <button type="button" class="about-card-edit-link" onclick="openInterestsPanel()">Edit</button>
              </div>
              <div class="interests-chips" id="ph-interests-chips"></div>
            </div>

            <div class="about-card">
              <div class="about-card-header" style="justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:9px;">
                  <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg></span>
                  <h3>I'm looking for</h3>
                </div>
                <button type="button" class="about-card-edit-link" onclick="showLookingForScreen()">Edit</button>
              </div>
              <div class="about-pills-grid" id="ph-lookingfor-pills"></div>
            </div>

            <div class="about-card">
              <div class="about-card-header" style="justify-content:space-between;">
                <div style="display:flex;align-items:center;gap:9px;">
                  <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="3" y="4" width="18" height="15" rx="2.5"/><circle cx="8.5" cy="9.5" r="1.6"/><path d="M21 15.5 15.5 11 6 19"/></svg></span>
                  <h3>My Vibes</h3>
                </div>
                <span class="vibes-counter" id="ph-vibes-counter">0/3 photos</span>
              </div>
              <div class="vibes-grid vibes-grid-view" id="ph-vibes-grid"></div>
            </div>

            <div class="about-card">
              <div class="about-card-header">
                <span class="icon-circle"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></span>
                <h3>Prompts</h3>
              </div>
              <div id="ph-prompts-list"></div>
            </div>

            <div class="about-card">
              <button type="button" onclick="showQuestionnaire('profile')" style="background:var(--cream);color:var(--ink);border:1px solid var(--border);width:100%;padding:11px;border-radius:10px;font-weight:600;font-size:13.5px;"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> Compatibility Quiz</button>
            </div>
          </div>

          <!-- ===== Edit mode ===== -->
          <div class="profile-form" id="profile-edit-mode" style="display:none;">
            <div class="profile-edit-header">
              <button type="button" class="profile-edit-back-btn" onclick="exitProfileEditMode()" aria-label="Back" title="Back">
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M15 5l-7 7 7 7"/></svg>
              </button>
              <h3>Edit Profile</h3>
            </div>
            <label>Name</label><input id="p-name" />
            <label>Age</label><input id="p-age" type="number" min="18" />
            <label>Gender</label>
            <select id="p-gender">
              <option value="man">Man</option>
              <option value="woman">Woman</option>
              <option value="non-binary">Non-binary</option>
              <option value="genderqueer">Genderqueer</option>
              <option value="genderfluid">Genderfluid</option>
              <option value="agender">Agender</option>
              <option value="other">Other</option>
              <option value="prefer_not_to_say">Prefer not to say</option>
            </select>
            <label>Country</label><input id="p-country" />
            <label>Location</label><input id="p-location" />
            <label>Bio</label><textarea id="p-bio"></textarea>
            <div class="field-hint" style="margin:-8px 0 14px 2px;">Interests are edited from the Interests card on your profile — tap "Edit" there.</div>

            <div class="edit-vibes-section">
              <div class="about-card-header" style="justify-content:space-between;margin-bottom:10px;">
                <span style="font-size:12.5px;font-weight:600;color:var(--muted);">My Vibes</span>
                <span class="vibes-counter" id="vibes-counter">0/3 photos</span>
              </div>
              <div class="vibes-grid" id="vibes-grid"></div>
              <div class="vibes-status" id="vibes-status"></div>
              <input type="file" id="vibes-photo-input" accept="image/png,image/jpeg,image/webp,image/gif" style="display:none;" onchange="handleVibesPhotoSelect(event)" />
            </div>

            <div class="edit-prompts-section">
              <div class="about-card-header" style="justify-content:space-between;margin-bottom:10px;">
                <span style="font-size:12.5px;font-weight:600;color:var(--muted);">Prompts</span>
                <span class="vibes-counter" id="prompts-counter">0/3 answered</span>
              </div>
              <div id="prompts-edit-rows"></div>
              <button type="button" onclick="savePrompts()" style="background:var(--cream);color:var(--ink);border:1px solid var(--border);width:100%;padding:10px;border-radius:10px;font-weight:600;font-size:13px;margin-top:4px;">Save prompts</button>
              <div class="vibes-status" id="prompts-status"></div>
            </div>

            <button onclick="saveProfile()">Save changes</button>
            <span class="save-note" id="save-note" style="display:none;">Saved!</span>
          </div>
        </div>

      </div>


      <div class="side-col">
        <div class="side-card">
          <div class="side-head"><h3>Matches</h3><button type="button" class="text-link" onclick="switchView('matches')">See all</button></div>
          <div class="match-avatars" id="matches-list"></div>
        </div>
        <div class="side-card">
          <div class="side-head"><h3>Messages</h3><button type="button" class="text-link" onclick="switchView('matches')">See all</button></div>
          <div id="messages-list"></div>
        </div>
        <div class="promo-card">
          <h4>Get more with Swing Premium</h4>
          <p>Unlimited likes, see who likes you, boost profile & more!</p>
          <button type="button" onclick="alert('Swing Premium is launching soon — thanks for your interest!')"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M3 8.5 7 11l5-7 5 7 4-2.5-1.6 10.5H4.6L3 8.5Z"/></svg> Upgrade Now</button>
        </div>
      </div>
    </div>

    <div class="app-footer">
      <div>© 2026 Swing</div>
      <div class="links"><a href="#">About</a><a href="#">Safety</a><a href="#">Help</a><a href="#">Privacy</a><a href="#">Terms</a></div>
    </div>
`;
