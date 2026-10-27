// HTML: Settings panel and its sub-panels (password, delete, blocked, orientation)
module.exports = `  <div class="filter-overlay" id="filter-overlay" onclick="closeFilterPanel()"></div>
  <div class="settings-overlay" id="settings-overlay" onclick="closeProfileSettings()"></div>
  <aside class="settings-panel" id="settings-panel" role="dialog" aria-modal="true" aria-labelledby="settings-panel-title" aria-hidden="true">
    <div class="settings-header">
      <h2 id="settings-panel-title">Settings</h2>
      <button class="settings-close" onclick="closeProfileSettings()" aria-label="Close settings">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="settings-body">
      <div class="settings-section">
        <p class="settings-section-title">ACCOUNT</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="closeProfileSettings(); enterProfileEditMode();">
            <span class="settings-icon">✎</span><span class="settings-copy"><span class="settings-label">Edit profile</span><span class="settings-desc">Update your bio, interests, lifestyle and dating intentions.</span></span><span class="settings-chevron">›</span>
          </button>
          <div class="settings-row">
            <span class="settings-icon">@</span><span class="settings-copy"><span class="settings-label">Email</span><span class="settings-desc">Your sign-in email</span></span><span class="settings-value" id="settings-email">—</span>
          </div>
          <div class="settings-row">
            <span class="settings-icon">☎</span><span class="settings-copy"><span class="settings-label">Phone</span><span class="settings-desc">Your sign-in phone number</span></span><span class="settings-value" id="settings-phone">—</span>
          </div>
          <button class="settings-row clickable" type="button" onclick="openChangePassword()">
            <span class="settings-icon">🔒</span><span class="settings-copy"><span class="settings-label">Change password</span><span class="settings-desc">Update the password you sign in with.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">DISCOVERY</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="closeProfileSettings(); openFilterPanel();">
            <span class="settings-icon">⌘</span><span class="settings-copy"><span class="settings-label">Discovery filters</span><span class="settings-desc">Control who appears in Discover and Explore.</span></span><span class="settings-chevron">›</span>
          </button>
          <button class="settings-row clickable" type="button" onclick="resetFiltersFromSettings()">
            <span class="settings-icon">↺</span><span class="settings-copy"><span class="settings-label">Reset filters</span><span class="settings-desc">Return Discover preferences to their defaults.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">DATING PREFERENCES</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="openOrientationPanel()">
            <span class="settings-icon">◐</span><span class="settings-copy"><span class="settings-label">Sexual Orientation</span><span class="settings-desc">Private — used for matching only, never shown on your profile.</span></span><span class="settings-chevron">›</span>
          </button>
          <button class="settings-row clickable" type="button" onclick="openInterestedInPanel()">
            <span class="settings-icon">⚭</span><span class="settings-copy"><span class="settings-label">Interested In</span><span class="settings-desc">Private — controls who's eligible to see you and who you see in Discover.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">PRIVACY</p>
        <div class="settings-card">
          <button class="settings-row clickable" type="button" onclick="togglePrivacySetting('discoverable')">
            <span class="settings-icon">◎</span><span class="settings-copy"><span class="settings-label">Show me in Discover</span><span class="settings-desc">Turn your profile on or off in other people's Discover feed.</span></span><span class="settings-toggle" id="settings-discoverable-toggle" aria-hidden="true"></span>
          </button>
          <button class="settings-row clickable" type="button" onclick="togglePrivacySetting('showLocation')">
            <span class="settings-icon">⌖</span><span class="settings-copy"><span class="settings-label">Show my location</span><span class="settings-desc">Allow your saved city/location to appear on your profile.</span></span><span class="settings-toggle" id="settings-location-toggle" aria-hidden="true"></span>
          </button>
          <button class="settings-row clickable" type="button" onclick="openBlockedUsersPanel()">
            <span class="settings-icon">🚫</span><span class="settings-copy"><span class="settings-label">Blocked Users</span><span class="settings-desc">See and manage people you've blocked.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">APPEARANCE</p>
        <div class="settings-card">
          <div class="settings-row">
            <span class="settings-icon">◐</span><span class="settings-copy"><span class="settings-label">Theme</span><span class="settings-desc">Choose how Swing looks on this device.</span></span>
          </div>
          <div class="settings-choice-row">
            <button type="button" class="settings-choice" data-theme-choice="system" onclick="setSwingTheme('system')">System</button>
            <button type="button" class="settings-choice" data-theme-choice="light" onclick="setSwingTheme('light')">Light</button>
            <button type="button" class="settings-choice" data-theme-choice="dark" onclick="setSwingTheme('dark')">Dark</button>
          </div>
          <button class="settings-row clickable" type="button" onclick="toggleReducedMotion()">
            <span class="settings-icon">≈</span><span class="settings-copy"><span class="settings-label">Reduce motion</span><span class="settings-desc">Minimize animations and transitions.</span></span><span class="settings-toggle" id="settings-motion-toggle" aria-hidden="true"></span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">SESSION</p>
        <div class="settings-card">
          <button class="settings-row clickable settings-danger" type="button" onclick="logoutFromSettings()">
            <span class="settings-icon">⇥</span><span class="settings-copy"><span class="settings-label">Log out</span><span class="settings-desc">Sign out of Swing on this device.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>

      <div class="settings-section">
        <p class="settings-section-title">DANGER ZONE</p>
        <div class="settings-card">
          <button class="settings-row clickable settings-danger" type="button" onclick="openDeleteAccount()">
            <span class="settings-icon">⚠</span><span class="settings-copy"><span class="settings-label">Delete account</span><span class="settings-desc">Permanently delete your account, matches, and messages. This can't be undone.</span></span><span class="settings-chevron">›</span>
          </button>
        </div>
      </div>
      <p class="settings-note">Settings marked for this device are stored locally in your browser. Account and profile data remain managed by your Swing account.</p>
    </div>
  </aside>

  <div class="filter-overlay" id="change-password-overlay" onclick="closeChangePassword()"></div>
  <div class="filter-panel" id="change-password-panel" role="dialog" aria-modal="true" aria-labelledby="change-password-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="change-password-title">Change password</h2>
      <button class="filter-panel-close" onclick="closeChangePassword()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div class="password-field-wrap">
        <input id="cp-current-password" type="password" placeholder="Current password" autocomplete="current-password" />
        <button type="button" class="password-toggle-btn" onclick="togglePasswordVisibility('cp-current-password', this)" aria-label="Show password" aria-pressed="false">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <div class="password-field-wrap">
        <input id="cp-new-password" type="password" placeholder="New password" autocomplete="new-password" />
        <button type="button" class="password-toggle-btn" onclick="togglePasswordVisibility('cp-new-password', this)" aria-label="Show password" aria-pressed="false">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <div class="field-hint">At least 6 characters, with letters and numbers.</div>
      <div id="change-password-error" class="auth-error" style="display:none;"></div>
    </div>
    <div class="filter-panel-footer">
      <button type="button" class="filter-apply-btn" id="change-password-btn" onclick="submitChangePassword()">Update password</button>
    </div>
  </div>

  <div class="filter-overlay" id="delete-account-overlay" onclick="closeDeleteAccount()"></div>
  <div class="filter-panel" id="delete-account-panel" role="dialog" aria-modal="true" aria-labelledby="delete-account-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="delete-account-title">Delete account</h2>
      <button class="filter-panel-close" onclick="closeDeleteAccount()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div class="field-hint" style="margin:0 0 14px 2px;">This permanently deletes your profile, photos, matches, and messages. This can't be undone. Enter your password to confirm.</div>
      <div class="password-field-wrap">
        <input id="da-password" type="password" placeholder="Password" autocomplete="current-password" />
        <button type="button" class="password-toggle-btn" onclick="togglePasswordVisibility('da-password', this)" aria-label="Show password" aria-pressed="false">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
      <div id="delete-account-error" class="auth-error" style="display:none;"></div>
    </div>
    <div class="filter-panel-footer">
      <button type="button" class="filter-apply-btn settings-danger-btn" id="delete-account-btn" onclick="submitDeleteAccount()">Permanently delete my account</button>
    </div>
  </div>

  <div class="filter-overlay" id="blocked-users-overlay" onclick="closeBlockedUsersPanel()"></div>
  <div class="filter-panel" id="blocked-users-panel" role="dialog" aria-modal="true" aria-labelledby="blocked-users-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="blocked-users-title">Blocked Users</h2>
      <button class="filter-panel-close" onclick="closeBlockedUsersPanel()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body" id="blocked-users-body">
      <div class="field-hint">Loading…</div>
    </div>
  </div>

  <div class="filter-overlay" id="orientation-overlay" onclick="closeOrientationPanel()"></div>
  <div class="filter-panel" id="orientation-panel" role="dialog" aria-modal="true" aria-labelledby="orientation-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="orientation-title">Sexual Orientation</h2>
      <button class="filter-panel-close" onclick="closeOrientationPanel()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div class="field-hint" style="margin-bottom:12px;">Private — this is used to help with matching and is never shown on your profile.</div>
      <div class="report-reason-list" id="orientation-options"></div>
      <div class="auth-error" id="orientation-error" style="display:none;"></div>
      <button type="button" class="filter-apply-btn" onclick="saveOrientation()" id="orientation-save-btn">Save</button>
    </div>
  </div>

  <div class="filter-overlay" id="interested-in-overlay" onclick="closeInterestedInPanel()"></div>
  <div class="filter-panel" id="interested-in-panel" role="dialog" aria-modal="true" aria-labelledby="interested-in-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="interested-in-title">Interested In</h2>
      <button class="filter-panel-close" onclick="closeInterestedInPanel()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div class="field-hint" style="margin-bottom:12px;">Private — controls who's eligible to see you and who you see in Discover. Pick as many as apply.</div>
      <div class="report-reason-list" id="interested-in-options"></div>
      <div class="auth-error" id="interested-in-error" style="display:none;"></div>
      <button type="button" class="filter-apply-btn" onclick="saveInterestedIn()" id="interested-in-save-btn">Save</button>
    </div>
  </div>

`;
