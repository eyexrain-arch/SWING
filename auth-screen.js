// HTML: Landing / login / sign up / forgot password
module.exports = `<div id="auth-screen">
  <svg class="landing-couples" viewBox="0 0 1000 1000" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <symbol id="couple-icon" viewBox="0 0 100 120">
        <path d="M16,118 C16,72 24,42 38,42 C52,42 60,72 60,118 Z" fill="currentColor" opacity="0.92"/>
        <circle cx="38" cy="26" r="16" fill="currentColor" opacity="0.92"/>
        <path d="M40,118 C40,70 48,38 62,38 C76,38 84,70 84,118 Z" fill="currentColor" opacity="0.72"/>
        <circle cx="62" cy="22" r="16" fill="currentColor" opacity="0.72"/>
      </symbol>
    </defs>
    <use href="#couple-icon" x="700" y="30" width="260" height="310" style="color:#f4b8ca" opacity="0.55"/>
    <use href="#couple-icon" x="30" y="640" width="190" height="230" style="color:#e8926b" opacity="0.5"/>
    <use href="#couple-icon" x="230" y="700" width="170" height="200" style="color:#7c3aed" opacity="0.45"/>
    <use href="#couple-icon" x="770" y="400" width="210" height="250" style="color:#e0b48a" opacity="0.5"/>
    <use href="#couple-icon" x="790" y="680" width="190" height="230" style="color:#8b5cf6" opacity="0.45"/>
    <use href="#couple-icon" x="450" y="740" width="180" height="210" style="color:#f0b79a" opacity="0.4"/>
  </svg>

  <svg class="landing-map" viewBox="0 0 800 300" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
    <g fill="none" stroke="rgba(255,255,255,0.5)" stroke-width="1" stroke-dasharray="1 4">
      <path d="M50,150 Q200,80 350,140 T650,120"/>
      <path d="M100,200 Q300,220 500,160 T750,180"/>
    </g>
    <g fill="#8b5cf6">
      <circle cx="50" cy="150" r="3"/>
      <circle cx="350" cy="140" r="3"/>
      <circle cx="650" cy="120" r="3"/>
      <circle cx="100" cy="200" r="3"/>
      <circle cx="500" cy="160" r="3"/>
      <circle cx="750" cy="180" r="3"/>
    </g>
  </svg>

  <div class="landing-body">
    <div class="landing-left">
      <div class="landing-brand"><span class="logo-font">Swing</span> <span class="brand-heart"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></span></div>
      <div class="landing-kicker">MEET • MATCH • CONNECT</div>
      <h1 class="landing-headline">Meet someone worth <span>staying for.</span></h1>
      <p class="landing-sub">Swing helps you find real connections with people who get you.</p>
      <div class="landing-features">
        <div class="landing-feature"><div class="ico"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></div><div class="label">Meaningful Matches</div></div>
        <div class="landing-feature"><div class="ico"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 3l7 3v5.5c0 4.6-3 7.8-7 9.5-4-1.7-7-4.9-7-9.5V6l7-3Z"/></svg></div><div class="label">Safe &amp; Private</div></div>
        <div class="landing-feature"><div class="ico"><svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></div><div class="label">Built for real connections</div></div>
      </div>
    </div>

    <div class="auth-card">
      <span class="logo-font">swing</span>
      <div class="auth-sub">Meet someone worth staying for.</div>
      <div class="auth-tabs">
        <button id="tab-login" class="active" onclick="setAuthMode('login')">Log in</button>
        <button id="tab-register" onclick="setAuthMode('register')">Sign up</button>
      </div>
      <div id="auth-error" class="auth-error" style="display:none;"></div>
      <form id="auth-form">
        <input id="f-name" name="name" placeholder="Name" style="display:none;" />
        <input id="f-age" name="age" type="number" placeholder="Age" min="18" style="display:none;" />
        <select id="f-gender" name="gender" style="display:none;">
          <option value="">I am a...</option>
          <option value="man">Man</option>
          <option value="woman">Woman</option>
          <option value="non-binary">Non-binary</option>
          <option value="genderqueer">Genderqueer</option>
          <option value="genderfluid">Genderfluid</option>
          <option value="agender">Agender</option>
          <option value="other">Other</option>
          <option value="prefer_not_to_say">Prefer not to say</option>
        </select>
        <input id="f-country" name="country" placeholder="Country (e.g. Philippines)" style="display:none;" />
        <input id="f-location" name="location" placeholder="Location (e.g. Manila, Philippines)" style="display:none;" />
        <textarea id="f-bio" name="bio" placeholder="Short bio" style="display:none;"></textarea>
        <div id="f-tags-picker" style="display:none;margin-bottom:12px;">
          <div class="filter-field-label" style="margin-bottom:6px;">Interests <span style="font-weight:400;color:var(--muted);">(up to 2 per category)</span></div>
          <div id="f-tags-chips"></div>
        </div>
        <input id="f-identity" name="identity" type="text" inputmode="email" autocomplete="username" placeholder="Email or phone number" required />
        <div class="password-field-wrap">
          <input id="f-password" name="password" type="password" placeholder="Password" autocomplete="current-password" required />
          <button type="button" class="password-toggle-btn" id="password-toggle-btn" onclick="togglePasswordVisibility()" aria-label="Show password" aria-pressed="false">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
        <div class="field-hint" id="password-hint" style="display:none;">At least 6 characters, with letters and numbers.</div>
        <div class="auth-forgot-link" id="auth-forgot-link"><button type="button" onclick="openForgotPassword()">Forgot password?</button></div>
        <button type="submit" class="auth-submit" id="auth-submit-btn">Log in</button>
      </form>
    </div>
  </div>

  <div class="filter-overlay" id="forgot-password-overlay" onclick="closeForgotPassword()"></div>
  <div class="filter-panel" id="forgot-password-panel" role="dialog" aria-modal="true" aria-labelledby="forgot-password-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="forgot-password-title">Reset password</h2>
      <button class="filter-panel-close" onclick="closeForgotPassword()" aria-label="Close">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg>
      </button>
    </div>
    <div class="filter-panel-body">
      <div id="forgot-step-request">
        <div class="field-hint" style="margin:0 0 14px 2px;">Enter the email or phone number on your account and we'll send a reset code.</div>
        <input id="fp-identity" type="text" placeholder="Email or phone number" />
        <div id="forgot-request-error" class="auth-error" style="display:none;"></div>
      </div>
      <div id="forgot-step-reset" style="display:none;">
        <div class="field-hint" id="forgot-reset-hint" style="margin:0 0 14px 2px;">Enter the code and choose a new password.</div>
        <input id="fp-code" type="text" inputmode="numeric" maxlength="6" placeholder="6-digit code" />
        <div class="password-field-wrap">
          <input id="fp-new-password" type="password" placeholder="New password" autocomplete="new-password" />
          <button type="button" class="password-toggle-btn" onclick="togglePasswordVisibility('fp-new-password', this)" aria-label="Show password" aria-pressed="false">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
        <div class="field-hint">At least 6 characters, with letters and numbers.</div>
        <div id="forgot-reset-error" class="auth-error" style="display:none;"></div>
      </div>
    </div>
    <div class="filter-panel-footer">
      <button type="button" class="filter-apply-btn" id="forgot-step-btn" onclick="submitForgotPasswordStep()">Send reset code</button>
    </div>
  </div>

  <div class="landing-footer">
    <div>
      <div class="globe-line"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.7 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3Z"/></svg> Connect around <b>the world.</b></div>
      <div class="sub-line">No matter where you are, real connections are everywhere.</div>
    </div>
    <div class="join-badge"><svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> New here? Be one of the first to join.</div>
  </div>

</div>

`;
