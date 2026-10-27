// HTML: Complete-your-profile (details) screen
module.exports = `<div id="details-screen">
  <div class="q-card" style="max-width:540px;">
    <button type="button" class="profile-overlay-close" onclick="closeDetailsScreen()" aria-label="Close About Me">
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>
    </button>
    <div class="q-header">
      <div class="logo-font">swing</div>
      <div class="q-kicker"><svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> COMPLETE YOUR PROFILE</div>
    </div>
    <h3 class="q-title">A few more details</h3>
    <div class="q-hint">Optional — but profiles with more details get better matches</div>
    <div class="q-progress-bar"><div class="q-progress-fill" id="details-progress-fill" style="width:0%;"></div></div>

    <div class="details-body" id="details-form-body">

      <div class="filter-section">
        <p class="filter-section-title">LANGUAGES</p>
        <div class="filter-field">
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="languages" data-value="English">English</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Tagalog">Tagalog</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Spanish">Spanish</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Mandarin">Mandarin</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Japanese">Japanese</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="Korean">Korean</button>
            <button type="button" class="filter-chip" data-group="languages" data-value="French">French</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">PROFILE</p>
        <div class="filter-field">
          <label class="filter-field-label" for="d-education">Education</label>
          <select class="filter-select" id="d-education">
            <option value="">Prefer not to say</option>
            <option value="high_school">High school</option>
            <option value="undergrad">Undergrad</option>
            <option value="postgrad">Postgrad</option>
            <option value="phd">PhD</option>
          </select>
        </div>
        <div class="filter-field">
          <div class="filter-field-label">Height <span class="val" id="d-height-val">170 cm</span></div>
          <div class="single-range"><input type="range" id="d-height" min="140" max="210" value="170" oninput="onDetailsHeightInput()" /></div>
        </div>
        <div class="filter-field">
          <div class="filter-field-label">Exercise</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="exercise" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="exercise" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="exercise" data-value="often">Often</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">LIFESTYLE</p>
        <div class="filter-field">
          <div class="filter-field-label">Drinking</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="drinking" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="drinking" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="drinking" data-value="often">Often</button>
          </div>
        </div>
        <div class="filter-field">
          <div class="filter-field-label">Smoking</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="smoking" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="smoking" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="smoking" data-value="often">Often</button>
          </div>
        </div>
        <div class="filter-field">
          <label class="filter-field-label" for="d-religion">Religion</label>
          <select class="filter-select" id="d-religion">
            <option value="">Prefer not to say</option>
            <option value="christian">Christian</option>
            <option value="muslim">Muslim</option>
            <option value="hindu">Hindu</option>
            <option value="buddhist">Buddhist</option>
            <option value="jewish">Jewish</option>
            <option value="spiritual">Spiritual</option>
            <option value="agnostic">Agnostic</option>
            <option value="atheist">Atheist</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="filter-field">
          <label class="filter-field-label" for="d-political">Political views</label>
          <select class="filter-select" id="d-political">
            <option value="">Prefer not to say</option>
            <option value="liberal">Liberal</option>
            <option value="moderate">Moderate</option>
            <option value="conservative">Conservative</option>
            <option value="not_political">Not political</option>
            <option value="other">Other</option>
          </select>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">FAMILY</p>
        <div class="filter-field">
          <div class="filter-field-label">Children</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="children" data-value="has">Has children</button>
            <button type="button" class="filter-chip" data-group="children" data-value="none">Doesn't have children</button>
            <button type="button" class="filter-chip" data-group="children" data-value="unspecified">Prefer not to say</button>
          </div>
        </div>
        <div class="filter-field">
          <div class="filter-field-label">Wants children</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="wantsChildren" data-value="yes">Yes</button>
            <button type="button" class="filter-chip" data-group="wantsChildren" data-value="no">No</button>
            <button type="button" class="filter-chip" data-group="wantsChildren" data-value="maybe">Maybe</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">DATING</p>
        <div class="filter-field">
          <div class="filter-field-label">Dating intentions</div>
          <div class="filter-chips">
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="casual">Casual</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="relationship">Relationship</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="marriage">Marriage</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="friendship">Friendship</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="not_sure">Not sure</button>
          </div>
        </div>
      </div>

    </div>

    <button id="details-save-btn" onclick="saveDetailsScreen()">Save & continue</button>
    <button class="q-skip" onclick="skipDetailsScreen()">Skip for now</button>
  </div>
</div>

`;
