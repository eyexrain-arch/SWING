// HTML: "I'm looking for" screen
module.exports = `<div id="looking-for-screen">
  <div class="q-card" style="max-width:540px;">
    <button type="button" class="profile-overlay-close" onclick="closeLookingForScreen()" aria-label="Close I'm looking for">
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>
    </button>
    <div class="q-header">
      <div class="logo-font">swing</div>
      <div class="q-kicker"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg> I'M LOOKING FOR</div>
    </div>
    <h3 class="q-title">What are you looking for?</h3>
    <div class="q-hint">Choose as many as apply</div>

    <div class="details-body" id="looking-for-form-body">
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

    <button id="looking-for-save-btn" onclick="saveLookingForScreen()">Save</button>
    <button class="q-skip" onclick="closeLookingForScreen()">Cancel</button>
  </div>
</div>

`;
