// HTML: Compatibility questionnaire screen
module.exports = `<div id="questionnaire-screen">
  <div class="q-card">
    <div class="q-header">
      <div class="logo-font">swing</div>
      <div class="q-kicker"><svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg> COMPATIBILITY QUESTIONNAIRE</div>
    </div>
    <div id="questionnaire-body"></div>
    <div class="q-actions">
      <button id="q-back-btn" onclick="goBackQuestion()">Back</button>
      <button id="q-next-btn" onclick="goNextQuestion()">Next</button>
    </div>
    <button class="q-skip" onclick="skipQuestionnaire()">Skip for now</button>
  </div>
</div>

`;
