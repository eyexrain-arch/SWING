// HTML: Matches, chat, likes, explore panels
module.exports = `        <div class="view-panel" id="panel-matches">
          <div id="matches-full-list"></div>
        </div>

        <div class="view-panel" id="panel-chat">
          <div class="chat-panel">
            <div class="chat-header">
              <button class="back-btn" onclick="switchView('matches')" aria-label="Back to matches"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M19 12H5M11 6l-6 6 6 6"/></svg></button>
              <div class="msg-avatar" id="chat-avatar" style="width:36px;height:36px;font-size:12px;"></div>
              <div style="font-weight:600;" id="chat-name"></div>
            </div>
            <div id="chat-compat-panel"></div>
            <div class="chat-messages" id="chat-messages"></div>
            <div class="chat-input-row">
              <input id="chat-input" placeholder="Type a message..." />
              <button onclick="sendMessage()">Send</button>
            </div>
          </div>
        </div>

        <div class="view-panel" id="panel-likes">
          <div class="admirer-grid" id="admirer-grid"></div>
        </div>

        <div class="view-panel" id="panel-explore">
          <div class="explore-panel">
            <div class="explore-header">
              <div class="explore-title">Explore</div>
              <div class="explore-sub muted-note">Browse everyone currently available to you at a glance — tap anyone to see their full profile.</div>
            </div>
            <div class="explore-grid" id="explore-grid"></div>
          </div>
        </div>

`;
