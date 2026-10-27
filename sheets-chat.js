// CSS: Block/report sheet, chat view, likes grid
module.exports = `  /* ---------- Block / Report action sheet ---------- */
  .action-sheet-overlay {
    display: none; position: fixed; inset: 0; z-index: 320; background: rgba(20,5,12,0.45);
    align-items: flex-end; justify-content: center;
  }
  .action-sheet-overlay.open { display: flex; }
  .action-sheet {
    background: white; border-radius: 20px 20px 0 0; width: 100%; max-width: 440px;
    padding: 8px 0 max(10px, env(safe-area-inset-bottom)); overflow: hidden;
  }
  .action-sheet-row {
    width: 100%; padding: 16px 20px; border: none; background: none; text-align: left;
    font: inherit; font-size: 15px; font-weight: 600; color: var(--ink); display: flex;
    align-items: center; gap: 12px; cursor: pointer; border-bottom: 1px solid var(--border);
  }
  .action-sheet-row:hover { background: var(--cream); }
  .action-sheet-row:last-child { border-bottom: none; }
  .action-sheet-row.danger { color: #c6284d; }
  .action-sheet-row.cancel { font-weight: 700; justify-content: center; margin-top: 4px; }
  .report-reason-list { padding: 6px 20px 16px; display: flex; flex-direction: column; gap: 8px; }
  .report-reason-list button {
    padding: 12px 14px; border-radius: 12px; border: 1px solid var(--border); background: white;
    text-align: left; font: inherit; font-size: 14px; color: var(--ink); cursor: pointer;
  }
  .report-reason-list button:hover { background: var(--cream); }
  .report-reason-list button.selected { background: var(--pink-500); border-color: var(--pink-500); color: white; font-weight: 600; }
  .blocked-user-row { display: flex; align-items: center; gap: 12px; padding: 12px 14px; border-bottom: 1px solid var(--border); }
  .blocked-user-row:last-child { border-bottom: none; }
  .blocked-user-row .avatar { width: 42px; height: 42px; border-radius: 50%; background-size: cover; background-position: center; flex-shrink: 0; }
  .blocked-user-row .name { font-weight: 600; font-size: 14.5px; flex: 1; min-width: 0; }
  .blocked-user-row button {
    padding: 7px 14px; border-radius: 10px; border: 1px solid var(--border); background: white;
    font: inherit; font-size: 13px; font-weight: 600; color: var(--ink); cursor: pointer; flex-shrink: 0;
  }
  .blocked-user-row button:hover { background: var(--cream); }

  .side-card { background: white; border-radius: 18px; padding: 18px; margin-bottom: 18px; }
  .side-card .side-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
  .side-card .side-head h3 { font-size: 16px; margin: 0; }
  .side-card .side-head a, .side-card .side-head .text-link { font-size: 12.5px; color: var(--pink-600); text-decoration: none; font-weight: 500; cursor: pointer; background: none; border: none; padding: 0; font-family: inherit; }
  .side-card .side-head .text-link:hover, .side-card .side-head a:hover { text-decoration: underline; }

  .match-avatars { display: flex; gap: 14px; flex-wrap: wrap; }
  .match-avatar-wrap { text-align: center; cursor: pointer; }
  .match-avatar { width: 56px; height: 56px; border-radius: 50%; border: 2.5px solid var(--pink-500); position: relative; display: flex; align-items: center; justify-content: center; color: white; font-weight: 700; font-size: 16px; }
  .match-avatar .heart-badge { position: absolute; bottom: -2px; right: -2px; width: 18px; height: 18px; border-radius: 50%; background: var(--pink-600); color: white; font-size: 9px; display: flex; align-items: center; justify-content: center; border: 2px solid white; }
  .match-avatar-wrap .mname { font-size: 11.5px; margin-top: 6px; color: var(--ink); }
  .muted-note { color: var(--muted); font-size: 13px; }

  .msg-item { display: flex; gap: 10px; padding: 10px 0; border-bottom: 1px solid var(--border); cursor: pointer; }
  .msg-item:last-child { border-bottom: none; }
  .msg-avatar { width: 40px; height: 40px; border-radius: 50%; color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; flex-shrink: 0; }
  .msg-body { flex: 1; min-width: 0; }
  .msg-top { display: flex; justify-content: space-between; font-size: 13px; }
  .msg-top .mname { font-weight: 600; }
  .msg-top .time { color: var(--muted); font-size: 11px; }
  .msg-preview { font-size: 12px; color: var(--muted); display: flex; justify-content: space-between; gap: 6px; }
  .msg-preview .text { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .unread-dot { background: var(--pink-600); color: white; font-size: 10px; font-weight: 700; width: 16px; height: 16px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }

  .promo-card { background: linear-gradient(135deg, var(--pink-100), #ffd3e2); border-radius: 18px; padding: 20px; }
  .promo-card h4 { margin: 0 0 6px; font-size: 15.5px; }
  .promo-card p { font-size: 12.5px; color: #7a5a66; margin: 0 0 14px; line-height: 1.5; }
  .promo-card button { background: var(--maroon-800); color: white; border: none; padding: 10px 18px; border-radius: 10px; font-size: 13px; font-weight: 600; }

  /* Chat view */
  .chat-panel { background: white; border-radius: 22px; display: flex; flex-direction: column; height: clamp(480px, calc(100dvh - 160px), 760px); }
  .chat-header { display: flex; align-items: center; gap: 12px; padding: 16px 20px; border-bottom: 1px solid var(--border); }
  .chat-header .back-btn { background: var(--cream); border: none; width: 34px; height: 34px; border-radius: 50%; font-size: 15px; }
  .chat-messages { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 10px; }
  .bubble { max-width: 65%; padding: 10px 14px; border-radius: 16px; font-size: 13.5px; line-height: 1.4; }
  .bubble.mine { align-self: flex-end; background: var(--pink-600); color: white; border-bottom-right-radius: 4px; }
  .bubble.theirs { align-self: flex-start; background: var(--cream); color: var(--ink); border-bottom-left-radius: 4px; }
  .chat-input-row { display: flex; gap: 10px; padding: 16px 20px; border-top: 1px solid var(--border); }
  .chat-input-row input { flex: 1; min-width: 0; padding: 11px 14px; border: 1px solid var(--border); border-radius: 10px; outline: none; font-size: 13.5px; }
  .chat-input-row button { background: var(--pink-600); color: white; border: none; padding: 0 18px; border-radius: 10px; font-weight: 600; font-size: 13px; flex-shrink: 0; white-space: nowrap; }

  /* Likes You grid */
  .admirer-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 14px; }
  .admirer-card { background: white; border-radius: 16px; padding: 16px; text-align: center; }
  .admirer-card .match-avatar { margin: 0 auto 8px; }
  .admirer-card .aname { font-weight: 600; font-size: 13.5px; }
  .admirer-card button { margin-top: 10px; width: 100%; padding: 8px; border: none; border-radius: 8px; background: var(--pink-600); color: white; font-size: 12.5px; font-weight: 600; }

  /* Profile view */
  .profile-form { background: white; border-radius: clamp(14px, 3vw, 18px); padding: clamp(18px, 5vw, 24px); width: 100%; max-width: min(480px, 100%); }
  .profile-form label { display: block; font-size: 12.5px; font-weight: 600; color: var(--muted); margin-bottom: 4px; }
  .profile-form input, .profile-form textarea, .profile-form select { width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 14px; font-size: 14px; box-sizing: border-box; }
  .profile-form textarea { resize: vertical; min-height: 70px; }
  .profile-form button { background: var(--pink-600); color: white; border: none; padding: 11px 20px; border-radius: 10px; font-weight: 600; font-size: 13.5px; }

`;
