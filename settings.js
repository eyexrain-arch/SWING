// CSS: Settings panel
module.exports = `  /* ---------- Settings panel ---------- */
  .settings-overlay {
    position: fixed; inset: 0; background: rgba(20,5,12,0.45); z-index: 210;
    opacity: 0; pointer-events: none; transition: opacity 0.25s ease;
  }
  .settings-overlay.open { opacity: 1; pointer-events: auto; }
  .settings-panel {
    position: fixed; top: 0; right: 0; bottom: 0; z-index: 211;
    width: min(440px, 100vw); background: var(--card); color: var(--ink);
    box-shadow: -12px 0 40px rgba(20,5,12,0.22);
    transform: translateX(100%); transition: transform 0.3s cubic-bezier(.32,.72,0,1);
    display: flex; flex-direction: column;
  }
  .settings-panel.open { transform: translateX(0); }
  .settings-header { display:flex; align-items:center; gap:12px; padding:18px 20px; border-bottom:1px solid var(--border); flex-shrink:0; }
  .settings-header h2 { margin:0; font-size:19px; flex:1; }
  .settings-close { width:34px; height:34px; border:0; border-radius:50%; background:var(--cream); color:var(--muted); display:flex; align-items:center; justify-content:center; }
  .settings-body { overflow-y:auto; padding:16px 16px 28px; }
  .settings-section { margin-bottom:20px; }
  .settings-section-title { margin:0 4px 8px; font-size:11px; font-weight:800; letter-spacing:1px; color:var(--muted); }
  .settings-card { background:var(--card); border:1px solid var(--border); border-radius:16px; overflow:hidden; }
  .settings-row { width:100%; min-height:58px; padding:12px 14px; display:flex; align-items:center; gap:12px; border:0; border-bottom:1px solid var(--border); background:transparent; color:var(--ink); text-align:left; font:inherit; }
  .settings-row:last-child { border-bottom:0; }
  .settings-row.clickable { cursor:pointer; }
  .settings-row.clickable:hover { background:var(--cream); }
  .settings-icon { width:34px; height:34px; border-radius:10px; background:var(--cream); color:var(--pink-600); display:flex; align-items:center; justify-content:center; flex-shrink:0; }
  .settings-copy { min-width:0; flex:1; }
  .settings-label { display:block; font-size:13.5px; font-weight:650; }
  .settings-desc { display:block; margin-top:2px; font-size:11.5px; color:var(--muted); line-height:1.4; }
  .settings-chevron { color:var(--muted); font-size:18px; }
  .settings-value { color:var(--muted); font-size:12px; max-width:150px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .settings-choice-row { display:flex; gap:7px; padding:12px 14px; border-bottom:1px solid var(--border); }
  .settings-choice-row:last-child { border-bottom:0; }
  .settings-choice { flex:1; border:1px solid var(--border); background:var(--card); color:var(--muted); border-radius:10px; padding:9px 6px; font-size:12px; font-weight:650; }
  .settings-choice.active { border-color:var(--pink-600); background:var(--pink-100); color:var(--pink-600); }
  .settings-toggle { width:42px; height:24px; border:0; border-radius:14px; background:var(--border); padding:3px; position:relative; flex-shrink:0; }
  .settings-toggle::after { content:''; position:absolute; top:3px; left:3px; width:18px; height:18px; border-radius:50%; background:white; box-shadow:0 1px 3px rgba(0,0,0,.18); transition:transform .2s ease; }
  .settings-toggle.active { background:var(--pink-600); }
  .settings-toggle.active::after { transform:translateX(18px); }
  .settings-danger { color:#c6284d; }
  .settings-danger-btn { background: #c6284d !important; }
  .settings-danger-btn:hover { background: #a91f40 !important; }
  .settings-note { margin:8px 4px 0; font-size:11px; color:var(--muted); line-height:1.45; }
  body.settings-dark {
    --cream:#15161a; --card:#202126; --ink:#f4f1f3; --muted:#aaa5ab; --border:#35363d; --pink-100:#3b202b;
  }
  body.settings-dark .q-option, body.settings-dark .settings-choice { background:var(--card); color:var(--ink); }
  body.settings-dark .icon-btn { background:var(--card); }
  body.settings-dark .icon-btn#profile-settings-btn {
    background: rgba(255,255,255,.07);
    border-color: rgba(255,255,255,.10);
    color: #f2f2f5;
    box-shadow: 0 2px 8px rgba(0,0,0,.18);
  }
  body.settings-dark .icon-btn#profile-settings-btn:hover {
    background: rgba(255,255,255,.11);
    color: #ff8db7;
    border-color: rgba(255,255,255,.14);
  }
  body.settings-dark .settings-row.clickable:hover { background:#292a30; }
`;
