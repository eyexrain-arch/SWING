// CSS: Dark / system theme overrides
module.exports = `  /* ---------- Dark/system theme coverage ---------- */
  body.settings-dark {
    background: var(--cream);
    color: var(--ink);
  }
  body.settings-dark .main-content,
  body.settings-dark .content-area,
  body.settings-dark .profile-view,
  body.settings-dark .profile-form,
  body.settings-dark .side-card,
  body.settings-dark .swipe-card,
  body.settings-dark .empty-state,
  body.settings-dark .admirer-card,
  body.settings-dark .chat-panel,
  body.settings-dark .q-card,
  body.settings-dark .settings-card,
  body.settings-dark .discover-row,
  body.settings-dark .discover-row-menu,
  body.settings-dark .candidate-modal {
    background: var(--card);
    color: var(--ink);
  }
  body.settings-dark .discover-row-tags span { background: var(--cream); }
  body.settings-dark .filter-tabs button,
  body.settings-dark .act-pass {
    background: var(--card);
    color: var(--ink);
  }
  body.settings-dark .q-option,
  body.settings-dark .filter-chip,
  body.settings-dark .filter-tabs button,
  body.settings-dark .filter-field input,
  body.settings-dark .filter-field select,
  body.settings-dark .filter-field textarea,
  body.settings-dark input,
  body.settings-dark textarea,
  body.settings-dark select,
  body.settings-dark .icon-btn {
    background: var(--card);
    color: var(--ink);
    border-color: var(--border);
  }
  body.settings-dark input::placeholder,
  body.settings-dark textarea::placeholder { color: var(--muted); }
  body.settings-dark .profile-label,
  body.settings-dark .field-label,
  body.settings-dark .form-label,
  body.settings-dark .section-title,
  body.settings-dark .card-title,
  body.settings-dark .profile-name,
  body.settings-dark .profile-meta,
  body.settings-dark .profile-bio,
  body.settings-dark .swipe-section-text,
  body.settings-dark .empty-state h3,
  body.settings-dark .empty-state p,
  body.settings-dark .chat-header,
  body.settings-dark .chat-input-row input,
  body.settings-dark .msg-item,
  body.settings-dark .match-item,
  body.settings-dark .vibes-slot {
    color: var(--ink);
  }
  body.settings-dark .muted,
  body.settings-dark .hint,
  body.settings-dark .subtext,
  body.settings-dark .profile-location,
  body.settings-dark .profile-detail,
  body.settings-dark .profile-field-value,
  body.settings-dark .filter-section-title,
  body.settings-dark .filter-field-label,
  body.settings-dark .settings-desc,
  body.settings-dark .settings-section-title,
  body.settings-dark .settings-note,
  body.settings-dark .settings-value {
    color: var(--muted);
  }
  body.settings-dark .nav-item:not(.active),
  body.settings-dark .nav-item:not(.active) span { color: #d8d3d7; }
  body.settings-dark .topbar h1,
  body.settings-dark .topbar,
  body.settings-dark .profile-header,
  body.settings-dark .filter-panel,
  body.settings-dark .settings-panel { color: var(--ink); }
  body.settings-dark .filter-panel,
  body.settings-dark .settings-panel { background: var(--card); }
  body.settings-dark .filter-panel-header,
  body.settings-dark .settings-header,
  body.settings-dark .filter-section,
  body.settings-dark .settings-row { border-color: var(--border); }
  body.settings-dark .filter-panel-close,
  body.settings-dark .settings-close,
  body.settings-dark .settings-icon { background: #292a30; color: var(--ink); }
  body.settings-dark .filter-tabs button.active { color: white; }
  /* The dark-mode "make every filter-tabs button dark" rule above also
     matched the active (pink) discover-category-tabs button, wiping out
     its pink highlight — restore it here with higher specificity. */
  body.settings-dark .discover-category-tabs button.active {
    background: var(--pink-500);
    border-color: var(--pink-500);
    color: white;
  }
  body.settings-dark .settings-choice { color: var(--muted); }
  body.settings-dark .settings-choice.active { color: var(--pink-500); }
  body.settings-dark .settings-row.clickable:hover { background: #292a30; }
  body.settings-dark .msg-item[style*="background:white"],
  body.settings-dark .msg-item[style*="background: white"] { background: var(--card) !important; color: var(--ink) !important; }
  body.settings-dark .settings-danger { color: #ff7b9d; }

  @media (max-width: 600px) {
    .settings-panel { width:100vw; }
  }

`;
