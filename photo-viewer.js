// CSS: Discover card panel, photo lightbox, profile photo crop
module.exports = `  /* ---------- Discover card — About Me / Interests / My Vibes panel ---------- */
  .swipe-card-body { padding: 20px 22px 22px; display: flex; flex-direction: column; gap: 18px; }
  .swipe-section-title { display: flex; align-items: center; gap: 9px; margin-bottom: 10px; font-size: 14px; font-weight: 700; color: var(--ink); }
  .swipe-section-title .icon-circle { width: 28px; height: 28px; border-radius: 50%; background: var(--pink-100); color: var(--pink-600); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .swipe-section-text { margin: 0; font-size: 13.5px; line-height: 1.6; color: var(--ink); opacity: 0.85; white-space: pre-wrap; }
  .swipe-section-text.empty { opacity: 0.5; font-style: italic; }
  .swipe-vibes-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .swipe-vibes-thumb { aspect-ratio: 1; border-radius: 12px; overflow: hidden; background: var(--cream); cursor: pointer; }
  .swipe-vibes-thumb img { width: 100%; height: 100%; object-fit: cover; display: block; }

  /* ---------- Photo lightbox (full-size vibes photos) ---------- */
  .photo-lightbox-overlay {
    display: none; position: fixed; inset: 0; z-index: 300;
    background: rgba(10,4,8,0.92); align-items: center; justify-content: center; padding: 40px 16px;
  }
  .photo-lightbox-overlay.visible { display: flex; }
  .photo-lightbox-overlay img {
    max-width: 100%; max-height: 100%; object-fit: contain; border-radius: 8px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  .photo-lightbox-close, .photo-lightbox-nav {
    position: fixed; border: none; background: rgba(255,255,255,0.12); color: white;
    border-radius: 50%; display: flex; align-items: center; justify-content: center;
    cursor: pointer; backdrop-filter: blur(2px);
  }
  .photo-lightbox-close:hover, .photo-lightbox-nav:hover { background: rgba(255,255,255,0.22); }
  .photo-lightbox-close { top: 18px; right: 18px; width: 40px; height: 40px; }
  .photo-lightbox-nav { top: 50%; transform: translateY(-50%); width: 48px; height: 48px; }
  .photo-lightbox-prev { left: 18px; }
  .photo-lightbox-next { right: 18px; }
  .photo-lightbox-nav:disabled { opacity: 0.25; cursor: default; }
  .photo-lightbox-counter {
    position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
    color: white; font-size: 12.5px; opacity: 0.8; background: rgba(255,255,255,0.12);
    padding: 4px 12px; border-radius: 999px;
  }
  @media (max-width: 560px) {
    .photo-lightbox-nav { width: 40px; height: 40px; }
  }

  /* ---------- Profile photo crop step ---------- */
  .photo-crop-overlay {
    display: none; position: fixed; inset: 0; z-index: 320;
    background: rgba(10,4,8,0.92); align-items: center; justify-content: center; padding: 20px;
  }
  .photo-crop-overlay.visible { display: flex; }
  .photo-crop-modal {
    width: 100%; max-width: 420px; background: var(--card); border-radius: 18px;
    padding: 18px; display: flex; flex-direction: column; gap: 12px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.4);
  }
  .photo-crop-header { font-weight: 700; font-size: 16px; text-align: center; }
  /* Fixed 3:4 stage. The image inside is absolutely positioned and moved/
     scaled via a JS-driven transform (drag to pan, wheel/pinch to zoom) —
     whatever's visible inside this box on confirm is exactly what gets
     uploaded, so every profile photo ends up the same 3:4 portrait shape. */
  .photo-crop-stage {
    position: relative; width: 100%; aspect-ratio: 3 / 4; background: #000;
    border-radius: 12px; overflow: hidden; touch-action: none; cursor: grab;
  }
  .photo-crop-stage.dragging { cursor: grabbing; }
  .photo-crop-stage img {
    position: absolute; top: 0; left: 0; max-width: none; max-height: none;
    will-change: transform; user-select: none; -webkit-user-drag: none; pointer-events: none;
  }
  .photo-crop-hint { text-align: center; font-size: 12px; color: var(--muted); }
  .photo-crop-actions { display: flex; gap: 10px; }
  .photo-crop-actions button { flex: 1; padding: 12px; border-radius: 10px; border: none; font-weight: 600; font-size: 14px; }
  .photo-crop-cancel { background: var(--cream); color: var(--ink); }
  .photo-crop-confirm { background: var(--pink-600); color: white; }
  .photo-crop-confirm:disabled { opacity: 0.6; }

  .swipe-actions { display: flex; justify-content: center; align-items: center; gap: 18px; padding: 22px 0 6px; }
  .swipe-actions button { border: none; border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }
  .act-pass { width: 62px; height: 62px; background: white; color: #d8536b; font-size: 24px; }
  .act-like { width: 62px; height: 62px; background: linear-gradient(135deg, var(--pink-500), var(--pink-600)); color: white; font-size: 24px; }
  .swipe-hint { text-align: center; font-size: 12.5px; color: var(--muted); }
  #discover-explore-hint { margin-bottom: 4px; }

`;
