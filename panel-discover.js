// HTML: Discover panel
module.exports = `        <div class="view-panel visible" id="panel-discover">
          <div class="filter-tabs discover-category-tabs" role="tablist" aria-label="Discover categories">
            <button class="active" type="button" role="tab" aria-selected="true" onclick="setDiscoverTab('maylike')" aria-label="Profiles You May Like" title="Profiles You May Like"><svg viewBox="0 0 24 24" width="19" height="19" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 2c.6 3.6 1.4 5.9 2.6 7.4 1.5 1.2 3.8 2 7.4 2.6-3.6.6-5.9 1.4-7.4 2.6-1.2 1.5-2 3.8-2.6 7.4-.6-3.6-1.4-5.9-2.6-7.4C7.9 13.4 5.6 12.6 2 12c3.6-.6 5.9-1.4 7.4-2.6C10.6 7.9 11.4 5.6 12 2Z"/></svg></button>
            <button type="button" role="tab" aria-selected="false" onclick="setDiscoverTab('liked')" aria-label="Profiles You Liked" title="Profiles You Liked"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 0 0-7.8 7.8l1 1L12 21.2l7.8-7.8 1-1a5.5 5.5 0 0 0 0-7.8Z"/></svg></button>
            <button type="button" role="tab" aria-selected="false" onclick="setDiscoverTab('nearby')" aria-label="Users Nearby" title="Users Nearby"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 21s7-6.5 7-11.5A7 7 0 1 0 5 9.5C5 14.5 12 21 12 21Z"/><circle cx="12" cy="9.5" r="2.2"/></svg></button>
            <button type="button" role="tab" aria-selected="false" onclick="setDiscoverTab('new')" aria-label="New Users" title="New Users"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/></svg></button>
          </div>
          <div class="discover-section-title" id="discover-tab-heading">Profiles You May Like <span id="discover-tab-count">0</span></div>
          <div class="discover-stack-wrap">
            <div class="discover-stack-nav-wrap">
              <div id="discover-list" class="discover-stack"></div>
              <button type="button" class="discover-nav-btn discover-nav-prev" id="discover-nav-prev" onclick="scrollDiscoverCarousel(-1)" aria-label="Previous profile" title="Previous profile" style="display:none;"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M15 5l-7 7 7 7"/></svg></button>
              <button type="button" class="discover-nav-btn discover-nav-next" id="discover-nav-next" onclick="scrollDiscoverCarousel(1)" aria-label="Next profile" title="Next profile" style="display:none;"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M9 5l7 7-7 7"/></svg></button>
            </div>
            <div class="swipe-hint" id="discover-explore-hint" style="display:none;">Tap a profile to explore more</div>
            <div class="swipe-actions" id="discover-stack-actions" style="display:none;">
              <button type="button" class="act-pass" onclick="swipeCurrentCard('pass')" aria-label="Pass" title="Pass"><svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg></button>
              <button type="button" class="act-like" onclick="swipeCurrentCard('like')" aria-label="Like" title="Like"><svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><path d="M12 20.5s-7.5-4.6-10-9.3C.4 8 1.7 4.6 5 3.6c2.2-.6 4.3.3 5.6 2.1l1.4 1.9 1.4-1.9C14.7 3.9 16.8 3 19 3.6c3.3 1 4.6 4.4 3 7.6-2.5 4.7-10 9.3-10 9.3Z"/></svg></button>
            </div>
            <div class="swipe-hint" id="discover-stack-hint" style="display:none;">Scroll sideways to browse, or use the buttons below</div>
          </div>
        </div>

        <div class="candidate-modal-overlay" id="candidate-detail-modal">
          <div class="candidate-modal">
            <button type="button" class="candidate-modal-menu-btn" onclick="openProfileActionSheet()" aria-label="More options" title="More options"><svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" stroke="none" aria-hidden="true" focusable="false"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg></button>
            <button type="button" class="candidate-modal-close" onclick="closeCandidateDetail()" aria-label="Close"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
            <div id="candidate-detail-body"></div>
            <div class="swipe-actions" id="candidate-detail-footer"></div>
          </div>
        </div>

        <div class="photo-lightbox-overlay" id="photo-lightbox" onclick="if (event.target === this) closePhotoLightbox()">
          <button type="button" class="photo-lightbox-close" onclick="closePhotoLightbox()" aria-label="Close"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
          <button type="button" class="photo-lightbox-nav photo-lightbox-prev" id="photo-lightbox-prev" onclick="navPhotoLightbox(-1)" aria-label="Previous photo"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M15 5l-7 7 7 7"/></svg></button>
          <img id="photo-lightbox-img" src="" alt="Full-size photo" />
          <button type="button" class="photo-lightbox-nav photo-lightbox-next" id="photo-lightbox-next" onclick="navPhotoLightbox(1)" aria-label="Next photo"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M9 5l7 7-7 7"/></svg></button>
          <div class="photo-lightbox-counter" id="photo-lightbox-counter"></div>
        </div>

        <div class="action-sheet-overlay" id="action-sheet-overlay" onclick="if (event.target === this) closeActionSheet()">
          <div class="action-sheet" id="action-sheet-body"></div>
        </div>

        <!-- Profile photo crop step: every profile photo is cropped to a
             3:4 portrait before it's uploaded, so every profile photo in
             the app ends up the same shape. -->
        <div class="photo-crop-overlay" id="photo-crop-overlay">
          <div class="photo-crop-modal">
            <div class="photo-crop-header">Crop your photo</div>
            <div class="photo-crop-stage" id="photo-crop-stage"><img id="photo-crop-img" src="" alt="" /></div>
            <div class="photo-crop-hint">Drag to reposition, pinch or scroll to zoom</div>
            <div class="photo-crop-actions">
              <button type="button" class="photo-crop-cancel" onclick="cancelPhotoCrop()">Cancel</button>
              <button type="button" class="photo-crop-confirm" id="photo-crop-confirm-btn" onclick="confirmPhotoCrop()">Use photo</button>
            </div>
          </div>
        </div>

`;
