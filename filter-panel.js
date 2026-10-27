// HTML: Filter panel and end of dashboard
module.exports = `  <div class="filter-panel" id="filter-panel" role="dialog" aria-modal="true" aria-labelledby="filter-panel-title" aria-hidden="true">
    <div class="filter-panel-handle"></div>
    <div class="filter-panel-header">
      <h2 id="filter-panel-title">Filters</h2>
      <button class="filter-panel-close" onclick="closeFilterPanel()" aria-label="Close filters"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 5l14 14M19 5 5 19"/></svg></button>
    </div>

    <div class="filter-panel-body">

      <div class="filter-section">
        <p class="filter-section-title">BASIC</p>

        <div class="filter-field">
          <div class="filter-field-label">Show me</div>
          <div class="filter-chips" id="f-showme-chips">
            <button type="button" class="filter-chip" data-group="showMe" data-value="men">Men</button>
            <button type="button" class="filter-chip" data-group="showMe" data-value="women">Women</button>
            <button type="button" class="filter-chip" data-group="showMe" data-value="nonbinary">Non-binary</button>
            <button type="button" class="filter-chip" data-group="showMe" data-value="everyone">Everyone</button>
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Age <span class="val" id="f-age-val">18 – 60</span></div>
          <div class="dual-range">
            <div class="track"></div>
            <div class="fill" id="f-age-fill"></div>
            <input type="range" id="f-age-min" min="18" max="80" value="18" oninput="onDualRangeInput('age', this)" />
            <input type="range" id="f-age-max" min="18" max="80" value="60" oninput="onDualRangeInput('age', this)" />
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Distance <span class="val" id="f-distance-val">Up to 100 km</span></div>
          <div class="single-range">
            <input type="range" id="f-distance" min="1" max="500" value="100" oninput="onSingleRangeInput('distance')" />
          </div>
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-filter-country">Country</label>
          <input class="filter-input" id="f-filter-country" type="text" placeholder="e.g. Philippines" oninput="onTextFilterInput('country', this)" />
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-city">City</label>
          <input class="filter-input" id="f-city" type="text" placeholder="e.g. Manila" oninput="onTextFilterInput('city', this)" />
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Languages</div>
          <div class="filter-chips" id="f-languages-chips">
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

        <div class="filter-field filter-toggle-row">
          <label class="filter-field-label" for="f-verified">Verified profiles</label>
          <button type="button" class="filter-switch" id="f-verified" onclick="toggleSwitch('verified')"></button>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Interests</div>
          <div class="filter-chips" id="f-interests-chips">
            <button type="button" class="filter-chip" data-group="interests" data-value="travel">Travel</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="music">Music</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="fitness">Fitness</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="foodie">Foodie</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="movies">Movies</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="gaming">Gaming</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="art">Art</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="pets">Pets</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="reading">Reading</button>
            <button type="button" class="filter-chip" data-group="interests" data-value="outdoors">Outdoors</button>
          </div>
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-education">Education</label>
          <select class="filter-select" id="f-education">
            <option value="">Any</option>
            <option value="high_school">High school</option>
            <option value="undergrad">Undergrad</option>
            <option value="postgrad">Postgrad</option>
            <option value="phd">PhD</option>
          </select>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Height (cm) <span class="val" id="f-height-val">140 – 210</span></div>
          <div class="dual-range">
            <div class="track"></div>
            <div class="fill" id="f-height-fill"></div>
            <input type="range" id="f-height-min" min="140" max="210" value="140" oninput="onDualRangeInput('height', this)" />
            <input type="range" id="f-height-max" min="140" max="210" value="210" oninput="onDualRangeInput('height', this)" />
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Exercise</div>
          <div class="filter-chips" id="f-exercise-chips">
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
          <div class="filter-chips" id="f-drinking-chips">
            <button type="button" class="filter-chip" data-group="drinking" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="drinking" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="drinking" data-value="often">Often</button>
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Smoking</div>
          <div class="filter-chips" id="f-smoking-chips">
            <button type="button" class="filter-chip" data-group="smoking" data-value="never">Never</button>
            <button type="button" class="filter-chip" data-group="smoking" data-value="sometimes">Sometimes</button>
            <button type="button" class="filter-chip" data-group="smoking" data-value="often">Often</button>
          </div>
        </div>

        <div class="filter-field">
          <label class="filter-field-label" for="f-religion">Religion</label>
          <select class="filter-select" id="f-religion">
            <option value="">Any</option>
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
          <label class="filter-field-label" for="f-political">Political views</label>
          <select class="filter-select" id="f-political">
            <option value="">Any</option>
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
          <div class="filter-chips" id="f-children-chips">
            <button type="button" class="filter-chip" data-group="children" data-value="has">Has children</button>
            <button type="button" class="filter-chip" data-group="children" data-value="none">Doesn't have children</button>
            <button type="button" class="filter-chip" data-group="children" data-value="unspecified">Prefer not to say</button>
          </div>
        </div>

        <div class="filter-field">
          <div class="filter-field-label">Wants children</div>
          <div class="filter-chips" id="f-wantschildren-chips">
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
          <div class="filter-chips" id="f-intentions-chips">
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="casual">Casual</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="relationship">Relationship</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="marriage">Marriage</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="friendship">Friendship</button>
            <button type="button" class="filter-chip" data-group="datingIntentions" data-value="not_sure">Not sure</button>
          </div>
        </div>
      </div>

      <div class="filter-section">
        <p class="filter-section-title">ACTIVITY</p>

        <div class="filter-field filter-toggle-row">
          <label class="filter-field-label" for="f-online">Online now</label>
          <button type="button" class="filter-switch" id="f-online" onclick="toggleSwitch('onlineNow')"></button>
        </div>

        <div class="filter-field filter-toggle-row">
          <label class="filter-field-label" for="f-new">New here</label>
          <button type="button" class="filter-switch" id="f-new" onclick="toggleSwitch('newHere')"></button>
        </div>
      </div>

    </div>

    <div class="filter-panel-footer">
      <button type="button" class="filter-reset-btn" onclick="resetFilters()">Reset all</button>
      <button type="button" class="filter-apply-btn" onclick="applyFiltersAndClose()">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M20 6 9 17l-5-5"/></svg>
        Apply filters
      </button>
    </div>
  </div>
</div>

`;
