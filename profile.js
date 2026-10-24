/**
 * Update profile details.
 */

const { MAX_BIO_CHARS, MAX_COUNTRY_CHARS, MAX_LOCATION_CHARS, MAX_NAME_CHARS, MAX_TEXT_BYTES, VALID_GENDERS, VALID_INTERESTED_IN, VALID_ORIENTATIONS } = require('../config');
const { supabase } = require('../supabase');
const { readBody, sendJSON } = require('../lib/http');
const { parseTags } = require('../lib/utils');
const { toOwnUser } = require('../services/serializers');
const { requireAuth } = require('../middleware/auth');

async function handleUpdateProfile(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const updates = {};
  if (body.name !== undefined) updates.name = String(body.name).trim().replace(/\s+/g, ' ').slice(0, MAX_NAME_CHARS);
  if (body.age !== undefined) { const a = Number(body.age); updates.age = Number.isInteger(a) && a >= 18 && a <= 100 ? a : null; }
  if (body.bio !== undefined) updates.bio = String(body.bio).trim().slice(0, MAX_BIO_CHARS);
  if (body.location !== undefined) updates.location = String(body.location).trim().slice(0, MAX_LOCATION_CHARS);
  if (body.country !== undefined) updates.country = String(body.country).trim().slice(0, MAX_COUNTRY_CHARS);
  // ⚠️ SCHEMA CHANGE — discoverable/show_location are new boolean columns.
  // This isn't in the original setup SQL — add it once via:
  //   ALTER TABLE users ADD COLUMN discoverable boolean NOT NULL DEFAULT true;
  //   ALTER TABLE users ADD COLUMN show_location boolean NOT NULL DEFAULT true;
  // Until that migration runs, these two lines will make every profile
  // update fail (Postgres will reject the unknown columns).
  if (body.discoverable !== undefined) updates.discoverable = body.discoverable === true;
  if (body.showLocation !== undefined) updates.show_location = body.showLocation === true;
  if (body.gender !== undefined && VALID_GENDERS.includes(body.gender)) updates.gender = body.gender;
  if (body.orientation !== undefined) {
    if (body.orientation === null || body.orientation === '') updates.orientation = null;
    else if (VALID_ORIENTATIONS.includes(body.orientation)) updates.orientation = body.orientation;
  }
  if (body.interestedIn !== undefined && Array.isArray(body.interestedIn)) {
    updates.interested_in = [...new Set(body.interestedIn.filter(v => VALID_INTERESTED_IN.includes(v)))];
  }
  if (body.tags !== undefined) updates.tags = parseTags(body.tags);

  // Extended profile fields (see PROFILE_COMPLETION_FIELDS / matchesFilters
  // on the frontend). Each is validated against the same option lists used
  // by the "complete your profile" screen and the Discover filter panel, so
  // stored values always line up with what the filters check against.
  const ONE_WORD_SCALE = ['never', 'sometimes', 'often'];
  if (body.languages !== undefined) {
    updates.languages = Array.isArray(body.languages)
      ? body.languages.map(l => String(l).trim()).filter(Boolean).slice(0, 10)
      : [];
  }
  if (body.education !== undefined && ['', 'high_school', 'undergrad', 'postgrad', 'phd'].includes(body.education)) {
    updates.education = body.education;
  }
  if (body.heightCm !== undefined) {
    const h = parseInt(body.heightCm, 10);
    updates.height_cm = (Number.isFinite(h) && h >= 100 && h <= 250) ? h : null;
  }
  if (body.exercise !== undefined && ['', ...ONE_WORD_SCALE].includes(body.exercise)) updates.exercise = body.exercise;
  if (body.drinking !== undefined && ['', ...ONE_WORD_SCALE].includes(body.drinking)) updates.drinking = body.drinking;
  if (body.smoking !== undefined && ['', ...ONE_WORD_SCALE].includes(body.smoking)) updates.smoking = body.smoking;
  if (body.religion !== undefined && ['', 'christian', 'muslim', 'hindu', 'buddhist', 'jewish', 'spiritual', 'agnostic', 'atheist', 'other'].includes(body.religion)) {
    updates.religion = body.religion;
  }
  if (body.political !== undefined && ['', 'liberal', 'moderate', 'conservative', 'not_political', 'other'].includes(body.political)) {
    // DB check constraint allows NULL or one of the five values, but not ''
    // — so an empty string (meaning "unset") must be stored as NULL.
    updates.political_views = body.political === '' ? null : body.political;
  }
  if (body.children !== undefined && ['', 'has', 'none', 'unspecified'].includes(body.children)) updates.children = body.children;
  if (body.wantsChildren !== undefined && ['', 'yes', 'no', 'maybe'].includes(body.wantsChildren)) updates.wants_children = body.wantsChildren;
  if (body.datingIntentions !== undefined) {
    const allowed = ['casual', 'relationship', 'marriage', 'friendship', 'not_sure'];
    updates.dating_intentions = Array.isArray(body.datingIntentions)
      ? body.datingIntentions.filter(v => allowed.includes(v))
      : [];
  }

  const { data: updated, error } = await supabase
    .from('users').update(updates).eq('id', user.id).select().single();
  if (error) throw error;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

module.exports = {
  handleUpdateProfile,
};
