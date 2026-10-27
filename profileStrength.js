// Profile strength / completion scoring.

// Dynamic weighted profile strength. Each section earns only the portion of
// its weight represented by the user's actual completed data.
//
// IMPORTANT: Do not replace this with a hard-coded percentage. The score is
// recalculated every time the user's profile is returned from the server.
const PROFILE_STRENGTH_SECTIONS = [
  {
    key: 'profilePhoto',
    label: 'Profile photo',
    weight: 10,
    fields: [{ get: u => u.photoUrl }],
  },
  {
    key: 'nameAndAge',
    label: 'Name and age',
    weight: 10,
    fields: [{ get: u => u.name }, { get: u => u.age }],
  },
  {
    key: 'bio',
    label: 'Bio/About Me',
    weight: 10,
    fields: [{ get: u => u.bio }],
  },
  {
    key: 'locationAndQuiz',
    label: 'Location and compatibility quiz',
    weight: 20,
    fields: [
      { get: u => u.location },
      { get: u => u.questionnaire?.relationship_goal },
      { get: u => u.questionnaire?.wants_kids },
      { get: u => u.questionnaire?.personality },
      { get: u => u.questionnaire?.top_value },
      { get: u => u.questionnaire?.conflict_style },
      { get: u => u.questionnaire?.social_style },
      { get: u => u.questionnaire?.career_priority },
      { get: u => u.questionnaire?.communication_style },
      { get: u => u.questionnaire?.personal_space },
      { get: u => u.questionnaire?.lifestyle_pace },
      { get: u => u.questionnaire?.dealbreakers },
    ],
  },
  {
    key: 'interestsAndQuickInfo',
    label: 'Interests/Hobbies and quick info',
    weight: 10,
    fields: [
      { get: u => u.tags },
      { get: u => u.languages },
    ],
  },
  {
    key: 'lookingFor',
    label: 'Looking For',
    weight: 10,
    fields: [{ get: u => u.datingIntentions }],
  },
  {
    key: 'lifestyle',
    label: 'Lifestyle details',
    weight: 5,
    fields: [
      { get: u => u.education },
      { get: u => u.heightCm },
      { get: u => u.exercise },
      { get: u => u.drinking },
      { get: u => u.smoking },
      { get: u => u.religion },
      { get: u => u.political },
      { get: u => u.children },
      { get: u => u.wantsChildren },
    ],
  },
  {
    key: 'additionalPhotosOrVibe',
    label: 'Additional photos or my vibe',
    weight: 15,
    // My Vibes currently supports up to 3 additional photos. Each photo earns
    // one third of this section's weight, so 1/3/3 photos = 5/10/15 points.
    fields: [
      { get: u => Array.isArray(u.galleryUrls) ? u.galleryUrls[0] : null },
      { get: u => Array.isArray(u.galleryUrls) ? u.galleryUrls[1] : null },
      { get: u => Array.isArray(u.galleryUrls) ? u.galleryUrls[2] : null },
    ],
  },
  {
    key: 'prompts',
    label: 'Prompts/Questions',
    weight: 10,
    // Up to 3 preset prompts a user can pick and answer (see PROMPT_LIBRARY).
    // Each answered prompt earns one third of this section's weight, so
    // 1/2/3 answered = ~3.3/6.7/10 points.
    fields: [
      { get: u => Array.isArray(u.prompts) ? u.prompts[0] : null },
      { get: u => Array.isArray(u.prompts) ? u.prompts[1] : null },
      { get: u => Array.isArray(u.prompts) ? u.prompts[2] : null },
    ],
  },
];

function isProfileValueCompleted(value) {
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'boolean') return true;
  return value !== null && value !== undefined && String(value).trim().length > 0;
}

function computeProfileStrength(user) {
  const sectionScores = {};
  let total = 0;

  for (const section of PROFILE_STRENGTH_SECTIONS) {
    const completed = section.fields.reduce((count, field) => {
      let value;
      try { value = field.get(user); } catch (_) { value = null; }
      return count + (isProfileValueCompleted(value) ? 1 : 0);
    }, 0);

    const ratio = section.fields.length ? completed / section.fields.length : 0;
    const points = section.weight * ratio;
    sectionScores[section.key] = {
      label: section.label,
      weight: section.weight,
      completed,
      totalFields: section.fields.length,
      points: Math.round(points * 100) / 100,
    };
    total += points;
  }

  return {
    percentage: Math.min(100, Math.round(total)),
    sections: sectionScores,
  };
}

// Backwards-compatible name used by the existing profile UI/API.
function computeProfileCompletion(user) {
  return computeProfileStrength(user).percentage;
}

module.exports = {
  computeProfileStrength,
};
