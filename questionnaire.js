/**
 * Compatibility questionnaire: question definitions, validation, display and scoring.
 */


// ---------- Compatibility questionnaire ----------

const QUESTIONNAIRE = [
  {
    id: 'relationship_goal', type: 'single', question: 'What are you looking for?',
    options: [
      { value: 'long_term', label: 'Long-term relationship' },
      { value: 'marriage', label: 'Marriage' },
      { value: 'dating', label: 'Dating' },
      { value: 'friendship', label: 'Friendship' },
      { value: 'casual', label: 'Casual relationship' },
      { value: 'not_sure', label: 'Not sure yet' },
    ],
    matchPhrase: (label) => `want the same thing right now (${label.toLowerCase()})`,
  },
  {
    id: 'wants_kids', type: 'single', question: 'Do you want children someday?',
    options: [
      { value: 'yes', label: 'Yes' },
      { value: 'no', label: 'No' },
      { value: 'maybe', label: 'Maybe' },
      { value: 'have_kids', label: 'I already have kids' },
    ],
    matchPhrase: (label) => `feel the same about having kids`,
  },
  {
    id: 'personality', type: 'single', question: 'How would you describe your personality?',
    options: [
      { value: 'introvert', label: 'Introvert' },
      { value: 'extrovert', label: 'Extrovert' },
      { value: 'ambivert', label: 'A mix of both' },
    ],
    matchPhrase: (label) => `share a similar personality (${label.toLowerCase()})`,
  },
  {
    id: 'top_value', type: 'single', question: 'What matters most to you in a partner?',
    options: [
      { value: 'humor', label: 'Sense of humor' },
      { value: 'ambition', label: 'Ambition' },
      { value: 'kindness', label: 'Kindness' },
      { value: 'intelligence', label: 'Intelligence' },
      { value: 'loyalty', label: 'Loyalty' },
    ],
    matchPhrase: (label) => `value ${label.toLowerCase()} most in a partner`,
  },
  {
    id: 'conflict_style', type: 'single', question: 'How do you handle conflict?',
    options: [
      { value: 'talk_immediately', label: 'Talk it out right away' },
      { value: 'need_space', label: 'Need space, then talk' },
      { value: 'avoid', label: 'Tend to avoid it' },
      { value: 'direct', label: 'Direct and to the point' },
    ],
    matchPhrase: () => `handle conflict in a similar way`,
  },
  {
    id: 'social_style', type: 'single', question: 'How social are you?',
    options: [
      { value: 'go_out', label: 'Love going out' },
      { value: 'stay_in', label: 'Prefer staying in' },
      { value: 'balance', label: 'A balance of both' },
    ],
    matchPhrase: (label) => `have a similar social style (${label.toLowerCase()})`,
  },
  {
    id: 'career_priority', type: 'single', question: 'How important is career/ambition to you?',
    options: [
      { value: 'very', label: 'Very important' },
      { value: 'balanced', label: 'Important, but balanced' },
      { value: 'low', label: 'Not a big priority' },
    ],
    matchPhrase: () => `feel similarly about career priorities`,
  },
  {
    id: 'communication_style', type: 'single', question: 'How do you like to communicate?',
    options: [
      { value: 'texting', label: 'Texting throughout the day' },
      { value: 'meaningful', label: 'A few meaningful messages' },
      { value: 'calls', label: 'Prefer calls' },
      { value: 'in_person', label: 'Prefer in-person' },
    ],
    matchPhrase: () => `like to communicate the same way`,
  },
  {
    id: 'personal_space', type: 'single', question: 'How much personal space do you need?',
    options: [
      { value: 'lots', label: 'I need lots of alone time' },
      { value: 'together', label: 'I like togetherness most of the time' },
      { value: 'balanced', label: 'Balanced' },
    ],
    matchPhrase: () => `need a similar amount of personal space`,
  },
  {
    id: 'lifestyle_pace', type: 'single', question: 'What best describes your lifestyle?',
    options: [
      { value: 'homebody', label: 'Homebody' },
      { value: 'adventurous', label: 'Adventurous / loves to travel' },
      { value: 'fitness', label: 'Fitness-focused' },
      { value: 'balanced', label: 'A balance of everything' },
    ],
    matchPhrase: (label) => `share a similar lifestyle (${label.toLowerCase()})`,
  },
  {
    id: 'dealbreakers', type: 'multi', question: 'Any deal-breakers for you?',
    options: [
      { value: 'smoking', label: 'Smoking' },
      { value: 'heavy_drinking', label: 'Heavy drinking' },
      { value: 'diff_religion', label: 'Different religion' },
      { value: 'long_distance', label: 'Long distance' },
      { value: 'no_kids_wanted', label: "Doesn't want kids" },
      { value: 'none', label: 'No dealbreakers for me' },
    ],
  },
];

function validateQuestionnaireAnswers(answers) {
  const clean = {};
  for (const q of QUESTIONNAIRE) {
    const val = answers[q.id];
    if (val === undefined || val === null) continue;
    const validValues = q.options.map(o => o.value);
    if (q.type === 'single') {
      if (validValues.includes(val)) clean[q.id] = val;
    } else if (q.type === 'multi') {
      if (Array.isArray(val)) clean[q.id] = val.filter(v => validValues.includes(v));
    }
  }
  return clean;
}

// Turns a raw questionnaire answers object (question id -> value/values) into
// a readable list of { question, answer } for display on someone's profile.
// Only answered questions are included; unanswered ones are skipped.
function buildQuizAnswersDisplay(questionnaire) {
  if (!questionnaire) return [];
  const out = [];
  for (const q of QUESTIONNAIRE) {
    const val = questionnaire[q.id];
    if (val === undefined || val === null) continue;
    if (q.type === 'multi') {
      if (!Array.isArray(val) || !val.length) continue;
      const labels = val.map(v => (q.options.find(o => o.value === v) || {}).label).filter(Boolean);
      if (!labels.length) continue;
      out.push({ question: q.question, answer: labels.join(', ') });
    } else {
      const opt = q.options.find(o => o.value === val);
      if (!opt) continue;
      out.push({ question: q.question, answer: opt.label });
    }
  }
  return out;
}

// Compares two people's answers into a 0-100 score plus a few plain-English
// reasons they'd get along. (Raw answers are shown separately via
// buildQuizAnswersDisplay/toPublicUser — this function itself never leaks
// one person's specific answer through the other's "reasons".)
function computeCompatibility(a, b) {
  if (!a || !b || !Object.keys(a).length || !Object.keys(b).length) return null;

  let totalWeight = 0;
  let matchWeight = 0;
  const reasons = [];

  for (const q of QUESTIONNAIRE) {
    const av = a[q.id];
    const bv = b[q.id];
    if (av === undefined || bv === undefined) continue;

    if (q.type === 'single') {
      totalWeight += 1;
      if (av === bv) {
        matchWeight += 1;
        const label = (q.options.find(o => o.value === av) || {}).label || av;
        reasons.push(`You both ${q.matchPhrase(label)}`);
      }
    } else if (q.type === 'multi') {
      const setA = new Set(Array.isArray(av) ? av : []);
      const setB = new Set(Array.isArray(bv) ? bv : []);
      if (!setA.size && !setB.size) continue;
      totalWeight += 1;
      const union = new Set([...setA, ...setB]);
      const intersection = [...setA].filter(x => setB.has(x));
      const overlap = union.size ? intersection.length / union.size : 1;
      matchWeight += overlap;
    }
  }

  if (totalWeight === 0) return null;
  const percent = Math.round((matchWeight / totalWeight) * 100);
  return { percent, reasons: reasons.slice(0, 4) };
}

module.exports = {
  QUESTIONNAIRE,
  buildQuizAnswersDisplay,
  computeCompatibility,
  validateQuestionnaireAnswers,
};
