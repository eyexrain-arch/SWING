// Profile prompts library and validation.

// A short list of preset prompts a user can pick and answer (Hinge-style),
// stored in users.prompts (jsonb array of { question, answer }). See the
// column-add note near toPublicUser() above.
const PROMPT_LIBRARY = [
  'My simple pleasures are...',
  'Together, we could...',
  'The way to win me over is...',
  'A life goal of mine is...',
  'My most controversial opinion is...',
  'A typical Sunday for me looks like...',
  "I'm looking for someone who...",
  'Two truths and a lie about me...',
];

const MAX_PROMPTS = 3;

const MAX_PROMPT_ANSWER_LEN = 300;

function validatePrompts(input) {
  if (!Array.isArray(input)) return [];
  const seen = new Set();
  const clean = [];
  for (const p of input) {
    if (!p || typeof p !== 'object') continue;
    const question = String(p.question || '').trim();
    const answer = String(p.answer || '').trim().slice(0, MAX_PROMPT_ANSWER_LEN);
    if (!PROMPT_LIBRARY.includes(question) || !answer || seen.has(question)) continue;
    seen.add(question);
    clean.push({ question, answer });
    if (clean.length >= MAX_PROMPTS) break;
  }
  return clean;
}

module.exports = {
  PROMPT_LIBRARY,
  validatePrompts,
};
