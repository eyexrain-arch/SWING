/**
 * Profile prompts.
 */

const { MAX_TEXT_BYTES } = require('../config');
const { supabase } = require('../supabase');
const { readBody, sendJSON } = require('../lib/http');
const { toOwnUser } = require('../services/serializers');
const { requireAuth } = require('../middleware/auth');

// ---------- Profile prompts ("Prompts/Questions") ----------
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

async function handleGetPrompts(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  sendJSON(res, 200, { library: PROMPT_LIBRARY, answers: user.prompts || [] });
}

async function handleUpdatePrompts(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;
  const body = await readBody(req, MAX_TEXT_BYTES);
  const clean = validatePrompts(body.prompts);

  const { data: updated, error } = await supabase
    .from('users').update({ prompts: clean }).eq('id', user.id).select().single();
  if (error) throw error;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

module.exports = {
  handleGetPrompts,
  handleUpdatePrompts,
};
