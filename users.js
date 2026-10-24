/**
 * User lookups.
 */

const { supabase } = require('../supabase');
const { getSessionUserId } = require('./sessions');

async function getUserById(id) {
  const { data, error } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data;
}

async function getUserByToken(token) {
  const userId = await getSessionUserId(token);
  if (!userId) return null;
  return await getUserById(userId);
}

module.exports = {
  getUserById,
  getUserByToken,
};
