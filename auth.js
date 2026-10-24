/**
 * Authentication guard for protected routes.
 */

const { getAuthToken } = require('../lib/cookies');
const { sendJSON } = require('../lib/http');
const { getUserByToken } = require('../services/users');

async function requireAuth(req, res) {
  const token = getAuthToken(req);
  const user = token ? await getUserByToken(token) : null;
  if (!user) {
    sendJSON(res, 401, { error: 'Not authenticated' });
    return null;
  }
  return user;
}

module.exports = {
  requireAuth,
};
