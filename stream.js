// GET /api/stream (live updates).
const { getAuthToken } = require('../lib/http');
const { addSseClient, removeSseClient } = require('../lib/sse');
const { getUserByToken } = require('../lib/users');

// Browsers' built-in EventSource API can't send custom headers, so the
// live-updates connection authenticates via a token in the URL instead.
async function handleStream(req, res) {
  const token = getAuthToken(req);
  const user = token ? await getUserByToken(token) : null;
  if (!user) {
    res.writeHead(401, { 'Content-Type': 'text/plain' });
    return res.end('Not authenticated');
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });
  res.write('retry: 3000\n\n');

  addSseClient(user.id, res);

  const heartbeat = setInterval(() => {
    try { res.write(': keep-alive\n\n'); } catch (e) { /* ignore */ }
  }, 20000);

  req.on('close', () => {
    clearInterval(heartbeat);
    removeSseClient(user.id, res);
  });
}

module.exports = {
  handleStream,
};
