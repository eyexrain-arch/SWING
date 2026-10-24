/**
 * Live updates (Server-Sent Events) connection registry.
 */


// ---------- Live updates (Server-Sent Events) ----------
// Maps a userId to the set of open SSE connections for that person
// (they might have the app open on more than one device/tab at once).
const sseClients = new Map(); // userId -> Set<res>

function addSseClient(userId, res) {
  if (!sseClients.has(userId)) sseClients.set(userId, new Set());
  sseClients.get(userId).add(res);
}

function removeSseClient(userId, res) {
  const set = sseClients.get(userId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) sseClients.delete(userId);
}

function pushEventToUser(userId, eventName, data) {
  const set = sseClients.get(userId);
  if (!set || !set.size) return;
  const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const clientRes of set) {
    try {
      clientRes.write(payload);
    } catch (e) {
      // connection likely already gone; it'll be cleaned up by its own 'close' handler
    }
  }
}

module.exports = {
  addSseClient,
  pushEventToUser,
  removeSseClient,
};
