/**
 * Low-level HTTP helpers: read a JSON body, send a JSON response.
 */

const { MAX_BODY_BYTES } = require('../config');

function readBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let body = '';
    let bytes = 0;
    let finished = false;
    req.on('data', chunk => {
      if (finished) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        finished = true;
        reject(new Error(`Request too large (max ${Math.floor(maxBytes / 1024)}KB)`));
        req.destroy();
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      if (finished) return;
      finished = true;
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (_) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', err => {
      if (!finished) { finished = true; reject(err); }
    });
  });
}

function sendJSON(res, status, obj, extraHeaders = {}) {
  const bodyStr = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(bodyStr),
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(bodyStr);
}

module.exports = {
  readBody,
  sendJSON,
};
