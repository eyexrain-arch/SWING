/**
 * Serves the frontend files from /public (index.html, /css, /js).
 */

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

// Returns true if the request was handled (a file was served), false otherwise
// so the router can carry on to the API routes.
async function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;
  if (pathname.startsWith('/api/')) return false;

  let relPath;
  try {
    relPath = decodeURIComponent(pathname === '/' ? '/index.html' : pathname);
  } catch (_) {
    return false;
  }

  // Block path traversal (../) and anything that resolves outside /public.
  const filePath = path.normalize(path.join(PUBLIC_DIR, relPath));
  if (filePath !== PUBLIC_DIR && !filePath.startsWith(PUBLIC_DIR + path.sep)) return false;

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext];
  if (!contentType) return false;

  let data;
  try {
    data = await fs.promises.readFile(filePath);
  } catch (_) {
    return false;
  }

  res.writeHead(200, {
    'Content-Type': contentType,
    'Content-Length': data.length,
    // HTML must always be revalidated; assets can be cached briefly.
    'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=300',
  });
  res.end(req.method === 'HEAD' ? undefined : data);
  return true;
}


module.exports = {
  serveStatic,
};
