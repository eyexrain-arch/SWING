/**
 * Password hashing (scrypt, with legacy PBKDF2 verification) and password rules.
 */

const crypto = require('crypto');

// crypto.scryptSync/pbkdf2Sync block Node's single-threaded event loop for
// their entire runtime. That's a big deal specifically for login/register:
// under any concurrent load (two people signing in around the same time,
// a double-clicked submit button, etc.) one hash computation stalls every
// other in-flight request on the server — including unrelated ones — for
// however long scrypt takes on the host's CPU. On a resource-constrained
// instance that can be long enough to trip the platform's request/health
// check timeout, which looks to users like an intermittent "Internal
// server error" or a hard "Load failed" with no clean response at all,
// concentrated on login/signup since that's where hashing happens. Using
// the async (threadpool-backed) variants keeps the event loop free.
const { promisify } = require('util');
const scryptAsync = promisify(crypto.scrypt);
const pbkdf2Async = promisify(crypto.pbkdf2);

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
  return { salt: salt.toString('hex'), hash: `scrypt$${derived.toString('hex')}` };
}

async function verifyPassword(password, salt, storedHash) {
  try {
    // Existing accounts used PBKDF2. Keep them working once, then transparently
    // upgrade them to scrypt on successful login.
    if (String(storedHash || '').startsWith('scrypt$')) {
      const hashBuf = Buffer.from(storedHash.slice(7), 'hex');
      const check = await scryptAsync(password, Buffer.from(salt, 'hex'), 64, { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 });
      return check.length === hashBuf.length && crypto.timingSafeEqual(check, hashBuf);
    }
    const check = await pbkdf2Async(password, salt, 100000, 64, 'sha512');
    const hashBuf = Buffer.from(storedHash, 'hex');
    return check.length === hashBuf.length && crypto.timingSafeEqual(check, hashBuf);
  } catch (_) {
    return false;
  }
}

// Password rule: 6+ chars, must contain at least one letter and one digit
// (case optional). Applied on register and on password reset.
function isValidPassword(pw) {
  return typeof pw === 'string' && pw.length >= 6 && pw.length <= 128
    && /[A-Za-z]/.test(pw) && /[0-9]/.test(pw);
}

module.exports = {
  hashPassword,
  isValidPassword,
  verifyPassword,
};
