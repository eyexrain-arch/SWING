// Email / phone normalisation and validation.

// Sign-in supports either an email address or a phone number as the
// account identity. classifyIdentity() takes whatever the person typed
// into the single "email or phone" field and figures out which one it is
// and normalizes it, so the rest of the code can treat it uniformly.
function normalizeEmail(v) {
  return String(v || '').trim().toLowerCase();
}

function isValidEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function normalizePhone(v) {
  const raw = String(v || '').trim();
  const hasPlus = raw.startsWith('+');
  const digits = raw.replace(/\D/g, '');
  return digits ? (hasPlus ? '+' + digits : digits) : '';
}

function isValidPhone(v) {
  // Loose E.164-ish check: optional leading +, 7–15 digits total.
  return /^\+?[0-9]{7,15}$/.test(v);
}

function classifyIdentity(raw) {
  const value = String(raw || '').trim();
  if (!value) return null;
  if (value.includes('@')) {
    const email = normalizeEmail(value);
    return isValidEmail(email) ? { field: 'email', value: email } : null;
  }
  const phone = normalizePhone(value);
  return isValidPhone(phone) ? { field: 'phone', value: phone } : null;
}

module.exports = {
  classifyIdentity,
};
