// Small shared helpers.

function pairKey(id1, id2) {
  return [id1, id2].sort().join('::');
}

function parseTags(tags) {
  if (Array.isArray(tags)) return tags;
  if (tags) return String(tags).split(',').map(t => t.trim()).filter(Boolean);
  return [];
}

module.exports = {
  pairKey,
  parseTags,
};
