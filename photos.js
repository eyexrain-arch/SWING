// Profile photo and My Vibes gallery endpoints.
const { MAX_TEXT_BYTES } = require('../config');
const { readBody, sendJSON } = require('../lib/http');
const { decodeImageDataUrl, removeFromPhotosBucket, uploadToPhotosBucket } = require('../lib/photoStorage');
const { getUserById, requireAuth, toOwnUser } = require('../lib/users');
const { supabase } = require('../supabase');

async function handleUploadPhoto(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 413, { error: err.message });
  }

  const decoded = decodeImageDataUrl(body.photo);
  if (decoded.error) return sendJSON(res, 400, { error: decoded.error });

  const photoUrl = await uploadToPhotosBucket(user.id, 'profile', decoded);

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ photo_url: photoUrl }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

async function handleAddGalleryPhoto(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const galleryUrls = user.gallery_urls || [];
  if (galleryUrls.length >= 3) {
    return sendJSON(res, 400, { error: 'You can upload up to 3 My Vibes photos.' });
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 413, { error: err.message });
  }

  const decoded = decodeImageDataUrl(body.photo);
  if (decoded.error) return sendJSON(res, 400, { error: decoded.error });

  const photoUrl = await uploadToPhotosBucket(user.id, 'vibes', decoded);

  // Re-read the row right before writing so two near-simultaneous uploads
  // can't both slip past the length check above (still not fully atomic
  // without the DB CHECK constraint noted above, but this narrows the gap).
  const fresh = await getUserById(user.id);
  const freshUrls = fresh.gallery_urls || [];
  if (freshUrls.length >= 3) {
    await removeFromPhotosBucket(photoUrl);
    return sendJSON(res, 400, { error: 'You can upload up to 3 My Vibes photos.' });
  }
  const newUrls = [...freshUrls, photoUrl];

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ gallery_urls: newUrls }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

async function handleReplaceGalleryPhoto(req, res, indexStr) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const index = parseInt(indexStr, 10);
  if (!Number.isInteger(index) || index < 0 || index > 2) {
    return sendJSON(res, 400, { error: 'Invalid photo slot' });
  }
  const galleryUrls = user.gallery_urls || [];
  if (index >= galleryUrls.length) {
    return sendJSON(res, 400, { error: 'That photo slot is empty' });
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return sendJSON(res, 413, { error: err.message });
  }

  const decoded = decodeImageDataUrl(body.photo);
  if (decoded.error) return sendJSON(res, 400, { error: decoded.error });

  const photoUrl = await uploadToPhotosBucket(user.id, 'vibes', decoded);

  const oldUrl = galleryUrls[index];
  const newUrls = galleryUrls.slice();
  newUrls[index] = photoUrl;

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ gallery_urls: newUrls }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  await removeFromPhotosBucket(oldUrl);
  sendJSON(res, 200, { user: toOwnUser(updated) });
}

async function handleDeleteGalleryPhoto(req, res, indexStr) {
  const user = await requireAuth(req, res);
  if (!user) return;

  const index = parseInt(indexStr, 10);
  if (!Number.isInteger(index) || index < 0 || index > 2) {
    return sendJSON(res, 400, { error: 'Invalid photo slot' });
  }
  const galleryUrls = user.gallery_urls || [];
  if (index >= galleryUrls.length) {
    return sendJSON(res, 400, { error: 'That photo slot is already empty' });
  }

  const removedUrl = galleryUrls[index];
  const newUrls = galleryUrls.slice();
  newUrls.splice(index, 1);

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ gallery_urls: newUrls }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  await removeFromPhotosBucket(removedUrl);
  sendJSON(res, 200, { user: toOwnUser(updated) });
}

async function handleReorderGalleryPhotos(req, res) {
  const user = await requireAuth(req, res);
  if (!user) return;

  let body;
  try {
    body = await readBody(req, MAX_TEXT_BYTES);
  } catch (err) {
    return sendJSON(res, 413, { error: err.message });
  }

  const galleryUrls = user.gallery_urls || [];
  const from = parseInt(body.from, 10);
  const to = parseInt(body.to, 10);
  if (
    !Number.isInteger(from) || !Number.isInteger(to) ||
    from < 0 || from >= galleryUrls.length || to < 0 || to >= galleryUrls.length
  ) {
    return sendJSON(res, 400, { error: 'Invalid photo positions' });
  }

  const newUrls = galleryUrls.slice();
  const [moved] = newUrls.splice(from, 1);
  newUrls.splice(to, 0, moved);

  const { data: updated, error: updateErr } = await supabase
    .from('users').update({ gallery_urls: newUrls }).eq('id', user.id).select().single();
  if (updateErr) throw updateErr;

  sendJSON(res, 200, { user: toOwnUser(updated) });
}

module.exports = {
  handleUploadPhoto,
  handleAddGalleryPhoto,
  handleReplaceGalleryPhoto,
  handleDeleteGalleryPhoto,
  handleReorderGalleryPhotos,
};
