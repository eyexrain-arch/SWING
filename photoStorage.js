/**
 * Photo validation and Supabase Storage upload/remove helpers.
 */

const { PHOTOS_BUCKET } = require('../config');
const { supabase } = require('../supabase');

// ---------- Photo upload ----------
// "My Vibes" gallery: up to 3 extra photos per user, stored in the
// users.gallery_urls column (jsonb array of public Storage URLs, default
// '[]'). This column isn't in the original setup SQL — add it once via:
//   ALTER TABLE users ADD COLUMN gallery_urls jsonb NOT NULL DEFAULT '[]';
// The 3-photo cap is enforced here in the handlers below, but that only
// protects against a single request at a time. For a hard guarantee against
// two simultaneous uploads sneaking past the limit, also add:
//   ALTER TABLE users ADD CONSTRAINT gallery_urls_max_3
//     CHECK (jsonb_array_length(gallery_urls) <= 3);

const ALLOWED_IMAGE_TYPES = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
};

function hasValidImageSignature(buffer, mimeType) {
  if (mimeType === 'image/jpeg') return buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  if (mimeType === 'image/png') return buffer.length >= 8 && buffer.slice(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
  if (mimeType === 'image/gif') return buffer.length >= 6 && (buffer.slice(0, 6).toString() === 'GIF87a' || buffer.slice(0, 6).toString() === 'GIF89a');
  if (mimeType === 'image/webp') return buffer.length >= 12 && buffer.slice(0, 4).toString() === 'RIFF' && buffer.slice(8, 12).toString() === 'WEBP';
  return false;
}

// Shared by the single profile photo and the My Vibes gallery photos.
function decodeImageDataUrl(photo) {
  if (!photo || typeof photo !== 'string') return { error: 'photo (base64 data URL) is required' };
  const match = photo.match(/^data:(image\/[a-zA-Z+]+);base64,(.+)$/);
  if (!match) return { error: 'photo must be a base64 image data URL' };
  const mimeType = match[1];
  const base64Data = match[2];
  const ext = ALLOWED_IMAGE_TYPES[mimeType];
  if (!ext) return { error: 'Unsupported image type. Use JPEG, PNG, WEBP, or GIF.' };
  const buffer = Buffer.from(base64Data, 'base64');
  if (buffer.length > 5 * 1024 * 1024) return { error: 'Image too large (max 5MB)' };
  if (!hasValidImageSignature(buffer, mimeType)) return { error: 'Invalid image data' };
  return { mimeType, ext, buffer };
}

async function uploadToPhotosBucket(userId, tag, decoded) {
  const filename = `${userId}-${tag}-${Date.now()}.${decoded.ext}`;
  const { error: uploadErr } = await supabase.storage
    .from(PHOTOS_BUCKET)
    .upload(filename, decoded.buffer, { contentType: decoded.mimeType, upsert: true });
  if (uploadErr) throw uploadErr;
  const { data: urlData } = supabase.storage.from(PHOTOS_BUCKET).getPublicUrl(filename);
  return urlData.publicUrl;
}

// Best-effort cleanup of a replaced/deleted gallery photo. Never throws —
// a failure here shouldn't fail the request, it just leaves an orphaned
// file in Storage.
async function removeFromPhotosBucket(url) {
  if (!url) return;
  try {
    const marker = `/object/public/${PHOTOS_BUCKET}/`;
    const idx = url.indexOf(marker);
    if (idx === -1) return;
    const path = url.slice(idx + marker.length);
    await supabase.storage.from(PHOTOS_BUCKET).remove([path]);
  } catch (e) {
    // ignore — orphaned storage object, not worth failing the request over
  }
}

module.exports = {
  decodeImageDataUrl,
  removeFromPhotosBucket,
  uploadToPhotosBucket,
};
