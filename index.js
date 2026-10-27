// URL -> handler table. Add new endpoints here.
const { FRONTEND_HTML } = require('../frontend/index');
const { sendJSON } = require('../lib/http');
const { handleChangePassword, handleDeleteAccount, handleMe } = require('./account');
const { handleForgotPassword, handleLogin, handleLogout, handleRegister, handleResetPassword } = require('./auth');
const { handleDiscover, handleLike, handleLikesYou } = require('./discover');
const { handleGetMessages, handleMatches, handlePostMessage } = require('./matches');
const { handleAddGalleryPhoto, handleDeleteGalleryPhoto, handleReorderGalleryPhotos, handleReplaceGalleryPhoto, handleUploadPhoto } = require('./photos');
const { handleGetPrompts, handleGetQuestionnaire, handleSubmitQuestionnaire, handleUpdateProfile, handleUpdatePrompts } = require('./profile');
const { handleBlock, handleGetBlockedUsers, handleReport, handleUnblock } = require('./safety');
const { handleStream } = require('./stream');

async function dispatch(req, res, url, pathname) {
    if (pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(FRONTEND_HTML);
    }

    if (pathname === '/robots.txt' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('User-agent: *\nAllow: /\n');
    }

    if (pathname === '/api/health' && req.method === 'GET') {
      return sendJSON(res, 200, { ok: true, service: 'swing' });
    }

    if (pathname === '/api/register' && req.method === 'POST') {
      return await handleRegister(req, res);
    }
    if (pathname === '/api/login' && req.method === 'POST') {
      return await handleLogin(req, res);
    }
    if (pathname === '/api/forgot-password' && req.method === 'POST') {
      return await handleForgotPassword(req, res);
    }
    if (pathname === '/api/reset-password' && req.method === 'POST') {
      return await handleResetPassword(req, res);
    }
    if (pathname === '/api/me' && req.method === 'GET') {
      return await handleMe(req, res);
    }
    if (pathname === '/api/logout' && req.method === 'POST') {
      return await handleLogout(req, res);
    }
    if (pathname === '/api/change-password' && req.method === 'POST') {
      return await handleChangePassword(req, res);
    }
    if (pathname === '/api/account' && req.method === 'DELETE') {
      return await handleDeleteAccount(req, res);
    }
    if (pathname === '/api/stream' && req.method === 'GET') {
      return await handleStream(req, res);
    }
    if (pathname === '/api/profile' && req.method === 'PUT') {
      return await handleUpdateProfile(req, res);
    }
    if (pathname === '/api/profile/photo' && req.method === 'POST') {
      return await handleUploadPhoto(req, res);
    }
    const galleryMatch = pathname.match(/^\/api\/profile\/gallery(?:\/(\d+))?$/);
    if (galleryMatch && req.method === 'POST' && galleryMatch[1] === undefined) {
      return await handleAddGalleryPhoto(req, res);
    }
    if (galleryMatch && req.method === 'PUT' && galleryMatch[1] !== undefined) {
      return await handleReplaceGalleryPhoto(req, res, galleryMatch[1]);
    }
    if (galleryMatch && req.method === 'DELETE' && galleryMatch[1] !== undefined) {
      return await handleDeleteGalleryPhoto(req, res, galleryMatch[1]);
    }
    if (pathname === '/api/profile/gallery/reorder' && req.method === 'POST') {
      return await handleReorderGalleryPhotos(req, res);
    }
    if (pathname === '/api/questionnaire' && req.method === 'GET') {
      return await handleGetQuestionnaire(req, res);
    }
    if (pathname === '/api/questionnaire' && req.method === 'PUT') {
      return await handleSubmitQuestionnaire(req, res);
    }
    if (pathname === '/api/prompts' && req.method === 'GET') {
      return await handleGetPrompts(req, res);
    }
    if (pathname === '/api/prompts' && req.method === 'PUT') {
      return await handleUpdatePrompts(req, res);
    }
    if (pathname === '/api/discover' && req.method === 'GET') {
      return await handleDiscover(req, res, url.searchParams);
    }
    if (pathname === '/api/like' && req.method === 'POST') {
      return await handleLike(req, res);
    }
    if (pathname === '/api/likes-you' && req.method === 'GET') {
      return await handleLikesYou(req, res);
    }
    if (pathname === '/api/block' && req.method === 'POST') {
      return await handleBlock(req, res);
    }
    if (pathname === '/api/unblock' && req.method === 'POST') {
      return await handleUnblock(req, res);
    }
    if (pathname === '/api/blocked' && req.method === 'GET') {
      return await handleGetBlockedUsers(req, res);
    }
    if (pathname === '/api/report' && req.method === 'POST') {
      return await handleReport(req, res);
    }
    if (pathname === '/api/matches' && req.method === 'GET') {
      return await handleMatches(req, res);
    }

    const msgMatch = pathname.match(/^\/api\/messages\/([^/]+)$/);
    if (msgMatch && req.method === 'GET') {
      return await handleGetMessages(req, res, decodeURIComponent(msgMatch[1]));
    }
    if (msgMatch && req.method === 'POST') {
      return await handlePostMessage(req, res, decodeURIComponent(msgMatch[1]));
    }

    sendJSON(res, 404, { error: 'Not found' });
}

module.exports = {
  dispatch,
};
