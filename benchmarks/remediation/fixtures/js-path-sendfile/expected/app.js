const path = require('node:path');

const ASSETS = '/srv/assets';
const THUMBS = '/srv/assets/thumbs';

function contain(base, name) {
  const target = path.resolve(base, String(name));
  return target === base || target.startsWith(`${base}${path.sep}`) ? target : null;
}

// Two routes in this file send a file named by the request.
function sendAsset(req, res) {
  const target = contain(ASSETS, req.params.name);
  return target === null ? res.status(400).end() : res.sendFile(target);
}

function sendThumbnail(req, res) {
  const target = contain(THUMBS, req.query.name);
  return target === null ? res.status(400).end() : res.sendFile(target);
}

module.exports = { sendAsset, sendThumbnail, ASSETS, THUMBS };
