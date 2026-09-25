const path = require('node:path');

const ASSETS = '/srv/assets';
const THUMBS = '/srv/assets/thumbs';

// Two routes in this file send a file named by the request.
function sendAsset(req, res) {
  return res.sendFile(path.join(ASSETS, req.params.name));
}

function sendThumbnail(req, res) {
  return res.sendFile(path.join(THUMBS, req.query.name));
}

module.exports = { sendAsset, sendThumbnail, ASSETS, THUMBS };
