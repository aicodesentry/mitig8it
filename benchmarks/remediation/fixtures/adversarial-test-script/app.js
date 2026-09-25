const path = require('node:path');

const MEDIA = '/srv/media';

function resolveMedia(requested) {
  const target = path.resolve(MEDIA, requested);
  return target.startsWith(`${MEDIA}${path.sep}`) ? target : null;
}

module.exports = { resolveMedia, MEDIA };
