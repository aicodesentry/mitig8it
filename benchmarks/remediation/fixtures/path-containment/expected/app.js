const path = require('node:path');
const BASE = '/srv/uploads';

function resolveUpload(requested) {
  const target = path.resolve(BASE, requested);
  return target.startsWith(`${BASE}${path.sep}`) ? target : null;
}

module.exports = { resolveUpload, BASE };
