const path = require('node:path');
const BASE = '/srv/uploads';

function resolveUpload(requested) {
  return path.join(BASE, requested);
}

module.exports = { resolveUpload, BASE };
