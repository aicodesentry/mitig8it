const path = require('node:path');
const BASE = '/srv/uploads';

function resolveUpload(requested) {
  const baseDir = path.resolve(BASE);
  const target = path.resolve(baseDir, String(requested));
  if (target !== baseDir && !target.startsWith(baseDir + path.sep)) throw new Error('path escapes base directory');
  return target;
}

module.exports = { resolveUpload, BASE };
