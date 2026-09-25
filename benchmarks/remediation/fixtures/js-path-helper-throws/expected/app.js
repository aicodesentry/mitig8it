const fs = require('node:fs');
const path = require('node:path');

const ATTACHMENTS = '/srv/attachments';

function readAttachment(name) {
  const baseDir = path.resolve(ATTACHMENTS);
  const target = path.resolve(baseDir, String(name));
  if (target !== baseDir && !target.startsWith(baseDir + path.sep)) throw new Error('path escapes base directory');
  return fs.readFileSync(target, 'utf8');
}

module.exports = { readAttachment, ATTACHMENTS };
