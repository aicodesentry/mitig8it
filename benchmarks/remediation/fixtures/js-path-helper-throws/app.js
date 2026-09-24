const fs = require('node:fs');
const path = require('node:path');

const ATTACHMENTS = '/srv/attachments';

function readAttachment(name) {
  const target = path.join(ATTACHMENTS, name);
  return fs.readFileSync(target, 'utf8');
}

module.exports = { readAttachment, ATTACHMENTS };
