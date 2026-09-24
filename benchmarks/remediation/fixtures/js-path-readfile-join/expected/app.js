const fs = require('node:fs');
const path = require('node:path');

const DOCS = '/srv/docs';

function readDocument(name, callback) {
  const baseDir = path.resolve(DOCS);
  const target = path.resolve(baseDir, String(name));
  if (target !== baseDir && !target.startsWith(baseDir + path.sep)) return callback(new Error('path escapes base directory'));
  return fs.readFile(target, 'utf8', callback);
}

module.exports = { readDocument, DOCS };
