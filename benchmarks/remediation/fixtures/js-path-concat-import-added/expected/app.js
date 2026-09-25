// The document name is concatenated onto the served directory. The module never requires
// node:path, so a repair has to bring the import with it.
const path = require('node:path');
const fs = require('node:fs');

const DOCS = '/srv/docs';

function readDocument(name, callback) {
  const baseDir = path.resolve(String(DOCS) + '/');
  const target = path.resolve(baseDir, String(name));
  if (target !== baseDir && !target.startsWith(baseDir + path.sep)) return callback(new Error('path escapes base directory'));
  return fs.readFile(target, 'utf8', callback);
}

module.exports = { readDocument, DOCS };
