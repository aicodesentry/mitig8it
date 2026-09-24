const fs = require('node:fs');
const path = require('node:path');

const DOCS = '/srv/docs';

function readDocument(name, callback) {
  const target = path.resolve(DOCS, name);
  if (target !== DOCS && !target.startsWith(`${DOCS}${path.sep}`)) {
    return callback(new Error('the requested document is outside the served directory'));
  }
  return fs.readFile(target, 'utf8', callback);
}

module.exports = { readDocument, DOCS };
