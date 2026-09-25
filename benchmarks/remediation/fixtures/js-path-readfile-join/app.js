const fs = require('node:fs');
const path = require('node:path');

const DOCS = '/srv/docs';

function readDocument(name, callback) {
  const target = path.join(DOCS, name);
  return fs.readFile(target, 'utf8', callback);
}

module.exports = { readDocument, DOCS };
