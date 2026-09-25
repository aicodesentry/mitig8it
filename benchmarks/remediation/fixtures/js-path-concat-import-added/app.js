// The document name is concatenated onto the served directory. The module never requires
// node:path, so a repair has to bring the import with it.
const fs = require('node:fs');

const DOCS = '/srv/docs';

function readDocument(name, callback) {
  return fs.readFile(DOCS + '/' + name, 'utf8', callback);
}

module.exports = { readDocument, DOCS };
