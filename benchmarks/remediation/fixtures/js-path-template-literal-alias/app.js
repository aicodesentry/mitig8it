// The module binds node:path under a name of its own and builds the path by interpolation
// rather than with a join. A repair uses the name the module already has.
const fs = require('node:fs');
const nodePath = require('node:path');

const DOCS = '/srv/docs';

function documentExtension(name) {
  return nodePath.extname(name);
}

function readDocument(name, callback) {
  return fs.readFile(`${DOCS}/${name}`, 'utf8', callback);
}

module.exports = { readDocument, documentExtension, DOCS };
