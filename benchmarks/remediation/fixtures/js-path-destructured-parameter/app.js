// The request fields arrive destructured at the signature, so the name the sink reads is a
// member of the first parameter rather than the parameter itself.
const fs = require('node:fs');
const path = require('node:path');

const DOCS = '/srv/docs';

function readDocument({ name }, callback) {
  const target = path.join(DOCS, name);
  return fs.readFile(target, 'utf8', callback);
}

module.exports = { readDocument, DOCS };
