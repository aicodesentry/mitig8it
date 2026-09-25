// The module does not require node:path, and it already calls something else `path`. The
// concatenation is a repairable shape, but an inserted `const path = require('node:path')`
// would be shadowed by this binding at the very line a repair rewrites, so the service refuses
// rather than writing a repair whose `path.resolve` would read a string.
const fs = require('node:fs');

const path = '/srv/docs';

function readDocument(name, callback) {
  return fs.readFile(path + '/' + name, 'utf8', callback);
}

module.exports = { readDocument, path };
