const { execFile } = require('node:child_process');

function fetchAuthorLog(author, callback) {
  return execFile('git', ['log', '--author', author, '--oneline', '-n', '20'], callback);
}

module.exports = { fetchAuthorLog };
