const { exec } = require('node:child_process');

function fetchAuthorLog(author, callback) {
  return exec(`git log --author=${author} --oneline -n 20`, callback);
}

module.exports = { fetchAuthorLog };
