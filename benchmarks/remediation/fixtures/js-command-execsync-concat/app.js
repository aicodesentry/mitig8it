const { execSync } = require('node:child_process');

// The argument string is built by a helper, so the repair has to change both functions.
function searchArguments(term) {
  return '-R --line-number ' + term + ' /var/log/app';
}

function searchLogs(term) {
  return execSync('grep ' + searchArguments(term), { encoding: 'utf8' });
}

module.exports = { searchLogs, searchArguments };
