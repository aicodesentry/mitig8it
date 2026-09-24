const { spawn } = require('node:child_process');

function pingHost(host) {
  return spawn('ping', ['-c', '1', '--', host]);
}

module.exports = { pingHost };
