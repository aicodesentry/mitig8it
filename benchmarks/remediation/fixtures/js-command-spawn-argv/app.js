const { spawn } = require('node:child_process');

function pingHost(host) {
  const command = 'ping -c 1 ' + host;
  return spawn('sh', ['-c', command]);
}

module.exports = { pingHost };
