const { spawn } = require('node:child_process');

function runBackup(target) {
  return spawn('tar -czf backup.tgz ' + target, { shell: true });
}

module.exports = { runBackup };
