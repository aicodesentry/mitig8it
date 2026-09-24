const { spawn } = require('node:child_process');

function runBackup(target) {
  return spawn('tar', ['-czf', 'backup.tgz', target]);
}

module.exports = { runBackup };
