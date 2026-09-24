// Abstention fixture: the call runs in shell mode, whose quoting and globbing semantics an
// argv list cannot reproduce, so the engine skips it as shell_pipeline_unsupported and no
// candidate should reach these checks.
const assert = require('node:assert/strict');
const path = require('node:path');
const childProcess = require('node:child_process');

const ATTACK = 'nightly; rm -rf /';
const CALLS = [];

childProcess.spawn = (file, args, options) => {
  // spawn(command, options) and spawn(file, args, options) are both in use.
  const settings = Array.isArray(args) ? options : args;
  CALLS.push({ shell: Boolean(settings && settings.shell), argv: file });
  return { on() {} };
};

function loadLocal() {
  CALLS.length = 0;
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  loadLocal().runBackup(ATTACK);
  if (CALLS[0].shell) {
    process.stderr.write('vulnerability present: the target reaches a shell command string\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  loadLocal().runBackup('nightly');
  assert.match(String(CALLS[0].argv), /tar -czf backup.tgz/);
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('this abstention fixture has no reference repair to compare\n'); process.exit(64); }
