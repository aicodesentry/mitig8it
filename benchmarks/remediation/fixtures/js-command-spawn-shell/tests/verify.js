// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The child_process module is replaced with a recorder before app.js is required, so nothing is
// ever executed: the checks read what the module asked to run, not a real process. The command
// this fixture builds carries no pipeline, redirection, or separator of its own, so the shell is
// the only thing putting the target within reach of one.
const assert = require('node:assert/strict');
const path = require('node:path');
const childProcess = require('node:child_process');

const ATTACK = 'nightly; rm -rf /';
const LEGITIMATE = 'nightly';
const CALLS = [];

childProcess.spawn = (file, args, options) => {
  // spawn(command, options) and spawn(file, args, options) are both in use.
  const settings = Array.isArray(args) ? options : args;
  const argv = [String(file), ...(Array.isArray(args) ? args : []).map(String)];
  CALLS.push({ shell: Boolean(settings && settings.shell), argv });
  return { on() {} };
};

function load(target) {
  CALLS.length = 0;
  return require(target);
}

function loadLocal() {
  return load(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  loadLocal().runBackup(ATTACK);
  const call = CALLS[0];
  if (call.shell) {
    process.stderr.write('vulnerability present: the backup target reaches a shell command string\n');
    process.exit(1);
  }
  assert.ok(call.argv.includes(ATTACK));
  process.exit(0);
}

function behavior() {
  loadLocal().runBackup(LEGITIMATE);
  const rendered = JSON.stringify(CALLS[0].argv);
  assert.ok(rendered.includes('tar') && rendered.includes('-czf') && rendered.includes('backup.tgz'));
  assert.ok(rendered.includes(LEGITIMATE));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  load(originalPath).runBackup(ATTACK);
  assert.equal(CALLS[0].shell, true);
  assert.match(JSON.stringify(CALLS[0].argv), /rm -rf \//);
  load(repairedPath).runBackup(ATTACK);
  assert.deepEqual(CALLS[0], { shell: false, argv: ['tar', '-czf', 'backup.tgz', ATTACK] });
  load(repairedPath).runBackup(LEGITIMATE);
  assert.deepEqual(CALLS[0].argv, ['tar', '-czf', 'backup.tgz', LEGITIMATE]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
