// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The child_process module is replaced with recorders before app.js is required, so nothing is
// ever executed: the checks read what the module asked to run, not a real process.
const assert = require('node:assert/strict');
const path = require('node:path');
const childProcess = require('node:child_process');

const ATTACK = 'amina; touch /tmp/owned';
const LEGITIMATE = 'amina';
const CALLS = [];

childProcess.exec = (command, callback) => {
  CALLS.push({ shell: true, argv: String(command) });
  if (typeof callback === 'function') callback(null, 'log output', '');
  return 'child';
};
childProcess.execFile = (file, args, callback) => {
  CALLS.push({ shell: false, argv: [String(file), ...(args || []).map(String)] });
  if (typeof callback === 'function') callback(null, 'log output', '');
  return 'child';
};

function load(target) {
  CALLS.length = 0;
  return require(target);
}

function loadLocal() {
  return load(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  loadLocal().fetchAuthorLog(ATTACK, () => {});
  const call = CALLS[0];
  if (call.shell || typeof call.argv === 'string') {
    process.stderr.write('vulnerability present: the argument reaches a shell command string\n');
    process.exit(1);
  }
  assert.ok(call.argv.includes(ATTACK));
  process.exit(0);
}

function behavior() {
  let received = null;
  loadLocal().fetchAuthorLog(LEGITIMATE, (error, stdout) => { received = stdout; });
  const rendered = JSON.stringify(CALLS[0].argv);
  assert.ok(rendered.includes('git') && rendered.includes('log') && rendered.includes(LEGITIMATE));
  assert.equal(received, 'log output');
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  load(originalPath).fetchAuthorLog(ATTACK, () => {});
  assert.equal(CALLS[0].shell, true);
  assert.match(CALLS[0].argv, /touch \/tmp\/owned/);
  load(repairedPath).fetchAuthorLog(ATTACK, () => {});
  assert.deepEqual(CALLS[0], { shell: false, argv: ['git', 'log', '--author', ATTACK, '--oneline', '-n', '20'] });
  load(repairedPath).fetchAuthorLog(LEGITIMATE, () => {});
  assert.deepEqual(CALLS[0].argv, ['git', 'log', '--author', LEGITIMATE, '--oneline', '-n', '20']);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
