// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The child_process module is replaced with recorders before app.js is required, so nothing is
// ever executed: the checks read what the module asked to run, not a real process.
const assert = require('node:assert/strict');
const path = require('node:path');
const childProcess = require('node:child_process');

const ATTACK = 'timeout; touch /tmp/owned';
const LEGITIMATE = 'timeout';
const OUTPUT = 'app.log:12: timeout\n';
const CALLS = [];

childProcess.execSync = (command) => {
  CALLS.push({ shell: true, argv: String(command) });
  return OUTPUT;
};
childProcess.execFileSync = (file, args) => {
  CALLS.push({ shell: false, argv: [String(file), ...(args || []).map(String)] });
  return OUTPUT;
};

function load(target) {
  CALLS.length = 0;
  return require(target);
}

function loadLocal() {
  return load(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  loadLocal().searchLogs(ATTACK);
  const call = CALLS[0];
  if (call.shell || typeof call.argv === 'string') {
    process.stderr.write('vulnerability present: the argument reaches a shell command string\n');
    process.exit(1);
  }
  assert.ok(call.argv.includes(ATTACK));
  process.exit(0);
}

function behavior() {
  assert.equal(loadLocal().searchLogs(LEGITIMATE), OUTPUT);
  const rendered = JSON.stringify(CALLS[0].argv);
  assert.ok(rendered.includes('grep') && rendered.includes(LEGITIMATE) && rendered.includes('/var/log/app'));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  load(originalPath).searchLogs(ATTACK);
  assert.equal(CALLS[0].shell, true);
  assert.match(CALLS[0].argv, /touch \/tmp\/owned/);
  const repaired = load(repairedPath);
  assert.equal(repaired.searchLogs(ATTACK), OUTPUT);
  assert.deepEqual(CALLS[0], {
    shell: false,
    argv: ['grep', '-R', '--line-number', '--', ATTACK, '/var/log/app'],
  });
  assert.deepEqual(repaired.searchArguments(LEGITIMATE), ['-R', '--line-number', '--', LEGITIMATE, '/var/log/app']);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
