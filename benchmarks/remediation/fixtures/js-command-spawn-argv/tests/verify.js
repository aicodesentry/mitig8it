// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The child_process module is replaced with a recorder before app.js is required, so nothing is
// ever executed: the checks read what the module asked to run, not a real process.
const assert = require('node:assert/strict');
const path = require('node:path');
const childProcess = require('node:child_process');

const ATTACK = 'example.com; touch /tmp/owned';
const LEGITIMATE = 'example.com';
const SHELLS = ['sh', 'bash', 'zsh', '/bin/sh', '/bin/bash'];
const CALLS = [];

childProcess.spawn = (file, args, options) => {
  const argv = [String(file), ...(args || []).map(String)];
  // `-c` alone is not a shell marker: `ping -c 1` is an ordinary argument list.
  const shell = Boolean(options && options.shell) || SHELLS.includes(argv[0]);
  CALLS.push({ shell, argv });
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
  loadLocal().pingHost(ATTACK);
  const call = CALLS[0];
  if (call.shell) {
    process.stderr.write('vulnerability present: the host name reaches a shell command string\n');
    process.exit(1);
  }
  assert.ok(call.argv.includes(ATTACK));
  process.exit(0);
}

function behavior() {
  loadLocal().pingHost(LEGITIMATE);
  const rendered = JSON.stringify(CALLS[0].argv);
  assert.ok(rendered.includes('ping') && rendered.includes(LEGITIMATE));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  load(originalPath).pingHost(ATTACK);
  assert.equal(CALLS[0].shell, true);
  assert.match(JSON.stringify(CALLS[0].argv), /touch \/tmp\/owned/);
  load(repairedPath).pingHost(ATTACK);
  assert.deepEqual(CALLS[0], { shell: false, argv: ['ping', '-c', '1', '--', ATTACK] });
  load(repairedPath).pingHost(LEGITIMATE);
  assert.deepEqual(CALLS[0].argv, ['ping', '-c', '1', '--', LEGITIMATE]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
