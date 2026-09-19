// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = 'report.txt; touch /tmp/owned';
const LEGITIMATE = 'report.txt';

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  const command = loadLocal().buildArchiveCommand(ATTACK);
  const shells = ['sh', 'bash', 'zsh', '/bin/sh', '/bin/bash'];
  // The vulnerability is the untrusted name reaching a shell, not the name's own text: a
  // fixed argv that carries the exact string as one argument is the repaired behavior.
  const shellInvoked = shells.includes(command[0]) || command.includes('-c');
  if (shellInvoked) {
    process.stderr.write('vulnerability present: the argument reaches a shell command string\n');
    process.exit(1);
  }
  assert.ok(command.includes(ATTACK));
  process.exit(0);
}

function behavior() {
  const command = loadLocal().buildArchiveCommand(LEGITIMATE);
  const rendered = JSON.stringify(command);
  assert.ok(rendered.includes('archive.tar'));
  assert.ok(rendered.includes(LEGITIMATE));
  assert.ok(rendered.includes('tar'));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = require(originalPath).buildArchiveCommand(ATTACK);
  const repaired = require(repairedPath).buildArchiveCommand(ATTACK);
  const legitimate = require(repairedPath).buildArchiveCommand(LEGITIMATE);
  assert.equal(original[0], 'sh');
  assert.match(original[2], /touch \/tmp\/owned/);
  assert.deepEqual(repaired, ['tar', '-cf', 'archive.tar', '--', ATTACK]);
  assert.deepEqual(legitimate, ['tar', '-cf', 'archive.tar', '--', LEGITIMATE]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
