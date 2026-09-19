// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = '../../etc/passwd';
const LEGITIMATE = 'avatars/user.png';

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  const resolved = loadLocal().resolveUpload(ATTACK);
  if (typeof resolved === 'string' && !resolved.startsWith('/srv/uploads/')) {
    process.stderr.write('vulnerability present: the resolved path escapes the base directory\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const resolved = loadLocal().resolveUpload(LEGITIMATE);
  assert.equal(resolved, '/srv/uploads/avatars/user.png');
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = require(originalPath);
  const repaired = require(repairedPath);
  assert.equal(original.resolveUpload(ATTACK), '/etc/passwd');
  assert.equal(repaired.resolveUpload(ATTACK), null);
  assert.equal(repaired.resolveUpload(LEGITIMATE), '/srv/uploads/avatars/user.png');
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
