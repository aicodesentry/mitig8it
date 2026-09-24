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

// A repaired helper refuses an escaping path one of two ways, and both are correct: it throws,
// or it returns a value that is not a path. A returned path that leaves the base directory is
// the vulnerability. `resolve` reports which happened so each mode can assert what it needs.
function resolve(module, name) {
  try {
    return { threw: false, value: module.resolveUpload(name) };
  } catch (error) {
    return { threw: true, error };
  }
}

const contained = (outcome) => outcome.threw || typeof outcome.value !== 'string' || outcome.value.startsWith('/srv/uploads/');

function exploit() {
  if (!contained(resolve(loadLocal(), ATTACK))) {
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
  assert.ok(contained(resolve(repaired, ATTACK)), 'the repair still returns a path outside the base directory');
  assert.equal(repaired.resolveUpload(LEGITIMATE), '/srv/uploads/avatars/user.png');
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
