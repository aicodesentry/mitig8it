// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = "x' OR '1'='1";
const LEGITIMATE = 'person@example.com';

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  const result = loadLocal().buildUserLookup(ATTACK);
  const interpolated = typeof result.text === 'string' && result.text.includes(ATTACK);
  if (interpolated) {
    process.stderr.write('vulnerability present: untrusted input is interpolated into SQL text\n');
    process.exit(1);
  }
  assert.ok(Array.isArray(result.values) && result.values.includes(ATTACK));
  process.exit(0);
}

function behavior() {
  const result = loadLocal().buildUserLookup(LEGITIMATE);
  assert.match(result.text, /FROM users/i);
  assert.ok(result.text.includes(LEGITIMATE) || (Array.isArray(result.values) && result.values.includes(LEGITIMATE)));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = require(originalPath).buildUserLookup(ATTACK);
  const repaired = require(repairedPath).buildUserLookup(ATTACK);
  const legitimate = require(repairedPath).buildUserLookup(LEGITIMATE);
  assert.match(original.text, /OR '1'='1/);
  assert.equal(repaired.text, 'SELECT id, email FROM users WHERE email = $1');
  assert.deepEqual(repaired.values, [ATTACK]);
  assert.deepEqual(legitimate.values, [LEGITIMATE]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
