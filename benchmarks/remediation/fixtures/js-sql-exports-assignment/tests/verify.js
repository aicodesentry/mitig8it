// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = "x' OR '1'='1";
const LEGITIMATE = 'person@example.com';

// A connection that records what it was asked to run, so the test can tell an interpolated
// query from a parameterized one without a database.
function recorder() {
  const calls = [];
  return { calls, query: (text, values) => (calls.push({ text: String(text), values }), { rows: [] }) };
}

function run(module, email) {
  const db = recorder();
  module.findCustomer(db, email);
  return db.calls[0];
}

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  const call = run(loadLocal(), ATTACK);
  if (call.text.includes(ATTACK)) {
    process.stderr.write('vulnerability present: untrusted input is interpolated into SQL text\n');
    process.exit(1);
  }
  assert.ok(Array.isArray(call.values) && call.values.includes(ATTACK));
  process.exit(0);
}

function behavior() {
  const call = run(loadLocal(), LEGITIMATE);
  assert.match(call.text, /FROM customers/i);
  assert.ok(call.text.includes(LEGITIMATE) || (Array.isArray(call.values) && call.values.includes(LEGITIMATE)));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = run(require(originalPath), ATTACK);
  const repaired = run(require(repairedPath), ATTACK);
  const legitimate = run(require(repairedPath), LEGITIMATE);
  assert.ok(original.text.includes(ATTACK), 'the original interpolates the payload');
  assert.ok(!repaired.text.includes(ATTACK), 'the repair keeps the payload out of the SQL text');
  assert.deepEqual(repaired.values, [ATTACK]);
  assert.deepEqual(legitimate.values, [LEGITIMATE]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
