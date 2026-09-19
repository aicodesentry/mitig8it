// Two invocation modes.
//   node tests/verify.js --exploit | --behavior            Sandbox mode: checks this tree.
//   node tests/verify.js <orig> <repaired> <orig> <repaired>  Harness mode: compares trees.
//
// One SQL injection chain runs through two files: customers.js decides what reaches the
// filter and orders.js decides how it is placed into SQL text. Either repair alone closes
// the chain, so each candidate tree and their union must all pass the exploit check.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = "x' OR '1'='1";
const LEGITIMATE = 'person@example.com';

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'orders.js'));
}

function exploit() {
  let result;
  try {
    result = loadLocal().buildOrderLookup(ATTACK);
  } catch (error) {
    // The attack input was rejected before it could reach any SQL text.
    process.exit(0);
  }
  if (typeof result.text === 'string' && result.text.includes(ATTACK)) {
    process.stderr.write('vulnerability present: untrusted input is interpolated into SQL text\n');
    process.exit(1);
  }
  assert.ok(Array.isArray(result.values) && result.values.includes(ATTACK));
  process.exit(0);
}

function behavior() {
  const result = loadLocal().buildOrderLookup(LEGITIMATE);
  assert.match(result.text, /FROM orders/i);
  assert.ok(result.text.includes(LEGITIMATE) || (Array.isArray(result.values) && result.values.includes(LEGITIMATE)));
  process.exit(0);
}

function compare(originalOrders, repairedOrders) {
  const original = require(originalOrders).buildOrderLookup(ATTACK);
  assert.match(original.text, /OR '1'='1/);
  const repaired = require(repairedOrders);
  assert.throws(() => repaired.buildOrderLookup(ATTACK), TypeError);
  const legitimate = repaired.buildOrderLookup(LEGITIMATE);
  assert.equal(legitimate.text, 'SELECT id, total FROM orders WHERE email = $1');
  assert.deepEqual(legitimate.values, [LEGITIMATE]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
