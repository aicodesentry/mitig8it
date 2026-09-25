// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// Two vulnerable statements live in this one file, so a repair that fixes only the template
// literal or only the concatenation leaves the exploit check failing.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = "42' OR '1'='1";
const LEGITIMATE = '4821';

function recorder() {
  const calls = [];
  return { calls, db: { raw: (sql, bindings) => { calls.push({ sql: String(sql), bindings: bindings || [] }); return []; } } };
}

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function collect(module, account) {
  const { calls, db } = recorder();
  module.accountEntries(db, account);
  module.accountBalance(db, account);
  return calls;
}

function exploit() {
  const calls = collect(loadLocal(), ATTACK);
  const interpolated = calls.filter((call) => call.sql.includes(ATTACK));
  if (interpolated.length > 0) {
    process.stderr.write(`vulnerability present: ${interpolated.length} statement(s) interpolate untrusted input\n`);
    process.exit(1);
  }
  assert.equal(calls.length, 2);
  for (const call of calls) assert.ok(call.bindings.includes(ATTACK));
  process.exit(0);
}

function behavior() {
  const calls = collect(loadLocal(), LEGITIMATE);
  assert.equal(calls.length, 2);
  assert.match(calls[0].sql, /FROM entries/i);
  assert.match(calls[1].sql, /SUM\(amount\)/i);
  for (const call of calls) {
    assert.ok(call.sql.includes(LEGITIMATE) || call.bindings.includes(LEGITIMATE));
  }
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = collect(require(originalPath), ATTACK);
  assert.equal(original.filter((call) => call.sql.includes(ATTACK)).length, 2);
  const repaired = collect(require(repairedPath), ATTACK);
  assert.deepEqual(repaired.map((call) => call.sql), [
    'SELECT id, amount FROM entries WHERE account_id = ?',
    'SELECT SUM(amount) AS balance FROM entries WHERE account_id = ?',
  ]);
  assert.deepEqual(repaired.map((call) => call.bindings), [[ATTACK], [ATTACK]]);
  const legitimate = collect(require(repairedPath), LEGITIMATE);
  assert.deepEqual(legitimate.map((call) => call.bindings), [[LEGITIMATE], [LEGITIMATE]]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
