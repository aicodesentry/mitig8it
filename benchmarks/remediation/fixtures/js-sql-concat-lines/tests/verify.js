// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The statement is assembled across three source lines, so the repair has to rewrite a
// multi-line concatenation rather than a single template literal.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = "eu' OR '1'='1";
const SINCE = '2026-01-01';
const LEGITIMATE = 'eu-west';

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  const result = loadLocal().reportQuery(ATTACK, SINCE);
  if (typeof result.text === 'string' && result.text.includes(ATTACK)) {
    process.stderr.write('vulnerability present: untrusted input is interpolated into SQL text\n');
    process.exit(1);
  }
  assert.ok((result.values || []).includes(ATTACK));
  process.exit(0);
}

function behavior() {
  const result = loadLocal().reportQuery(LEGITIMATE, SINCE);
  assert.match(result.text, /FROM invoices/i);
  assert.match(result.text, /GROUP BY region/i);
  const rendered = result.text + JSON.stringify(result.values || []);
  assert.ok(rendered.includes(LEGITIMATE) && rendered.includes(SINCE));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = require(originalPath).reportQuery(ATTACK, SINCE);
  const repaired = require(repairedPath).reportQuery(ATTACK, SINCE);
  const legitimate = require(repairedPath).reportQuery(LEGITIMATE, SINCE);
  assert.match(original.text, /OR '1'='1/);
  assert.equal(
    repaired.text,
    'SELECT region, SUM(total) AS total FROM invoices WHERE region = $1 AND issued_at >= $2 GROUP BY region'
  );
  assert.deepEqual(repaired.values, [ATTACK, SINCE]);
  assert.deepEqual(legitimate.values, [LEGITIMATE, SINCE]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
