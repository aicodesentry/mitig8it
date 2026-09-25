// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = "x' OR '1'='1";
const LEGITIMATE = 'widget';

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  const result = loadLocal().buildProductSearch(ATTACK, 10);
  if (typeof result.text === 'string' && result.text.includes(ATTACK)) {
    process.stderr.write('vulnerability present: untrusted input is interpolated into SQL text\n');
    process.exit(1);
  }
  assert.ok(JSON.stringify(result.values || []).includes(ATTACK));
  process.exit(0);
}

function behavior() {
  const result = loadLocal().buildProductSearch(LEGITIMATE, 10);
  assert.match(result.text, /FROM products/i);
  assert.match(result.text, /ORDER BY sku/i);
  const rendered = result.text + JSON.stringify(result.values || []);
  assert.ok(rendered.includes(LEGITIMATE));
  assert.ok(rendered.includes('10'));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = require(originalPath).buildProductSearch(ATTACK, 10);
  const repaired = require(repairedPath).buildProductSearch(ATTACK, 10);
  const legitimate = require(repairedPath).buildProductSearch(LEGITIMATE, 10);
  assert.match(original.text, /OR '1'='1/);
  assert.equal(repaired.text, 'SELECT id, sku, price FROM products WHERE sku LIKE $1 ORDER BY sku LIMIT $2');
  assert.deepEqual(repaired.values, [`%${ATTACK}%`, 10]);
  assert.deepEqual(legitimate.values, ['%widget%', 10]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
