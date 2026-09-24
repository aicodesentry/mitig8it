// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The rule the request carries is a document the function reads back as a value, so parsing it
// as data keeps what the function returns and removes the interpreter. The payload sets a flag
// rather than doing damage, so the check observes execution without any side effect: eval runs
// it, JSON.parse rejects it. The document is an array, which eval and JSON.parse read the same
// way, so the behavior check can pass on both trees and still say something.
const assert = require('node:assert/strict');
const path = require('node:path');

const PAYLOAD = '(globalThis.__mitig8itOwned = true)';
const DOCUMENT = '[1, 2]';
const PARSED = [1, 2];

function load(target) {
  globalThis.__mitig8itOwned = false;
  delete require.cache[require.resolve(target)];
  return require(target);
}

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function attempt(module, expression) {
  try {
    return module.applyRule({ expression }, {});
  } catch (error) {
    return undefined;
  }
}

function exploit() {
  const module = load(localPath());
  attempt(module, PAYLOAD);
  if (globalThis.__mitig8itOwned) {
    process.stderr.write('vulnerability present: the rule from the request body was executed as code\n');
    process.exit(1);
  }
  assert.deepEqual(attempt(module, DOCUMENT), PARSED);
  process.exit(0);
}

function behavior() {
  const module = load(localPath());
  assert.deepEqual(module.applyRule({ expression: DOCUMENT }, {}), PARSED);
  assert.deepEqual(module.applyRule({ expression: '[]' }, {}), []);
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  attempt(load(originalPath), PAYLOAD);
  assert.equal(globalThis.__mitig8itOwned, true);
  const repaired = load(repairedPath);
  attempt(repaired, PAYLOAD);
  assert.equal(globalThis.__mitig8itOwned, false);
  assert.deepEqual(repaired.applyRule({ expression: DOCUMENT }, {}), PARSED);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
