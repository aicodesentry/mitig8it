// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// fs.readFile is replaced with a recorder, so no file is opened: the exploit check passes only
// when a traversal name records no read at all.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const ATTACK = '../../etc/passwd';
const LEGITIMATE = 'handbook/intro.md';
const BASE = '/srv/docs';
const READS = [];

fs.readFile = (target, encoding, callback) => {
  READS.push(String(target));
  const done = typeof encoding === 'function' ? encoding : callback;
  if (typeof done === 'function') done(null, '# fixture document');
};

function load(target) {
  READS.length = 0;
  return require(target);
}

function loadLocal() {
  return load(path.resolve(__dirname, '..', 'app.js'));
}

// A refusal reaches the caller either way a repair can signal one: through the callback, or by
// throwing. The fixture cares that the name was refused and nothing was read, not which. Without
// the catch a throwing repair would crash this script and be scored as the vulnerability.
function fetch(module, name) {
  READS.length = 0;
  let error = null;
  let body = null;
  try {
    module.readDocument({ name }, (failure, content) => { error = failure; body = content; });
  } catch (thrown) {
    error = thrown;
  }
  return { error, body };
}

function exploit() {
  fetch(loadLocal(), ATTACK);
  const escaped = READS.filter((item) => !path.resolve(item).startsWith(`${BASE}${path.sep}`));
  if (escaped.length > 0) {
    process.stderr.write('vulnerability present: the resolved path escapes the served directory\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const result = fetch(loadLocal(), LEGITIMATE);
  assert.equal(result.error, null);
  assert.equal(result.body, '# fixture document');
  assert.deepEqual(READS, [path.join(BASE, LEGITIMATE)]);
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  fetch(load(originalPath), ATTACK);
  assert.deepEqual(READS, ['/etc/passwd']);
  const repaired = load(repairedPath);
  const blocked = fetch(repaired, ATTACK);
  assert.deepEqual(READS, []);
  assert.ok(blocked.error instanceof Error);
  const allowed = fetch(repaired, LEGITIMATE);
  assert.equal(allowed.error, null);
  assert.deepEqual(READS, [path.join(BASE, LEGITIMATE)]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
