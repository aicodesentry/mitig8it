// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// process.env.API_KEY is set before the module is loaded, so a repaired module reads it at load
// and the vulnerable one ignores it. The literal has to be gone from the file too: a module that
// read the environment but kept the literal beside it would still ship the secret.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const LITERAL = 'sk-live-3f9ab2c1d4e5f6a7';
const FROM_ENVIRONMENT = 'value-from-environment';

function load(target) {
  process.env.API_KEY = FROM_ENVIRONMENT;
  delete require.cache[require.resolve(target)];
  return require(target);
}

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function source(target) {
  return fs.readFileSync(target, 'utf8');
}

function exploit() {
  const module = load(localPath());
  if (module.API_KEY !== FROM_ENVIRONMENT || source(localPath()).includes(LITERAL)) {
    process.stderr.write('vulnerability present: the API key is a literal in the source, not read from the environment\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const module = load(localPath());
  const headers = module.vendorHeaders('req-1');
  assert.equal(headers.Authorization, `Bearer ${module.API_KEY}`);
  assert.equal(headers['Content-Type'], 'application/json');
  assert.equal(headers['X-Request-Id'], 'req-1');
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = load(originalPath);
  assert.equal(original.API_KEY, LITERAL);
  const repaired = load(repairedPath);
  assert.equal(repaired.API_KEY, FROM_ENVIRONMENT);
  assert.ok(!source(repairedPath).includes(LITERAL));
  assert.deepEqual(repaired.vendorHeaders('req-1'), {
    Authorization: `Bearer ${FROM_ENVIRONMENT}`,
    'Content-Type': 'application/json',
    'X-Request-Id': 'req-1',
  });
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
