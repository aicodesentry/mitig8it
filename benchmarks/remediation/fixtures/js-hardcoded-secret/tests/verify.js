// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const LITERAL = 'sk-live-7f3a91bc44de2210';
const FROM_ENVIRONMENT = 'value-from-environment';

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function load(file) {
  process.env.API_KEY = FROM_ENVIRONMENT;
  const resolved = path.resolve(file);
  delete require.cache[resolved];
  return require(resolved);
}

function source(file) {
  return fs.readFileSync(path.resolve(file), 'utf8');
}

function exploit() {
  const module_ = load(localPath());
  if (module_.apiKey !== FROM_ENVIRONMENT || source(localPath()).includes(LITERAL)) {
    process.stderr.write('vulnerability present: the API key is a literal in the source, not read from the environment\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const module_ = load(localPath());
  assert.equal(module_.authHeaders().Authorization, `Bearer ${module_.apiKey}`);
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = load(originalPath);
  assert.equal(original.apiKey, LITERAL);
  const repaired = load(repairedPath);
  assert.equal(repaired.apiKey, FROM_ENVIRONMENT);
  assert.ok(!source(repairedPath).includes(LITERAL));
  assert.equal(repaired.authHeaders().Authorization, `Bearer ${FROM_ENVIRONMENT}`);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
