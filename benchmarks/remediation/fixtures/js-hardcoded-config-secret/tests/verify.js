// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the config.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const LITERAL = 'MFyZ2h0LWNsaWVudC1zZWNyZXQ';
const FROM_ENVIRONMENT = 'value-from-environment';

function localPath() {
  return path.resolve(__dirname, '..', 'config.js');
}

function load(file) {
  process.env.CLIENT_SECRET = FROM_ENVIRONMENT;
  const resolved = path.resolve(file);
  delete require.cache[resolved];
  return require(resolved);
}

function source(file) {
  return fs.readFileSync(path.resolve(file), 'utf8');
}

function exploit() {
  const module_ = load(localPath());
  if (module_.config.clientSecret !== FROM_ENVIRONMENT || source(localPath()).includes(LITERAL)) {
    process.stderr.write('vulnerability present: the client secret is a literal config value, not read from the environment\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const module_ = load(localPath());
  assert.equal(module_.config.baseUrl, 'https://payments.example.com');
  assert.equal(module_.config.timeoutMs, 5000);
  const expected = `Basic ${Buffer.from(`payments:${module_.config.clientSecret}`).toString('base64')}`;
  assert.equal(module_.authorization(), expected);
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = load(originalPath);
  assert.equal(original.config.clientSecret, LITERAL);
  const repaired = load(repairedPath);
  assert.equal(repaired.config.clientSecret, FROM_ENVIRONMENT);
  assert.ok(!source(repairedPath).includes(LITERAL));
  assert.equal(repaired.config.baseUrl, original.config.baseUrl);
  assert.equal(
    repaired.authorization(),
    `Basic ${Buffer.from(`payments:${FROM_ENVIRONMENT}`).toString('base64')}`,
  );
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
