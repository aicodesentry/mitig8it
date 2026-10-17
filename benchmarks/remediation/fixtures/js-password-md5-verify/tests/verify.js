// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the auth.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
// The password is vulnerable when hashing it twice gives the same value, or when that value is a
// fast digest of it. Behaviour is the module's own verifier accepting the right password and
// rejecting a wrong one against a hash the module produced.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');

const PASSWORD = 'correct horse battery staple';

function load(file) {
  const resolved = path.resolve(file);
  delete require.cache[resolved];
  return require(resolved);
}

function localPath() {
  return path.resolve(__dirname, '..', 'auth.js');
}

function fastDigest(value) {
  return ['md5', 'sha1', 'sha256', 'sha512'].some((algorithm) =>
    ['hex', 'base64'].some((encoding) => crypto.createHash(algorithm).update(PASSWORD).digest(encoding) === value));
}

function vulnerable(m) {
  const first = m.hashPassword(PASSWORD);
  return first === m.hashPassword(PASSWORD) || fastDigest(first);
}

function verifies(m, password, stored) {
  return Boolean(m.verifyPassword(password, stored));
}

function behaves(m) {
  const stored = m.hashPassword(PASSWORD);
  assert.equal(verifies(m, PASSWORD, stored), true);
  assert.equal(verifies(m, 'wrong horse battery staple', stored), false);
}

function exploit() {
  const m = load(localPath());
  if (vulnerable(m)) {
    process.stderr.write('vulnerability present: the password is stored as an unsalted fast digest\n');
    process.exit(1);
  }
  behaves(m);
  process.exit(0);
}

function behavior() {
  behaves(load(localPath()));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = load(originalPath);
  assert.equal(vulnerable(original), true);
  behaves(original);
  const repaired = load(repairedPath);
  assert.equal(vulnerable(repaired), false);
  behaves(repaired);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
