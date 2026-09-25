// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the server.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const LITERAL = 'keyboard cat';
const FROM_ENVIRONMENT = 'value-from-environment';

function localPath() {
  return path.resolve(__dirname, '..', 'server.js');
}

function load(file) {
  process.env.SECRET = FROM_ENVIRONMENT;
  const resolved = path.resolve(file);
  delete require.cache[resolved];
  return require(resolved);
}

function source(file) {
  return fs.readFileSync(path.resolve(file), 'utf8');
}

// The installed middleware signs with whatever secret the options object carried, so the
// signature is what the session secret actually is, not what the source appears to say.
function secretInUse(module_) {
  let captured = null;
  module_.install({ use: (middleware) => { captured = middleware({ id: 'session-1' }); } });
  return Buffer.from(String(captured).split('.')[1], 'base64').toString('utf8');
}

function exploit() {
  const module_ = load(localPath());
  if (secretInUse(module_) !== FROM_ENVIRONMENT || source(localPath()).includes(LITERAL)) {
    process.stderr.write('vulnerability present: the session secret is a literal in the options object, not read from the environment\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const module_ = load(localPath());
  module_.store.clear();
  module_.install({ use: (middleware) => middleware({ id: 'session-1' }) });
  assert.equal(module_.store.size, 1);
  assert.deepEqual([...module_.store.values()], [{ resave: true, saveUninitialized: true }]);
  assert.equal(module_.sign('a', 'b'), `a.${Buffer.from('b').toString('base64')}`);
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = load(originalPath);
  assert.equal(secretInUse(original), LITERAL);
  const repaired = load(repairedPath);
  assert.equal(secretInUse(repaired), FROM_ENVIRONMENT);
  assert.ok(!source(repairedPath).includes(LITERAL));
  repaired.store.clear();
  repaired.install({ use: (middleware) => middleware({ id: 'session-1' }) });
  assert.deepEqual([...repaired.store.values()], [{ resave: true, saveUninitialized: true }]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
