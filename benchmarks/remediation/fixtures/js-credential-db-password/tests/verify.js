// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// process.env.PASSWORD is set before the module is loaded, so a repaired config object takes the
// password from the environment at load and the vulnerable one ignores it. The literal has to be
// gone from the file too, and the DSN the module builds has to keep its shape either way.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const LITERAL = 'Pa55w0rd-warehouse-2026';
const FROM_ENVIRONMENT = 'value-from-environment';

function load(target) {
  process.env.PASSWORD = FROM_ENVIRONMENT;
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
  if (module.config.password !== FROM_ENVIRONMENT || source(localPath()).includes(LITERAL)) {
    process.stderr.write('vulnerability present: the database password is a literal in the source, not read from the environment\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const module = load(localPath());
  assert.equal(
    module.dsn(),
    `postgresql://warehouse_app:${module.config.password}@warehouse.internal:5432/warehouse`,
  );
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = load(originalPath);
  assert.equal(original.config.password, LITERAL);
  const repaired = load(repairedPath);
  assert.equal(repaired.config.password, FROM_ENVIRONMENT);
  assert.ok(!source(repairedPath).includes(LITERAL));
  assert.equal(
    repaired.dsn(),
    `postgresql://warehouse_app:${FROM_ENVIRONMENT}@warehouse.internal:5432/warehouse`,
  );
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
