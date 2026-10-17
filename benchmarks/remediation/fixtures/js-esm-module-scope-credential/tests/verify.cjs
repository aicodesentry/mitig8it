// Two invocation modes.
//   node tests/verify.cjs --exploit | --behavior   Sandbox mode: checks the billing.mjs in this tree.
//   node tests/verify.cjs <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The secret is bound at module scope of an ES module, so the whole exploit is the import: a
// module that still carries the literal never reads the environment, and the literal is still
// in the file. Each import gets a URL of its own so it is evaluated with the environment it sets.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const LITERAL = 'pay-live-4f9c2a71e0b84d3a';
const FROM_ENVIRONMENT = 'value-from-environment';

let loads = 0;
async function load(file) {
  process.env.PAYMENT_SECRET = FROM_ENVIRONMENT;
  loads += 1;
  return import(`${pathToFileURL(path.resolve(file)).href}?load=${loads}`);
}
const source = (file) => fs.readFileSync(path.resolve(file), 'utf8');
const localPath = () => path.resolve(__dirname, '..', 'billing.mjs');

async function exploit() {
  const module_ = await load(localPath());
  if (module_.paymentSecret !== FROM_ENVIRONMENT || source(localPath()).includes(LITERAL)) {
    process.stderr.write('vulnerability present: the payment secret is a literal in the source, not read from the environment\n');
    process.exit(1);
  }
  process.exit(0);
}

async function behavior() {
  const module_ = await load(localPath());
  assert.equal(module_.region, 'eu-west-1');
  assert.equal(module_.retries, 3);
  process.exit(0);
}

async function compare(originalPath, repairedPath) {
  assert.equal((await load(originalPath)).paymentSecret, LITERAL);
  const repaired = await load(repairedPath);
  assert.equal(repaired.paymentSecret, FROM_ENVIRONMENT);
  assert.ok(!source(repairedPath).includes(LITERAL));
  assert.equal(repaired.region, 'eu-west-1');
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
(mode === '--exploit' ? exploit() : mode === '--behavior' ? behavior() : compare(process.argv[2], process.argv[3]))
  .catch((error) => { process.stderr.write(`${error.stack || error}\n`); process.exit(2); });
