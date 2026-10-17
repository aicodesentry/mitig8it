// Two invocation modes.
//   node tests/verify.cjs --exploit | --behavior   Sandbox mode: checks the app.mjs in this tree.
//   node tests/verify.cjs <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The module reads its document on import, so each case sets DOC_NAME and imports it again under
// a URL of its own: the ES module registry would otherwise hand back the first evaluation. The
// read is recorded on the real node:fs object, which is the default export an ES module gets.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const BASE = '/srv/docs';
const ATTACKS = ['../../etc/passwd', '/etc/passwd'];
const LEGITIMATE = 'guide.txt';
const READS = [];
// Only a read outside this tree is the module's: on Node 22 the ES module loader reads module
// sources through the same function, and those have to stay real.
const TREE = path.resolve(__dirname, '..');
const realRead = fs.readFileSync;
fs.readFileSync = (file, ...rest) => {
  const resolved = path.resolve(file instanceof URL ? file.pathname : String(file));
  if (resolved.startsWith(TREE + path.sep)) return realRead(file, ...rest);
  READS.push(resolved);
  return 'document body';
};

let loads = 0;
async function load(file, name) {
  READS.length = 0;
  process.env.DOC_NAME = name;
  loads += 1;
  try {
    return { module: await import(`${pathToFileURL(path.resolve(file)).href}?load=${loads}`), error: null };
  } catch (error) {
    return { module: null, error };
  }
}
const inside = (file) => file.startsWith(BASE + path.sep);
const localPath = () => path.resolve(__dirname, '..', 'app.mjs');

async function exploit() {
  for (const name of ATTACKS) {
    const { error } = await load(localPath(), name);
    if (!error || READS.some((file) => !inside(file))) {
      process.stderr.write(`vulnerability present: ${name} was read outside ${BASE}\n`);
      process.exit(1);
    }
  }
  process.exit(0);
}

async function behavior() {
  const { module, error } = await load(localPath(), LEGITIMATE);
  assert.equal(error, null);
  assert.equal(module.body, 'document body');
  assert.deepEqual(READS, [path.join(BASE, LEGITIMATE)]);
  process.exit(0);
}

async function compare(originalPath, repairedPath) {
  const original = await load(originalPath, ATTACKS[0]);
  assert.equal(original.error, null);
  assert.ok(READS.some((file) => !inside(file)), 'the original reads outside the base');
  const repaired = await load(repairedPath, ATTACKS[0]);
  assert.ok(repaired.error, 'the repaired module refuses the traversal on import');
  assert.deepEqual(READS, []);
  assert.equal((await load(repairedPath, LEGITIMATE)).module.body, 'document body');
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
(mode === '--exploit' ? exploit() : mode === '--behavior' ? behavior() : compare(process.argv[2], process.argv[3]))
  .catch((error) => { process.stderr.write(`${error.stack || error}\n`); process.exit(2); });
