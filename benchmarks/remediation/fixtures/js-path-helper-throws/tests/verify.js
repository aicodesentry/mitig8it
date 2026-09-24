// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');
const realFs = require('node:fs');

const ATTACK = '../../etc/passwd';
const LEGITIMATE = 'invoice.txt';
const BASE = '/srv/attachments';

// Records which absolute path the module tried to read instead of reading anything. A repair may
// refuse an escaping name by throwing or by returning something that is not file content; what it
// may not do is read outside the base directory.
function readsOf(modulePath, name) {
  const reads = [];
  const fake = Object.create(realFs);
  fake.readFileSync = (file) => (reads.push(path.resolve(String(file))), 'contents');
  fake.readFile = (file, ...rest) => {
    reads.push(path.resolve(String(file)));
    const cb = rest.find((v) => typeof v === 'function');
    if (cb) cb(null, 'contents');
  };
  const original = Module._load;
  Module._load = function (request, parent, isMain) {
    if (request === 'fs' || request === 'node:fs') return fake;
    return original.call(this, request, parent, isMain);
  };
  let threw = false;
  let value;
  try {
    delete require.cache[require.resolve(modulePath)];
    value = require(modulePath).readAttachment(name);
  } catch (error) {
    threw = true;
  } finally {
    Module._load = original;
  }
  return { reads, threw, value };
}

const escaped = (outcome) => outcome.reads.some((read) => !read.startsWith(BASE + path.sep));
const local = () => path.resolve(__dirname, '..', 'app.js');

function exploit() {
  if (escaped(readsOf(local(), ATTACK))) {
    process.stderr.write('vulnerability present: a file outside the base directory was read\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const outcome = readsOf(local(), LEGITIMATE);
  assert.ok(!outcome.threw, 'a legitimate name must still be read');
  assert.deepEqual(outcome.reads, [BASE + '/invoice.txt']);
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  const original = readsOf(originalPath, ATTACK);
  const repaired = readsOf(repairedPath, ATTACK);
  const legitimate = readsOf(repairedPath, LEGITIMATE);
  assert.ok(escaped(original), 'the original reads outside the base directory');
  assert.ok(!escaped(repaired), 'the repair reads nothing outside the base directory');
  assert.ok(!legitimate.threw && legitimate.reads.length === 1, 'a legitimate name is still read');
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
