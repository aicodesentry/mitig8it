// Two invocation modes.
//   node tests/verify.cjs --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.cjs <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The module binds `exec` by a named ES import, which is a live binding to node:child_process.
// The recorders are put on the built-in and `syncBuiltinESMExports` carries them to the ES view
// of it before the module is imported, so no command runs.
const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const Module = require('node:module');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const ATTACK = 'x; rm -rf /';
const LEGITIMATE = 'daily';
const CALLS = [];
childProcess.exec = (command, callback) => { CALLS.push({ fn: 'exec', command: String(command), args: null }); if (callback) callback(null, '', ''); };
childProcess.execFile = (file, args, callback) => { CALLS.push({ fn: 'execFile', command: String(file), args: args.map(String) }); if (callback) callback(null, '', ''); };
Module.syncBuiltinESMExports();

let loads = 0;
async function archive(file, name) {
  CALLS.length = 0;
  loads += 1;
  const module_ = await import(`${pathToFileURL(path.resolve(file)).href}?load=${loads}`);
  module_.archive(name, () => {});
  return CALLS[0];
}
const localPath = () => path.resolve(__dirname, '..', 'app.js');

async function exploit() {
  const call = await archive(localPath(), ATTACK);
  if (!call || call.args === null || !call.args.includes(`/backups/${ATTACK}.tgz`)) {
    process.stderr.write('vulnerability present: the archive name reaches a shell command string\n');
    process.exit(1);
  }
  process.exit(0);
}

async function behavior() {
  const call = await archive(localPath(), LEGITIMATE);
  const rendered = JSON.stringify(call);
  assert.ok(rendered.includes('tar') && rendered.includes(LEGITIMATE));
  process.exit(0);
}

async function compare(originalPath, repairedPath) {
  const original = await archive(originalPath, ATTACK);
  assert.equal(original.args, null, 'the original runs a shell command string');
  assert.deepEqual(await archive(repairedPath, ATTACK), { fn: 'execFile', command: 'tar', args: ['-czf', `/backups/${ATTACK}.tgz`, '/srv/data'] });
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
(mode === '--exploit' ? exploit() : mode === '--behavior' ? behavior() : compare(process.argv[2], process.argv[3]))
  .catch((error) => { process.stderr.write(`${error.stack || error}\n`); process.exit(2); });
