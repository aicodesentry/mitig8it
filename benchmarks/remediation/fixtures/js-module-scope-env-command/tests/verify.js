// Two invocation modes.
//   node tests/verify.js --exploit | --behavior   Sandbox mode: checks the app.js in this tree.
//   node tests/verify.js <original> <repaired>    Harness mode: compares the checked-in trees.
//
// The module under test runs its command when it is required, so there is nothing to call: the
// test sets the environment first and then imports it. child_process is replaced with a
// recorder, so no command runs and the test can tell an argument array from a shell string.
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const ATTACK = 'main; rm -rf /';
const LEGITIMATE = 'main';
const CALLS = [];

const record = (fn, command, args) => {
  CALLS.push({ fn, command: String(command), args: args === undefined ? null : args.map(String) });
  return Buffer.from('');
};
const fake = {
  execSync: (command) => record('execSync', command, undefined),
  execFileSync: (file, args) => record('execFileSync', file, args || []),
};
const original = Module._load;
Module._load = (request, parent, isMain) =>
  (String(request).replace(/^node:/, '') === 'child_process' ? fake : original(request, parent, isMain));

function load(file, branch) {
  CALLS.length = 0;
  process.env.BUILD_BRANCH = branch;
  const resolved = path.resolve(file);
  delete require.cache[resolved];
  return require(resolved);
}

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function exploit() {
  load(localPath(), ATTACK);
  const call = CALLS[0];
  if (!call || call.args === null || !call.args.includes(ATTACK)) {
    process.stderr.write('vulnerability present: the branch reaches a shell command string\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const module_ = load(localPath(), LEGITIMATE);
  assert.equal(typeof module_.log, 'string');
  const rendered = JSON.stringify(CALLS[0]);
  assert.ok(rendered.includes('git') && rendered.includes(LEGITIMATE));
  process.exit(0);
}

function compare(originalPath, repairedPath) {
  load(originalPath, ATTACK);
  assert.equal(CALLS[0].args, null, 'the original runs a shell command string');
  assert.ok(CALLS[0].command.includes('rm -rf /'));
  load(repairedPath, ATTACK);
  assert.deepEqual(CALLS[0], { fn: 'execFileSync', command: 'git', args: ['log', '--oneline', ATTACK] });
  load(repairedPath, LEGITIMATE);
  assert.deepEqual(CALLS[0].args, ['log', '--oneline', LEGITIMATE]);
  process.stdout.write(JSON.stringify({ vulnerability_observed: true, behavior_preserved: true }));
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else compare(process.argv[2], process.argv[3]);
