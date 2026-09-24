// Abstention fixture: the sink runs at import with an input no test can set, so the checks
// exist only to complete the verification profile; no candidate should reach them.
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const CALLS = [];
const fake = {
  execSync: (command) => (CALLS.push(String(command)), Buffer.from('')),
  execFileSync: (file, args) => (CALLS.push([String(file), ...(args || []).map(String)].join(' ')), Buffer.from('')),
};
const original = Module._load;
Module._load = (request, parent, isMain) =>
  (String(request).replace(/^node:/, '') === 'child_process' ? fake : original(request, parent, isMain));

function loadLocal() {
  CALLS.length = 0;
  const resolved = path.resolve(__dirname, '..', 'app.js');
  delete require.cache[resolved];
  return require(resolved);
}

function exploit() {
  loadLocal();
  if (CALLS.length !== 1) {
    process.stderr.write('vulnerability present: the archive command did not run exactly once at import\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const module_ = loadLocal();
  assert.equal(typeof module_.account, 'string');
  assert.ok(CALLS[0].includes('tar'));
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('unsupported invocation\n'); process.exit(64); }
