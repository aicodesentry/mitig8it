// Abstention fixture: the pipeline's quoting and output semantics are undocumented, so the
// checks exist only to complete the verification profile; no candidate should reach them.
const assert = require('node:assert/strict');
const path = require('node:path');

const ATTACK = 'x; rm -rf /';

function loadLocal() {
  return require(path.resolve(__dirname, '..', 'app.js'));
}

function exploit() {
  const rendered = loadLocal().auditReport(ATTACK);
  if (typeof rendered === 'string' && rendered.includes(ATTACK)) {
    process.stderr.write('vulnerability present: untrusted input reaches a shell pipeline string\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const rendered = loadLocal().auditReport('errors');
  assert.ok(String(rendered).includes('errors'));
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('unsupported invocation\n'); process.exit(64); }
