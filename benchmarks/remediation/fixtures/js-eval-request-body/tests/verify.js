// Abstention fixture: the eval really does run request text, but the Node harness stubs no
// eval and records no executed code, so no regression test can prove a code_injection_eval
// repair for a JavaScript source. The engine skips the finding rather than hand the agent an
// unprovable task, and no candidate should reach these checks.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function exploit() {
  if (/\beval\s*\(/.test(fs.readFileSync(localPath(), 'utf8'))) {
    process.stderr.write('vulnerability present: request text is handed to eval\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  assert.equal(require(localPath()).applyRule({ expression: '2 + 3' }, {}), 5);
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('this abstention fixture has no reference repair to compare\n'); process.exit(64); }
