// Abstention fixture: `new Function` compiles saved text just as eval does, but the Node
// harness stubs no dynamic compilation and records no executed code, so no regression test can
// prove a code_injection_eval repair for a JavaScript source. The engine skips the finding,
// and no candidate should reach these checks.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

function localPath() {
  return path.resolve(__dirname, '..', 'app.js');
}

function exploit() {
  if (/new Function\s*\(/.test(fs.readFileSync(localPath(), 'utf8'))) {
    process.stderr.write('vulnerability present: saved text is compiled into a function\n');
    process.exit(1);
  }
  process.exit(0);
}

function behavior() {
  const formula = require(localPath()).compileFormula('row.quantity * row.price');
  assert.equal(formula({ quantity: 3, price: 4 }), 12);
  process.exit(0);
}

const mode = process.argv[2];
if (mode === '--exploit') exploit();
else if (mode === '--behavior') behavior();
else { process.stderr.write('this abstention fixture has no reference repair to compare\n'); process.exit(64); }
